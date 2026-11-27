import random
import re
from dataclasses import dataclass, field

from flashfuzz import matter_schema
from flashfuzz.fsm import ClusterFSM, Parameter, Transition

# value ranges of the base datatypes; for nullable unsigned types the top value is the NULL sentinel, so the max is one below
TYPE_RANGES: dict[str, tuple[int, int]] = {
    "bool": (0, 1),
    "map8": (0, 0xFF), "map16": (0, 0xFFFF), "map32": (0, 0xFFFFFFFF), "map64": (0, 0xFFFFFFFFFFFFFFFF),
    "enum8": (0, 0xFF), "enum16": (0, 0xFFFF),
    "uint8": (0, 0xFE), "uint16": (0, 0xFFFE), "uint24": (0, 0xFFFFFE),
    "uint32": (0, 0xFFFFFFFE), "uint64": (0, 0xFFFFFFFFFFFFFFFE),
    "int8": (-128, 127), "int16": (-32768, 32767),
    "int32": (-(2 ** 31), 2 ** 31 - 1), "int64": (-(2 ** 63), 2 ** 63 - 1),
}
STRING_TYPES = {"string", "str", "char_string", "utf8", "octstr", "octet_string", "bytes"}
ARRAY_HINTS = ("list", "array", "set", "bag")

OVERFLOW_LENGTH = 1000       # Policy 1d: far above any string limit of the spec, still fits into one message
ANY = "ANY"                  # expected_status: the specification leaves the answer open, only a crash counts
MAX_INVALID_PER_PARAM = 5    # cap on LLM-listed invalid values per argument (enums can list hundreds)


def classify_type(type_token: str) -> str:
    """Coarse family of a Matter datatype: 'int', 'bool', 'string', 'array' or 'unknown'."""
    t = (type_token or "").strip().lower()
    if t == "bool":
        return "bool"
    if t in STRING_TYPES:
        return "string"
    for hint in ARRAY_HINTS:
        if hint in t:
            return "array"
    if t in TYPE_RANGES or t.startswith(("uint", "int", "enum", "map")):
        return "int"
    return "unknown"


@dataclass
class FuzzCase:
    """One test message: a command, or a write of the single payload value to attribute_id."""

    policy: str
    description: str
    kind: str
    endpoint_id: int
    cluster_id: int
    command_id: int | None = None
    command_name: str | None = None
    attribute_id: int | None = None
    payload: dict = field(default_factory=dict)
    value_types: dict = field(default_factory=dict)  # payload key -> TLV wire type (Policy 2)
    expected_status: str | None = None  # None: must succeed, ANY: either answer, else the error the device must send
    edge: Transition | None = None  # the FSM edge it was made for (None for Policy 4)

    @property
    def is_valid_input(self) -> bool:
        return self.expected_status is None

    @property
    def must_reject(self) -> bool:
        return self.expected_status not in (None, ANY)

    def label(self) -> str:
        target = self.command_name or f"attr {self.attribute_id}"
        return f"[P{self.policy}] {target}: {self.description}"


def parse_constraint(constraint: str) -> tuple[tuple[int, int] | None, list[int] | None]:
    """``'1..254'`` / ``'[1,254]'`` -> range; ``'0,1,2'`` -> value set; else ``(None, None)``."""
    c = (constraint or "").strip()
    if c.startswith("[") and c.endswith("]"):
        c = c[1:-1]
    if not c:
        return None, None
    try:
        if ".." in c:
            parts = c.split("..", 1)
            return (int(parts[0].strip()), int(parts[1].strip())), None
        if "," in c:
            values = []
            for x in c.split(","):
                if x.strip():
                    values.append(int(x.strip()))
            return None, values
        return None, [int(c)]
    except ValueError:
        return None, None


def valid_range(param: Parameter) -> tuple[int, int] | None:
    """``(lo, hi)`` from the LLM-extracted constraint, else from the base datatype."""
    rng, values = parse_constraint(param.constraint)
    if rng is not None:
        return rng
    if values:
        return min(values), max(values)
    return TYPE_RANGES.get((param.type or "").strip().lower())


def valid_value(param: Parameter) -> object:
    """One valid value 'as specified by the edge' (Policy 1a baseline)."""
    # TransitionTime=0 makes the effect observable right away
    if param.name.lower() == "transitiontime":
        return 0
    family = classify_type(param.type)
    if family == "string":
        return "fuzz"
    if family == "array":
        return [0]
    if family == "bool":
        return False
    _, values = parse_constraint(param.constraint)
    if values:
        return values[len(values) // 2]
    bounds = valid_range(param)
    if bounds is None:
        return 0
    lo, hi = bounds
    if hi <= lo:
        return lo
    return (lo + hi) // 2


def base_payload(params: list[Parameter]) -> dict:
    payload = {}
    for p in params:
        payload[p.name] = valid_value(p)
    return payload


def parse_value(text: str) -> object:
    """Best-effort Python value from an LLM-written literal (``'0'``, ``'null'``, ...)."""
    t = text.strip()
    if t.lower() in ("null", "none"):
        return None
    if t.lower() in ("true", "false"):
        return t.lower() == "true"
    for conv in (int, float):
        try:
            return conv(t)
        except ValueError:
            pass
    return t


def _case_for(edge: Transition, endpoint: int, cluster_id: int, policy: str, description: str,
              payload: dict, expected: str | None = None, value_types: dict | None = None) -> FuzzCase:
    if edge.trigger_type == "command":
        kind = "command"
    else:
        kind = "attribute_write"
    return FuzzCase(
        policy=policy, description=description,
        kind=kind,
        endpoint_id=endpoint, cluster_id=cluster_id,
        command_id=edge.command_id, command_name=edge.command_name, attribute_id=edge.attribute_id,
        payload=payload, value_types=value_types or {}, expected_status=expected, edge=edge,
    )


def policy1(edge: Transition, endpoint: int, cluster_id: int, rng: random.Random):
    base = base_payload(edge.parameters)

    def make(policy, description, payload, expected=None):
        return _case_for(edge, endpoint, cluster_id, policy, description, payload, expected)

    def with_value(name, value):
        payload = base.copy()
        payload[name] = value
        return payload

    cases = []
    # (a) the values specified by the edge -> must succeed and reach the destination state
    cases.append(make("1a", "valid baseline (values specified by edge)", base.copy()))

    for p in edge.parameters:
        family = classify_type(p.type)
        if family in ("int", "bool"):
            bounds = valid_range(p)
        else:
            bounds = None
        if bounds is not None:
            lo, hi = bounds
            # (b) extreme values of the valid range (valid) ...
            cases.append(make("1b", f"{p.name} = min ({lo})", with_value(p.name, lo)))
            cases.append(make("1b", f"{p.name} = max ({hi})", with_value(p.name, hi)))
            # ... and their out-of-range neighbours (invalid). A bitmap's undefined bits are reserved, not invalid
            if "map" in p.type.lower():
                outside = ANY
            else:
                outside = "CONSTRAINT_ERROR"
            cases.append(make("1b", f"{p.name} = below min ({lo - 1})", with_value(p.name, lo - 1), outside))
            cases.append(make("1b", f"{p.name} = above max ({hi + 1})", with_value(p.name, hi + 1), outside))
            # (c) a random valid value excluding the extremes; a value set can have gaps ('0,1,3')
            _, values = parse_constraint(p.constraint)
            if values:
                inner = []
                for x in values:
                    if lo < x < hi:
                        inner.append(x)
            else:
                inner = range(lo + 1, hi)
            if len(inner) > 1:
                r = rng.choice(inner)
                cases.append(make("1c", f"{p.name} = random valid ({r})", with_value(p.name, r)))

        # invalid values the LLM extracted from the spec (Figure 8, step 3)
        invalid = p.invalid_values
        if len(invalid) > MAX_INVALID_PER_PARAM:
            invalid = rng.sample(invalid, MAX_INVALID_PER_PARAM)
        for bad in invalid:
            cases.append(make("1c", f"{p.name} = invalid ({bad})", with_value(p.name, parse_value(bad)),
                              edge.expected_error or "CONSTRAINT_ERROR"))

        if family == "string":
            # (d) overlong string -> buffer overflow; (e) empty string -> uninitialized read
            cases.append(make("1d", f"{p.name} = overlong string (len {OVERFLOW_LENGTH})",
                              with_value(p.name, "A" * OVERFLOW_LENGTH), ANY))
            cases.append(make("1e", f"{p.name} = empty string", with_value(p.name, "")))
        if family == "array":
            # (f) NULL / single element / empty -> null dereference or out-of-bounds
            cases.append(make("1f", f"{p.name} = NULL", with_value(p.name, None)))
            cases.append(make("1f", f"{p.name} = single element", with_value(p.name, [0])))
            cases.append(make("1f", f"{p.name} = empty array", with_value(p.name, [])))
    return cases


# alternative encodings: family -> (value, TLV wire type token of the patched write path)
WRONG_TYPE_VALUES = {
    "string": ("1", "str"),
    "int": (65535, "uint"),
    "bool": (True, "bool"),
}


def policy2(edge: Transition, endpoint: int, cluster_id: int, rng: random.Random):
    base = base_payload(edge.parameters)
    cases = []
    for p in edge.parameters:
        family = classify_type(p.type)
        # "we change its type to a randomly selected one t'"
        other = rng.choice(sorted(set(WRONG_TYPE_VALUES) - {family}))
        value, wire_type = WRONG_TYPE_VALUES[other]
        payload = base.copy()
        payload[p.name] = value
        cases.append(_case_for(
            edge, endpoint, cluster_id, "2",
            f"{p.name}: type {p.type} -> {wire_type} value {value!r}",
            payload, "INVALID_COMMAND",
            value_types={p.name: wire_type},
        ))
    return cases


def attribute_write_cases(fsm: ClusterFSM, endpoint: int, attribute_list: list[int],
                          rng: random.Random):
    """Invalid writes to every attribute; they must be rejected whether writable or not."""
    widths = {}
    for v in fsm.state_variables:
        widths[v.attribute_id] = v.type
    names = matter_schema.attribute_names(fsm.cluster_id)
    cases = []
    for attribute_id in sorted(set(attribute_list) & set(names)):
        name = names[attribute_id]

        def make(policy, description, value, wire_type, expected):
            return FuzzCase(
                policy=policy, description=f"write {name}: {description}", kind="attribute_write",
                endpoint_id=endpoint, cluster_id=fsm.cluster_id, attribute_id=attribute_id,
                payload={name: value}, value_types={name: wire_type}, expected_status=expected,
            )

        family = classify_type(matter_schema.attribute_type(fsm.cluster_id, attribute_id))
        value, wire_type = WRONG_TYPE_VALUES[rng.choice(sorted(set(WRONG_TYPE_VALUES) - {family}))]
        cases.append(make("2", f"type -> {wire_type} value {value!r}", value, wire_type, "INVALID_DATA_TYPE"))
        width = re.fullmatch(r"(uint|int|map|enum)(8|16|24|32)", widths.get(attribute_id, "").strip().lower())
        if width and family == "int":
            signed = width.group(1) == "int"
            bits = int(width.group(2))
            if signed:
                lo, hi = -(2 ** (bits - 1)), 2 ** (bits - 1) - 1
            else:
                lo, hi = 0, 2 ** bits - 1
            cases.append(make("1b", f"below type range ({lo - 1})", lo - 1, "int", "CONSTRAINT_ERROR"))
            if signed:
                above_type = "int"
            else:
                above_type = "uint"
            cases.append(make("1b", f"above type range ({hi + 1})", hi + 1, above_type, "CONSTRAINT_ERROR"))
    return cases


def policy3(edge: Transition, endpoint: int, cluster_id: int):
    cases = []
    if edge.trigger_type != "command":
        return cases
    base = base_payload(edge.parameters)

    def make(description, payload, expected="INVALID_COMMAND"):
        return _case_for(edge, endpoint, cluster_id, "3", description, payload, expected)

    # a receiver ignores fields it does not know, so the extra argument may be accepted
    extra = base.copy()
    extra["fuzz_extra_arg"] = 1
    cases.append(make("n+1 arguments (extra undefined arg)", extra, ANY))
    if edge.parameters:
        dropped = edge.parameters[-1].name
        reduced = {}
        for k, v in base.items():
            if k != dropped:
                reduced[k] = v
        cases.append(make(f"n-1 arguments (dropped {dropped})", reduced))
        cases.append(make("0 arguments", {}))
    return cases


def policy4(endpoint: int, node_clusters: set[int], rng: random.Random,
            max_clusters: int = 2):
    """One message for every command of a few standard clusters the node does not have."""
    candidates = matter_schema.policy4_candidates(exclude=set(node_clusters))
    rng.shuffle(candidates)
    cases = []
    for cluster_id in candidates[:max_clusters]:
        name = matter_schema.cluster_name(cluster_id)
        for command_id, command_name, params in matter_schema.cluster_commands(cluster_id):
            cases.append(FuzzCase(
                policy="4", description=f"unsupported cluster {name} ({cluster_id}) command {command_name}",
                kind="command", endpoint_id=endpoint, cluster_id=cluster_id,
                command_id=command_id, command_name=command_name, payload=base_payload(params),
                expected_status="UNSUPPORTED_CLUSTER",
            ))
    return cases


def accepts(edge: Transition, payload: dict) -> bool:
    """True when every integer argument of the payload lies inside the edge's constraints."""
    for p in edge.parameters:
        value = payload.get(p.name)
        if value is None or classify_type(p.type) not in ("int", "bool"):
            continue
        if not isinstance(value, int):
            return False
        _, values = parse_constraint(p.constraint)
        if values:
            if value not in values:
                return False
        else:
            bounds = valid_range(p)
            if bounds and not bounds[0] <= value <= bounds[1]:
                return False
    return True


def cases_for_fsm(fsm: ClusterFSM, endpoint: int, seed: int = 0) -> list[FuzzCase]:
    """Policy 1-3 cases for every edge; a message that two edges from the same state share is sent once."""
    rng = random.Random(seed)
    cases: list[FuzzCase] = []
    seen: set[tuple] = set()
    for edge in fsm.transitions:
        # the LLM sometimes leaves an enum's valid values empty; the SDK defines them
        sdk = {}
        for p in matter_schema.command_parameters(fsm.cluster_id, edge.command_name):
            sdk[p.name.lower()] = p.constraint
        nullable = set()
        for f in matter_schema.command_fields(fsm.cluster_id, edge.command_name):
            if f.nullable:
                nullable.add(f.label.lower())
        for p in edge.parameters:
            p.constraint = p.constraint or sdk.get(p.name.lower(), "")
            bounds, type_range = valid_range(p), TYPE_RANGES.get(p.type.strip().lower())
            # the highest number of a nullable unsigned type encodes null; TYPE_RANGES ends one below it
            if p.name.lower() in nullable and "," not in p.constraint and bounds and type_range and bounds[1] > type_range[1]:
                p.constraint = f"{bounds[0]}..{type_range[1]}"
    for edge in fsm.transitions:
        siblings = []
        for e in fsm.transitions:
            if (e.trigger_type, e.command_id, e.attribute_id) == (edge.trigger_type, edge.command_id, edge.attribute_id):
                siblings.append(e)
        edge_cases = (policy1(edge, endpoint, fsm.cluster_id, rng)
                      + policy2(edge, endpoint, fsm.cluster_id, rng)
                      + policy3(edge, endpoint, fsm.cluster_id))
        for case in edge_cases:
            key = (edge.from_state, case.kind, case.command_id, case.attribute_id,
                   repr(sorted(case.payload.items())), repr(sorted(case.value_types.items())))
            if key in seen:
                continue
            # another edge of this command takes the message: the constraint was a guard, not a validity rule
            if case.policy in ("1b", "1c") and case.must_reject:
                for e in siblings:
                    if accepts(e, case.payload):
                        case.expected_status = ANY
                        break
            seen.add(key)
            cases.append(case)
    return cases

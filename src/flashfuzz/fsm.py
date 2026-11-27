import operator

from pydantic import BaseModel, Field


class Condition(BaseModel):
    """One predicate over one state variable, e.g. ``CurrentLevel eq MaxLevel``."""

    variable: str = Field(description="Name of a state_variable this condition constrains.")
    op: str = Field(description="Comparison operator: one of eq, ne, lt, le, gt, ge, in, any.")
    value: str = Field(
        description=(
            "Right-hand side as a string. Either a concrete value ('254'), a range "
            "('[1,254]'), or a symbolic reference to another attribute or to a command "
            "argument ('TargetLevel', 'MinLevel'). Use op='any' with value='*' for a wildcard."
        )
    )


class StateVariable(BaseModel):
    """A cluster attribute whose value is part of the device state (e.g. ``OnOff``)."""

    name: str = Field(description="Human-readable attribute name, e.g. 'OnOff', 'CurrentLevel'.")
    attribute_id: int = Field(description="Matter attribute id within the cluster (e.g. 0 for OnOff).")
    type: str = Field(description="Matter data type, e.g. 'bool', 'uint8', 'uint16'.")


class State(BaseModel):
    """A node of the FSM: a conjunction of conditions over the state variables.

    In Figure 9 a state is drawn as e.g. ``CurrentLevel: 254 / OnOff: False``.
    """

    id: str = Field(description="Unique, stable, identifier-like state id.")
    description: str = Field(description="Short human-readable label, as in the mGPTFuzz diagram.")
    conditions: list[Condition] = Field(
        default_factory=list,
        description="Conditions that must all hold for the device to be in this state.",
    )
    unaccepted_values: list[str] = Field(
        default_factory=list,
        description="Inputs/commands this state must reject (Chain-of-Thought step 4 of Figure 8).",
    )


class Parameter(BaseModel):
    """A command argument (or the value of an attribute write)."""

    name: str = Field(description="Parameter name, e.g. 'TargetLevel', 'TransitionTime'.")
    type: str = Field(description="Matter data type, e.g. 'uint8', 'uint16', 'enum8'.")
    constraint: str = Field(default="", description="Valid range or set, e.g. '1..254' or '0,1'.")
    invalid_values: list[str] = Field(
        default_factory=list,
        description="Out-of-range/invalid values the device must reject (Chain-of-Thought step 3).",
    )


class Transition(BaseModel):
    """An edge of the FSM: a command (or attribute write) moving the device Σ -> Δ."""

    id: str = Field(description="Unique transition id.")
    from_state: str = Field(description="Source state id (Σ).")
    to_state: str = Field(description="Destination state id (Δ).")
    trigger_type: str = Field(description="Either 'command' or 'attribute_write'.")
    command_id: int | None = Field(default=None, description="Command id (when trigger_type='command').")
    command_name: str | None = Field(default=None, description="Command name, e.g. 'MoveToLevel'.")
    attribute_id: int | None = Field(
        default=None, description="Attribute id (when trigger_type='attribute_write')."
    )
    parameters: list[Parameter] = Field(
        default_factory=list, description="Typed parameters of the command / value of the write."
    )
    guard: str | None = Field(default=None, description="Optional extra condition for this edge.")
    expected_error: str | None = Field(
        default=None,
        description="Status the device must answer for an invalid invocation, e.g. "
                    "'CONSTRAINT_ERROR' or 'INVALID_COMMAND' (Chain-of-Thought step 3).",
    )

    def label(self) -> str:
        """``MoveToLevel(Level, TransitionTime)`` style label for logs and diagrams."""
        name = self.command_name or f"write:{self.attribute_id}"
        params = ", ".join(p.name for p in self.parameters)
        return f"{name}({params})" if params else name


class ClusterFSM(BaseModel):
    """The merged FSM of one Matter cluster for one concrete device (FeatureMap)."""

    cluster_id: int
    cluster_name: str
    feature_map: int = Field(description="FeatureMap (attribute 65532) the FSM was generated for.")
    state_variables: list[StateVariable]
    states: list[State]
    transitions: list[Transition]
    models: list[str] = Field(default_factory=list, description="LLM models whose answers built this FSM.")
    spec: str = Field(default="", description="Specification file the FSM was generated from.")

    def state(self, state_id: str) -> State | None:
        for s in self.states:
            if s.id == state_id:
                return s
        return None


_OPS = {"eq": operator.eq, "ne": operator.ne, "lt": operator.lt, "le": operator.le, "gt": operator.gt, "ge": operator.ge}


def validate_fsm(
        fsm: ClusterFSM, accepted_commands: list[int], attribute_list: list[int]
) -> tuple[ClusterFSM, list[str]]:
    """Drop edges with commands or attributes the device does not have, or with unknown states."""
    warnings: list[str] = []
    state_ids = set()
    for s in fsm.states:
        state_ids.add(s.id)
    kept: list[Transition] = []
    for t in fsm.transitions:
        if t.trigger_type == "command" and t.command_id not in accepted_commands:
            warnings.append(f"drop {t.id}: command {t.command_id} ({t.command_name}) "
                            "not in AcceptedCommandList")
            continue
        if t.trigger_type == "attribute_write" and t.attribute_id not in attribute_list:
            warnings.append(f"drop {t.id}: attribute {t.attribute_id} not in AttributeList")
            continue
        if t.trigger_type not in ("command", "attribute_write"):
            warnings.append(f"drop {t.id}: unknown trigger_type {t.trigger_type!r}")
            continue
        if t.from_state not in state_ids or t.to_state not in state_ids:
            warnings.append(f"drop {t.id}: dangling state {t.from_state!r} -> {t.to_state!r}")
            continue
        kept.append(t)
    return fsm.model_copy(update={"transitions": kept}), warnings


def parse_literal(text: str):
    """``'true'`` -> ``True``, ``'254'`` -> ``254``; anything else -> ``None``."""
    low = text.strip().lower()
    if low in ("true", "false"):
        return low == "true"
    try:
        return int(low)
    except ValueError:
        return None


def _resolve_value(value: str, values: dict[str, object], params: dict[str, object]):
    """A literal, else a name: first a command argument (Level), then another attribute (MinLevel); None if unknown."""
    literal = parse_literal(value)
    if literal is not None:
        return literal
    name = value.strip()
    if name in params and params[name] is not None:
        return params[name]
    return values.get(name)


def _check_in(actual, value: str) -> bool | None:
    """Evaluate ``in`` against a range ``'[1,254]'`` or a set ``'0,1,2'``."""
    v = value.strip()
    try:
        if v.startswith("[") and v.endswith("]"):
            parts = v[1:-1].split(",")
            lo, hi = int(parts[0]), int(parts[1])
            return lo <= actual <= hi
        values = set()
        for x in v.split(","):
            values.add(int(x))
        return actual in values
    except (ValueError, TypeError):
        return None


def condition_holds(cond: Condition, values: dict[str, object],
                    params: dict[str, object] | None = None) -> bool | None:
    """True or False, or None when it cannot be decided (variable not read, name not resolvable)."""
    if cond.op == "any":
        return True
    actual = values.get(cond.variable)
    if actual is None:
        return None
    if cond.op == "in":
        return _check_in(actual, cond.value)
    rhs = _resolve_value(cond.value, values, params or {})
    fn = _OPS.get(cond.op)
    if rhs is None or fn is None:
        return None
    try:
        return fn(actual, rhs)
    except TypeError:
        return None


def state_matches(state: State, values: dict[str, object],
                  params: dict[str, object] | None = None) -> bool | None:
    """False if a condition is violated, True if at least one holds and none is violated, else None."""
    decided = False
    for cond in state.conditions:
        holds = condition_holds(cond, values, params)
        if holds is False:
            return False
        if holds is True:
            decided = True
    if decided:
        return True
    return None


def referenced_variables(state: State) -> set[str]:
    """The attribute names a state refers to, i.e. what must be read to check it."""
    names: set[str] = set()
    for cond in state.conditions:
        names.add(cond.variable)
        v = cond.value.strip()
        if v and v != "*" and not v.startswith("[") and parse_literal(v) is None:
            names.add(v)
    return names


def to_dot(fsm: ClusterFSM) -> str:
    lines = [
        f'digraph "{fsm.cluster_name}" {{',
        "    rankdir=LR;",
        '    node [shape=ellipse, style=filled, fillcolor="#d9d9d9"];',
    ]
    for s in fsm.states:
        parts = []
        for c in s.conditions:
            parts.append(f"{c.variable} {c.op} {c.value}")
        label = "\\n".join(parts) or s.description
        lines.append(f'    "{s.id}" [label="{label}"];')
    for t in fsm.transitions:
        label = t.label()
        for p in t.parameters:
            label += f"\\n- {p.name} : {p.type}"
        lines.append(f'    "{t.from_state}" -> "{t.to_state}" [label="{label}"];')
    lines.append("}")
    return "\n".join(lines)

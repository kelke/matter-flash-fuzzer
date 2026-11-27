import logging
import pathlib
from dataclasses import dataclass, field

from flashfuzz import fsm as fsm_mod
from flashfuzz import functionality_extractor
from flashfuzz import matter_schema
from flashfuzz.controller import MatterController, Response
from flashfuzz.fsm import ClusterFSM, State
from flashfuzz.fuzzing_policies import FuzzCase
from flashfuzz.utils import log_and_print, save_json, timestamp

# countdowns that change on their own between two reads
VOLATILE_VARIABLES = {"OnTime", "OffWaitTime", "RemainingTime"}

# Command-effect oracle: a *setter* must drive its target attribute to the
# argument value, clamped into the device's bounds. The static FSM cannot express
# "destination depends on the argument" (Figure 9 writes it as 'TargetLevel'), so
# these commands are judged by their effect instead of a static destination state.
# (cluster_id, command_name) -> (target attribute id, argument name, (min attr, max attr))
COMMAND_EFFECTS = {
    (8, "MoveToLevel"): (0, "Level", (2, 3)),           # CurrentLevel, clamped to Min/MaxLevel
    (8, "MoveToLevelWithOnOff"): (0, "Level", (2, 3)),
}

def setter(name: str, value) -> tuple | None:
    """(cluster, command, payload) that drives a state variable to value, None if there is no such command."""
    if name == "OnOff":
        if value:
            return 6, "On", {}
        return 6, "Off", {}
    if name == "CurrentLevel":
        return 8, "MoveToLevel", {"Level": int(value), "TransitionTime": 0}
    if name == "CurrentHue":
        return 768, "MoveToHue", {"Hue": int(value), "Direction": 0, "TransitionTime": 0}
    if name == "CurrentSaturation":
        return 768, "MoveToSaturation", {"Saturation": int(value), "TransitionTime": 0}
    return None


# LevelControl and ColorControl ignore their commands while the lamp is off (Options.ExecuteIfOff = 0).
NEEDS_ON = (8, 768)


NODES_DIR = pathlib.Path("data/nodes")


def baseline_state(controller: MatterController, node: dict) -> dict[str, object]:
    """Read every attribute of the node's application clusters and save them to data/nodes/<node_id>/."""
    node_id = node["node_id"]
    paths = []
    for caps in functionality_extractor.extract(node):
        for a in caps.attribute_list:
            if a < functionality_extractor.ATTR_GENERATED_COMMAND_LIST:
                paths.append(f"{caps.endpoint}/{caps.cluster_id}/{a}")
    state = {}
    for path in paths:
        state[path] = controller.read_attribute(node_id, path)
    file = NODES_DIR / str(node_id) / (timestamp() + ".json")
    save_json(file, state)
    log_and_print(f"Baseline state of node {node_id} saved to {file}")
    return state


def restore_node(controller: MatterController, node_id: int, state: dict[str, object]) -> None:
    """Drive every attribute that differs from state back: with its setter command, otherwise by a write."""
    todo = {}
    for path, value in state.items():
        if value is not None and controller.read_attribute(node_id, path) != value:
            todo[path] = value

    def order(item):  # Level/Color commands are ignored while off: switch on first, off last
        path, value = item
        if not path.endswith("/6/0"):
            return 1
        if value is False:
            return 2
        return 0

    for path, value in sorted(todo.items(), key=order):
        parts = path.split("/")
        endpoint, cluster, attribute = int(parts[0]), int(parts[1]), int(parts[2])
        name = matter_schema.attribute_names(cluster).get(attribute)
        command = setter(name, value)
        if command is not None:
            cluster_id, command_name, payload = command
            controller.send_command(node_id, endpoint, cluster_id, command_name, payload)
        else:
            controller.write_attribute(node_id, path, value)
    left = []
    for path, value in todo.items():
        if controller.read_attribute(node_id, path) != value:
            left.append(path)
    if left:  # read-only attributes without a setter, or a device that refused
        log_and_print(f"Node {node_id}: could not restore {left}", logging.WARNING)


@dataclass
class Verdict:
    """The monitor's judgement of one test message."""

    case: str
    policy: str
    status: str
    expected: str | None
    alive: bool = True
    timed_out: bool = False
    setup_ok: bool = True
    accepted_bad: bool = False     # N1: invalid input accepted
    rejected_good: bool = False    # N2: valid input rejected
    state_bug: bool = False        # destination state / effect not as the FSM predicts
    state_note: str = ""
    state_before: dict = field(default_factory=dict)
    state_after: dict = field(default_factory=dict)
    cluster_id: int | None = None
    payload: dict = field(default_factory=dict)   # what was sent, to check a finding without the debug log

    @property
    def reasons(self) -> list[str]:
        out = []
        if not self.alive:
            out.append("CRASH")
        if self.timed_out:
            out.append("timeout")
        if self.accepted_bad:
            out.append(f"accepted invalid input ({self.expected} expected)")
        if self.rejected_good:
            out.append(f"rejected valid input (status={self.status})")
        if self.state_bug:
            out.append(self.state_note)
        return out

    @property
    def suspicious(self) -> bool:
        return bool(self.reasons)


def judge(fsm: ClusterFSM | None, case: FuzzCase, response: Response, alive: bool,
          before: dict, after: dict, effect_value=None, effect_bounds=None) -> Verdict:
    """Combine the answer, the liveness probe and the state reads before and after into a verdict."""
    v = Verdict(case=case.label(), policy=case.policy, status=response.status,
                expected=case.expected_status, alive=alive, timed_out=response.timed_out,
                state_before=before, state_after=after, cluster_id=case.cluster_id, payload=case.payload)

    # Response oracle. SENT (sanitizing command path) is the device's verdict only
    # for Policy 4, where the server has nothing to sanitize.
    accepted = response.status == "SUCCESS" or (case.policy == "4" and response.status == "SENT")
    v.accepted_bad = case.must_reject and accepted
    # Only a living device rejects: for a dead one the error is the server's ("node not available").
    v.rejected_good = case.is_valid_input and alive and not response.accepted and not response.timed_out

    # State oracle, only when the edge's precondition held before the message.
    source = fsm.state(case.edge.from_state) if fsm and case.edge else None
    target = fsm.state(case.edge.to_state) if fsm and case.edge else None
    if source is not None and fsm_mod.state_matches(source, before) is False:
        return v
    stable_before = {k: x for k, x in before.items() if k not in VOLATILE_VARIABLES}
    stable_after = {k: x for k, x in after.items() if k not in VOLATILE_VARIABLES}

    effect = COMMAND_EFFECTS.get((case.cluster_id, case.command_name))
    if effect and case.is_valid_input and response.accepted:
        _, arg_name, _ = effect
        want = case.payload.get(arg_name)
        if case.payload.get("TransitionTime", 0) in (0, None) and isinstance(want, int) and effect_value is not None:
            if effect_bounds and all(isinstance(b, int) for b in effect_bounds):
                want = min(max(want, effect_bounds[0]), effect_bounds[1])
            if int(effect_value) != want:
                v.state_bug = True
                v.state_note = f"setter {case.command_name}({arg_name}={case.payload.get(arg_name)}) " \
                               f"left target attribute at {effect_value}, expected {want}"
    elif case.is_valid_input and response.accepted and target is not None:
        if fsm_mod.state_matches(target, stable_after, case.payload) is False:
            v.state_bug = True
            v.state_note = f"valid input did not reach {target.id}: {stable_after}"
    elif not case.is_valid_input and case.kind == "attribute_write" and stable_before != stable_after:
        v.state_bug = True
        v.state_note = f"rejected input changed state: {stable_before} -> {stable_after}"
    return v


class DeviceStateMonitor:

    def __init__(self, controller: MatterController, node_id: int):
        self.controller = controller
        self.node_id = node_id

    def _read(self, endpoint: int, cluster_id: int, names: set[str]) -> dict:
        """Fresh {name: value} of the given attributes, one live read each."""
        ids = {}
        for attribute_id, name in matter_schema.attribute_names(cluster_id).items():
            ids[name] = attribute_id
        out = {}
        for n in names:
            if n in ids:
                out[n] = self.controller.read_attribute(self.node_id, f"{endpoint}/{cluster_id}/{ids[n]}")
        return out

    def prepare(self, state: State, endpoint: int, cluster_id: int) -> bool:
        """Drive the device into ``state`` (the required initial state) and verify it."""
        names = fsm_mod.referenced_variables(state)
        observed = self._read(endpoint, cluster_id, names)
        if fsm_mod.state_matches(state, observed) is True:
            return True
        for cond in state.conditions:
            if cond.op != "eq":
                continue
            target = fsm_mod.parse_literal(cond.value)
            if target is None:
                target = observed.get(cond.value.strip())  # symbolic, e.g. 'MinLevel'
            if target is None:
                continue
            command = setter(cond.variable, target)
            if command is None:
                continue
            try:
                cluster_id, command_name, payload = command
                self.controller.send_command(self.node_id, endpoint, cluster_id, command_name, payload)
            except Exception as e:
                logging.warning("setup %s=%s failed: %s", cond.variable, target, e)
        return fsm_mod.state_matches(state, self._read(endpoint, cluster_id, names)) is not False

    def run(self, fsm: ClusterFSM | None, case: FuzzCase) -> Verdict:
        """Prepare the initial state, send the message, observe, judge."""
        log_and_print(f"fuzz: {case.label()}")
        ep, cl = case.endpoint_id, case.cluster_id
        source = None
        target = None
        if fsm and case.edge:
            source = fsm.state(case.edge.from_state)
            target = fsm.state(case.edge.to_state)
        names: set[str] = set()
        for s in (source, target):
            if s is not None:
                names |= fsm_mod.referenced_variables(s)

        if case.kind == "attribute_write":  # a rejected write must leave the attribute as it was
            names |= set(case.payload)

        if cl in NEEDS_ON and self.controller.read_attribute(self.node_id, f"{ep}/6/0") is False:
            self.controller.send_command(self.node_id, ep, 6, "On")
        setup_ok = True
        if source is not None:
            setup_ok = self.prepare(source, ep, cl)

        before = self._read(ep, cl, names)
        response = self.controller.send(self.node_id, case)
        after = self._read(ep, cl, names)

        effect_value = effect_bounds = None
        effect = COMMAND_EFFECTS.get((cl, case.command_name))
        if effect:
            target_attr, _, (lo_attr, hi_attr) = effect
            effect_value = self.controller.read_attribute(self.node_id, f"{ep}/{cl}/{target_attr}")
            effect_bounds = (self.controller.read_attribute(self.node_id, f"{ep}/{cl}/{lo_attr}"),
                             self.controller.read_attribute(self.node_id, f"{ep}/{cl}/{hi_attr}"))

        # A device that dies during the reads above is reported with this message
        alive = self.controller.is_alive(self.node_id)
        verdict = judge(fsm, case, response, alive, before, after, effect_value, effect_bounds)
        verdict.setup_ok = setup_ok
        if case.kind == "attribute_write" and not case.is_valid_input:
            for name in case.payload:  # put back what an accepted invalid write changed
                if before.get(name) is not None and after.get(name) != before[name]:
                    self.controller.write_attribute(self.node_id, f"{ep}/{cl}/{case.attribute_id}", before[name])
        if verdict.suspicious:
            log_and_print(f"  !! SUSPICIOUS {case.label()}: " + "; ".join(verdict.reasons),
                          logging.WARNING)
        return verdict

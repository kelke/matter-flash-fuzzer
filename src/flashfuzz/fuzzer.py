"""The fuzzing loop: device -> FSMs -> test messages -> controller -> monitor."""
import dataclasses
import json
import logging
import pathlib
import random

from flashfuzz import fsm as fsm_mod
from flashfuzz import functionality_extractor
from flashfuzz import fuzzing_policies
from flashfuzz import knowledge_base
from flashfuzz.controller import MatterController
from flashfuzz.device_state_monitor import DeviceStateMonitor, Verdict, baseline_state, restore_node
from flashfuzz.utils import log_and_print, save_json, timestamp

RUNS_DIR = pathlib.Path("data/runs")


def cluster_fsms(node: dict, clusters: list[int] | None = None, refresh: bool = False) -> list:
    """(capabilities, FSM) for every application cluster, without edges the device cannot have."""
    out = []
    for caps in functionality_extractor.extract(node, clusters):
        fsm = knowledge_base.cluster_fsm(caps, refresh)
        fsm, warnings = fsm_mod.validate_fsm(fsm, caps.accepted_commands, caps.attribute_list)
        for w in warnings:
            logging.warning("[validate %s] %s", caps.name, w)
        edge_commands = set()
        for t in fsm.transitions:
            edge_commands.add(t.command_id)
        missing = sorted(set(caps.accepted_commands) - edge_commands)
        if missing:
            log_and_print(f"[{caps.name}] accepted commands without FSM edge (not fuzzed): {missing}",
                          logging.WARNING)
        out.append((caps, fsm))
    return out


def plan(node: dict, seed: int = 0, clusters: list[int] | None = None) -> list:
    """Every test message for a node as (capabilities, FSM, case), in sending order."""
    items = []
    for caps, fsm in cluster_fsms(node, clusters):
        # The device is still at rest, so an attribute only changes if the write caused it to
        for case in fuzzing_policies.attribute_write_cases(fsm, caps.endpoint, caps.attribute_list,
                                                           random.Random(seed)):
            items.append((caps, fsm, case))
        for case in fuzzing_policies.cases_for_fsm(fsm, caps.endpoint, seed):
            items.append((caps, fsm, case))

    # Policy 4: clusters the node has on no endpoint at all
    node_clusters = functionality_extractor.all_clusters(functionality_extractor.parse_node(node))
    rng = random.Random(seed)
    endpoints = set()
    for caps in functionality_extractor.extract(node, clusters):
        endpoints.add(caps.endpoint)
    for endpoint in sorted(endpoints):
        for case in fuzzing_policies.policy4(endpoint, node_clusters, rng):
            items.append((None, None, case))
    return items


def fuzz_node(controller: MatterController, node: dict, seed: int = 0, limit: int = 0,
              clusters: list[int] | None = None) -> None:
    node_id = node["node_id"]
    log_and_print(f"Starting fuzzing for node {node_id}")
    items = plan(node, seed, clusters)
    if limit:
        items = items[:limit]
    log_and_print(f"Generated {len(items)} test messages for node {node_id}")
    commands = []
    for _, _, case in items:
        if case.kind == "command":
            commands.append(case)
    if commands:
        probe = commands[0]
        if not controller.has_raw_path(node_id, probe.endpoint_id, probe.cluster_id, probe.command_name):
            log_and_print("The Matter server ignores raw_fields - apply patches/skip_type_check.patch "
                          "and restart it.", logging.WARNING)
            return

    baseline = baseline_state(controller, node)
    monitor = DeviceStateMonitor(controller, node_id)
    verdicts = []
    crashed = False
    try:
        for i, (caps, fsm, case) in enumerate(items):
            if i > 0 and caps != items[i - 1][0]:  # the next cluster starts from the baseline again
                restore_node(controller, node_id, baseline)
            verdict = monitor.run(fsm, case)
            verdicts.append(verdict)
            if not verdict.alive:
                crashed = True
                log_and_print(f"Node {node_id} stopped answering - stopping its campaign.", logging.WARNING)
                break
    finally:  # also keep what was found when the server connection breaks or the run is stopped
        file = save_results(node, verdicts, seed, limit, clusters, crashed, baseline)
    if not crashed:
        restore_node(controller, node_id, baseline)
    results(file)


def save_results(node: dict, verdicts: list[Verdict], seed, limit, clusters, crashed, baseline) -> pathlib.Path:
    """Write a run's settings and every verdict to data/runs/<node_id>/<timestamp>.json."""
    node_id = node["node_id"]
    file = RUNS_DIR / str(node_id) / (timestamp() + ".json")
    verdict_list = []
    for v in verdicts:
        entry = dataclasses.asdict(v)
        entry["reasons"] = v.reasons
        verdict_list.append(entry)
    data = {
        "node_id": node_id,
        "matter_version": functionality_extractor.matter_version(node),
        "software_version": node["attributes"].get("0/40/10"),
        "seed": seed,
        "limit": limit,
        "clusters": clusters,
        "crashed": crashed,
        "baseline": baseline,
        "verdicts": verdict_list,
    }
    save_json(file, data)
    log_and_print(f"Results saved to {file}")
    return file


def results(file: pathlib.Path) -> None:
    """Print the summary of a saved run: one row per policy, then the findings."""
    data = json.loads(file.read_text())
    verdicts = data["verdicts"]
    crashed = ""
    if data["crashed"]:
        crashed = ", CRASHED"
    log_and_print(f"Node {data['node_id']} ({file.name}): Matter {data.get('matter_version', '?')}, "
                  f"software {data.get('software_version', '?')}, seed {data.get('seed')}{crashed}")

    policy_set = set()
    for v in verdicts:
        policy_set.add(v["policy"])
    policies = sorted(policy_set)
    log_and_print(f"  {'policy':<8}{'sent':>8}{'susp.':>8}{'N1':>8}{'N2':>8}{'state':>8}{'crash':>8}{'no setup':>10}")
    for policy in policies + ["total"]:
        if policy == "total":
            vs = verdicts
        else:
            vs = []
            for v in verdicts:
                if v["policy"] == policy:
                    vs.append(v)
        suspicious = n1 = n2 = state = crash = no_setup = 0
        for v in vs:
            if v["reasons"]:
                suspicious += 1
            if v["accepted_bad"]:
                n1 += 1
            if v["rejected_good"]:
                n2 += 1
            if v["state_bug"]:
                state += 1
            if not v["alive"] or v["timed_out"]:
                crash += 1
            if not v["setup_ok"]:
                no_setup += 1
        if policy == "total":
            name = policy
        else:
            name = f"P{policy}"
        log_and_print(f"  {name:<8}{len(vs):>8}{suspicious:>8}{n1:>8}{n2:>8}{state:>8}{crash:>8}{no_setup:>10}")
    log_and_print("  N1 = invalid input accepted, N2 = valid input rejected, state = effect differs from the FSM, "
                  "crash = crash or timeout, no setup = source state not reachable")

    findings = {}
    for v in verdicts:
        if v["reasons"]:
            finding = f"{v['case']}: {'; '.join(v['reasons'])}"
            findings[finding] = findings.get(finding, 0) + 1
    if findings:
        log_and_print(f"Findings ({len(findings)} distinct):")
    for finding in sorted(findings):
        log_and_print(f"  {findings[finding]:>3}x {finding}", logging.WARNING)


def build_fsms(node: dict, refresh: bool = False, diagram: bool = False, clusters: list[int] | None = None) -> None:
    """Generate or load the FSMs of a node; diagram also writes a Graphviz drawing next to each."""
    for caps, fsm in cluster_fsms(node, clusters, refresh):
        if diagram:
            dot = knowledge_base.FSM_DIR / f"{caps.cluster_id}_{caps.feature_map}.dot"
            dot.write_text(fsm_mod.to_dot(fsm))
        log_and_print(f"FSM ready for {caps.name}: {len(fsm.states)} states, {len(fsm.transitions)} transitions")

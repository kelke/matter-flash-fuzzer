"""flashfuzz: LLM-assisted fuzzing of Matter devices."""
import argparse
import json
import logging
import os
import pathlib
import sys

from dotenv import load_dotenv

from flashfuzz import device_state_monitor
from flashfuzz import fuzzer
from flashfuzz import utils
from flashfuzz.controller import MatterController
from flashfuzz.utils import env, log_and_print


def connect() -> MatterController:
    return MatterController(env("MATTER_SERVER_URL"))


def load_node(controller: MatterController, node_id: int) -> dict:
    for node in controller.get_nodes():
        if node["node_id"] == node_id:
            return node
    log_and_print(f"Node {node_id} not found.", logging.WARNING)
    sys.exit(1)


def saved_file(folder: pathlib.Path, date: str | None) -> pathlib.Path:
    """The file of that date in folder, by default the newest one."""
    if date:
        path = folder / f"{date}.json"
    else:
        files = sorted(folder.glob("*.json"))
        if files:
            path = files[-1]
        else:
            path = folder
    if not path.is_file():
        log_and_print(f"No saved file {path}.", logging.WARNING)
        sys.exit(1)
    return path


def cmd_add_device(args):
    controller = connect()
    if not controller.diagnostics()["result"]["info"]["wifi_credentials_set"]:
        controller.set_wifi(env("WIFI_SSID"), env("WIFI_PSK"))
    controller.commission(args.code)


def cmd_prepare(args):
    fuzzer.build_fsms(load_node(connect(), args.node), args.refresh, args.diagram, args.clusters)


def cmd_fuzz_plan(args):
    items = fuzzer.plan(load_node(connect(), args.node), args.seed, args.clusters)
    counts = {}
    for _, _, case in items:
        log_and_print(case.label())
        counts[case.policy] = counts.get(case.policy, 0) + 1
    log_and_print(f"\nTotal test messages: {len(items)}")
    for policy in sorted(counts):
        log_and_print(f"  Policy {policy}: {counts[policy]}")


def cmd_fuzz(args):
    controller = connect()
    if args.all_nodes:
        nodes = controller.get_nodes()
    else:
        nodes = [load_node(controller, args.node)]
    for node in nodes:
        if not node.get("available"):  # Would not answer and look like a crash
            log_and_print(f"Node {node['node_id']} is not available - skipped.", logging.WARNING)
            continue
        fuzzer.fuzz_node(controller, node, args.seed, args.limit, args.clusters)


def cmd_results(args):
    fuzzer.results(saved_file(fuzzer.RUNS_DIR / str(args.node), args.date))


def cmd_restore_node(args):
    path = saved_file(device_state_monitor.NODES_DIR / str(args.node), args.date)
    log_and_print(f"Restoring node {args.node} from {path}")
    device_state_monitor.restore_node(connect(), args.node, json.loads(path.read_text()))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="flashfuzz", description="LLM-assisted fuzzing of Matter devices")
    sub = parser.add_subparsers(required=True)
    clusters_help = "only these cluster ids, e.g. 6 8 768 (default: every application cluster with commands)"
    date_help = "timestamp from the file name, e.g. 2026-11-22_15-57-03 (default: the newest)"

    p = sub.add_parser("add-device", help="commission a device (stores the WiFi credentials first if needed)")
    p.set_defaults(func=cmd_add_device)
    p.add_argument("--code", required=True, help="MT:... code")

    p = sub.add_parser("prepare", help="generate and cache the FSMs of a node's clusters")
    p.set_defaults(func=cmd_prepare)
    p.add_argument("--node", type=int, required=True)
    p.add_argument("--clusters", type=int, nargs="+", help=clusters_help)
    p.add_argument("--refresh", action="store_true", help="generate again even if cached")
    p.add_argument("--diagram", action="store_true", help="also write a Graphviz (.dot) drawing")

    p = sub.add_parser("fuzz-plan", help="list the test messages the policies would send (no device traffic)")
    p.set_defaults(func=cmd_fuzz_plan)
    p.add_argument("--node", type=int, required=True)
    p.add_argument("--clusters", type=int, nargs="+", help=clusters_help)
    p.add_argument("--seed", type=int, default=0, help="seed for the random choices of the policies")

    p = sub.add_parser("fuzz", help="send the test messages and judge the answers")
    p.set_defaults(func=cmd_fuzz)
    which = p.add_mutually_exclusive_group(required=True)
    which.add_argument("--node", type=int)
    which.add_argument("--all-nodes", action="store_true", help="every available node")
    p.add_argument("--clusters", type=int, nargs="+", help=clusters_help)
    p.add_argument("--seed", type=int, default=0, help="seed for the random choices of the policies")
    p.add_argument("--limit", type=int, default=0, help="at most this many messages per node (0 = all)")

    p = sub.add_parser("results", help="summary of a saved fuzzing run")
    p.set_defaults(func=cmd_results)
    p.add_argument("--node", type=int, required=True)
    p.add_argument("--date", help=date_help)

    p = sub.add_parser("restore-node", help="put a node back into a state saved at the start of a run")
    p.set_defaults(func=cmd_restore_node)
    p.add_argument("--node", type=int, required=True)
    p.add_argument("--date", help=date_help)
    return parser


def main():
    load_dotenv()
    utils.configure_logging(os.getenv("LOG_LEVEL", "INFO"))
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

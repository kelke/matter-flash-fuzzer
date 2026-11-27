import logging
from dataclasses import dataclass

from flashfuzz import matter_schema
from flashfuzz.utils import log_and_print

ATTR_GENERATED_COMMAND_LIST = 65528
ATTR_ACCEPTED_COMMAND_LIST = 65529
ATTR_ATTRIBUTE_LIST = 65531
ATTR_FEATURE_MAP = 65532

DESCRIPTOR_CLUSTER = 29
DESCRIPTOR_SERVER_LIST = 1


@dataclass
class ClusterCapabilities:
    """Everything the fuzzer needs to know about one cluster on one endpoint."""

    endpoint: int
    cluster_id: int
    name: str
    feature_map: int
    accepted_commands: list[int]
    attribute_list: list[int]


def parse_node(node: dict) -> dict[int, dict[int, dict[int, object]]]:
    """``{endpoint: {cluster: {attribute: value}}}`` from a node's flat attribute map."""
    result: dict[int, dict[int, dict[int, object]]] = {}
    for key, value in node.get("attributes", {}).items():
        parts = key.split("/")
        endpoint, cluster, attr = int(parts[0]), int(parts[1]), int(parts[2])
        result.setdefault(endpoint, {}).setdefault(cluster, {})[attr] = value
    return result


def server_clusters(parsed: dict, endpoint: int) -> list[int]:
    """Cluster ids the Descriptor cluster declares on an endpoint."""
    return list(parsed.get(endpoint, {}).get(DESCRIPTOR_CLUSTER, {}).get(DESCRIPTOR_SERVER_LIST, []))


def all_clusters(parsed: dict) -> set[int]:
    """Every cluster the node implements on any endpoint (for Policy 4's exclusion)."""
    clusters = set()
    for endpoint in parsed:
        for cid in server_clusters(parsed, endpoint):
            clusters.add(cid)
    return clusters


def cluster_capabilities(parsed: dict, endpoint: int, cluster_id: int) -> ClusterCapabilities:
    attrs = parsed.get(endpoint, {}).get(cluster_id, {})
    return ClusterCapabilities(
        endpoint=endpoint,
        cluster_id=cluster_id,
        name=matter_schema.cluster_name(cluster_id),
        feature_map=int(attrs.get(ATTR_FEATURE_MAP, 0)),
        accepted_commands=list(attrs.get(ATTR_ACCEPTED_COMMAND_LIST, [])),
        attribute_list=list(attrs.get(ATTR_ATTRIBUTE_LIST, [])),
    )


def extract(node: dict, cluster_ids: list[int] | None = None) -> list[ClusterCapabilities]:
    """Every application cluster of the node that accepts commands, optionally only cluster_ids."""
    parsed = parse_node(node)
    found = []
    for endpoint in sorted(parsed):
        for cluster_id in server_clusters(parsed, endpoint):
            if cluster_id in matter_schema.UNSAFE_CLUSTERS or (cluster_ids is not None and cluster_id not in cluster_ids):
                continue
            if cluster_id not in matter_schema.all_cluster_ids():
                log_and_print(f"Endpoint {endpoint}: cluster {cluster_id} is unknown to the SDK schema - skipped",
                              logging.WARNING)
                continue
            found.append(cluster_capabilities(parsed, endpoint, cluster_id))
    out = []
    for caps in found:
        if caps.accepted_commands:
            out.append(caps)
    return out


def matter_version(node: dict) -> str:
    """The node's Matter version from BasicInformation SpecificationVersion (``0xAABBCC00``, since Matter 1.3)."""
    attrs = node.get("attributes", {})
    version = attrs.get("0/40/21")
    if version is None:  # older devices only report the DataModelRevision
        return f"< 1.3 (DataModelRevision {attrs.get('0/40/0')})"
    return f"{version >> 24}.{version >> 16 & 0xFF}.{version >> 8 & 0xFF}"

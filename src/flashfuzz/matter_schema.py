import types
import typing
from dataclasses import dataclass

# importing Objects populates the ALL_* registries (ClusterObjects alone holds empty tables)
import chip.clusters.Objects as _Objects  # noqa: F401
from chip.clusters.ClusterObjects import ALL_ACCEPTED_COMMANDS, ALL_ATTRIBUTES, ALL_CLUSTERS
from chip.clusters.Types import Nullable
from chip.tlv import float32, uint

from flashfuzz.fsm import Parameter

# global attributes (AttributeList, FeatureMap, ...) are never state variables
_FIRST_GLOBAL_ATTRIBUTE = 0xF000

# never fuzzed and never Policy 4 probes: a command here could de-commission, reboot or re-network the device
UNSAFE_CLUSTERS: frozenset[int] = frozenset(
    # utility block, Matter core spec 0x001D-0x0046 (fabric, commissioning, OTA, diagnostics, group keys)
    set(range(0x001D, 0x0047))
    | {
        0x0451,  # WiFiNetworkManagement
        0x0452,  # ThreadBorderRouterManagement
        0x0453,  # ThreadNetworkDirectory
        0x0751,  # CommissionerControl
        0x0752,  # JointFabricDatastore
        0x0753,  # JointFabricAdministrator
        0x0801,  # TlsCertificateManagement
        0x0802,  # TlsClientManagement
        # vendor test / MEI clusters, not standard application clusters
        0xFFF1FC05,  # UnitTesting
        0xFFF1FC06,  # FaultInjection
        0xFFF1FC20,  # SampleMei
    }
)

_NONE_TYPES = (Nullable, type(None))
_UNION_ORIGINS = (typing.Union, types.UnionType)
_UNKNOWN_ENUM_MEMBER = "kUnknownEnumValue"


@dataclass(frozen=True)
class Field:
    """One command argument as the SDK encodes it."""

    label: str  # exact SDK field name = the payload key matter-server matches on
    tag: int  # TLV context tag
    type: str  # Matter base-type token (uint, bool, enum8, list, ...)
    nullable: bool  # may be sent as null / omitted
    enum_values: tuple[int, ...] = ()  # defined values of an enum / bitmap type


def all_cluster_ids() -> list[int]:
    return sorted(ALL_CLUSTERS)


def cluster_name(cluster_id: int) -> str:
    cls = ALL_CLUSTERS.get(cluster_id)
    if cls is not None:
        return cls.__name__
    return f"Cluster{cluster_id}"


def attribute_names(cluster_id: int) -> dict[int, str]:
    """``{attribute_id: name}`` of a cluster's non-global attributes."""
    names = {}
    for attr_id, cls in ALL_ATTRIBUTES.get(cluster_id, {}).items():
        if attr_id < _FIRST_GLOBAL_ATTRIBUTE:
            names[attr_id] = cls.__name__
    return names


def attribute_type(cluster_id: int, attribute_id: int) -> str:
    """Matter base-type token of an attribute (as for command fields), ``'unknown'`` without SDK entry."""
    cls = ALL_ATTRIBUTES.get(cluster_id, {}).get(attribute_id)
    if cls is not None:
        return _type_token(cls.attribute_type.Type)[0]
    return "unknown"


def accepted_commands(cluster_id: int) -> dict[int, str]:
    """``{command_id: name}`` of the client->server commands of a cluster."""
    commands = {}
    for cid, cls in ALL_ACCEPTED_COMMANDS.get(cluster_id, {}).items():
        commands[cid] = cls.__name__
    return commands


def _command_class(cluster_id: int, command_name: str):
    for cls in ALL_ACCEPTED_COMMANDS.get(cluster_id, {}).values():
        if cls.__name__ == command_name:
            return cls
    return None


def _type_token(python_type) -> tuple[str, bool, tuple[int, ...]]:
    """(base-type token, nullable, enum values) of an SDK field type; the SDK has no integer widths."""
    nullable = False
    t = python_type
    if typing.get_origin(t) in _UNION_ORIGINS:
        args = typing.get_args(t)
        for a in args:
            if a in _NONE_TYPES:
                nullable = True
        inner = []
        for a in args:
            if a not in _NONE_TYPES:
                inner.append(a)
        if inner:
            t = inner[0]
        else:
            t = type(None)
    if typing.get_origin(t) is list:
        return "list", nullable, ()
    if not isinstance(t, type):
        return "unknown", nullable, ()
    mro = set()
    for m in t.__mro__:
        mro.add(m.__name__)
    # order matters: bool, enums and uint are all int subclasses
    if t is bool:
        return "bool", nullable, ()
    if "IntFlag" in mro:
        values = set()
        for m in t.__members__.values():
            values.add(int(m))
        return "map32", nullable, tuple(sorted(values))
    if "IntEnum" in mro:
        # kUnknownEnumValue (= max + 1) is the SDK's out-of-range sentinel, not a spec value; it is Policy 1b's "above max" probe
        values = set()
        for name, m in t.__members__.items():
            if name != _UNKNOWN_ENUM_MEMBER:
                values.add(int(m))
        return "enum8", nullable, tuple(sorted(values))
    if issubclass(t, uint):
        return "uint", nullable, ()
    if issubclass(t, float32):
        return "single", nullable, ()
    if t is float:
        return "double", nullable, ()
    if issubclass(t, int):
        return "int", nullable, ()
    if t is str:
        return "string", nullable, ()
    if t is bytes:
        return "octstr", nullable, ()
    if hasattr(t, "descriptor"):
        return "struct", nullable, ()
    return "unknown", nullable, ()


def command_fields(cluster_id: int, command_name: str) -> list[Field]:
    """The arguments of a command, in TLV tag order, with exact SDK labels."""
    cls = _command_class(cluster_id, command_name)
    if cls is None:
        return []
    fields = []
    for f in cls.descriptor.Fields:
        token, nullable, values = _type_token(f.Type)
        fields.append(Field(label=f.Label, tag=f.Tag, type=token, nullable=nullable, enum_values=values))
    return fields


def _wire_type(value, field: Field | None) -> str:
    """TLV type token of the patched server for a value; the SDK field tells signed from unsigned."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        if value < 0 or (field is not None and field.type == "int"):
            return "int"
        return "uint"
    if isinstance(value, float):
        if field is not None and field.type == "single":
            return "float"
        return "double"
    return "str"


def raw_fields(cluster_id: int, command_name: str, payload: dict, wire_types: dict) -> list | None:
    """The payload as [tag, value, TLV type] for the raw path; None for a list or struct value."""
    fields = {}
    for f in command_fields(cluster_id, command_name):
        fields[f.label.lower()] = f
    free_tag = -1
    for f in fields.values():
        if f.tag > free_tag:
            free_tag = f.tag
    free_tag += 1
    out = []
    for name, value in payload.items():
        if isinstance(value, (list, dict)):
            return None
        field = fields.get(name.lower())
        if field is not None:
            tag = field.tag
        else:
            tag = free_tag
            free_tag += 1
        out.append([tag, value, wire_types.get(name) or _wire_type(value, field)])
    return out


def sdk_field_name(cluster_id: int, command_name: str, name: str) -> str:
    """The SDK label for an argument name, matched without case; an unknown name (Policy 3) stays as it is."""
    for f in command_fields(cluster_id, command_name):
        if f.label.lower() == name.lower():
            return f.label
    return name


def command_parameters(cluster_id: int, command_name: str) -> list[Parameter]:
    """The command's arguments; an enum gets its defined values as constraint ('0,1,2')."""
    params = []
    for f in command_fields(cluster_id, command_name):
        constraint = ""
        if f.type == "enum8":
            parts = []
            for v in f.enum_values:
                parts.append(str(v))
            constraint = ",".join(parts)
        params.append(Parameter(name=f.label, type=f.type, constraint=constraint))
    return params


def cluster_commands(cluster_id: int) -> list[tuple[int, str, list[Parameter]]]:
    """``(command_id, name, parameters)`` for every accepted command of a cluster."""
    out = []
    for cid, cls in sorted(ALL_ACCEPTED_COMMANDS.get(cluster_id, {}).items()):
        out.append((cid, cls.__name__, command_parameters(cluster_id, cls.__name__)))
    return out


def policy4_candidates(exclude: typing.Iterable[int] = ()) -> list[int]:
    """Application clusters with commands, sorted so a seeded shuffle is reproducible."""
    skip = set(exclude) | UNSAFE_CLUSTERS
    out = []
    for cid in all_cluster_ids():
        if ALL_ACCEPTED_COMMANDS.get(cid) and cid not in skip:
            out.append(cid)
    return out

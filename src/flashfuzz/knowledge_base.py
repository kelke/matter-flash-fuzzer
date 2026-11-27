"""From the specification chapter of a cluster to its FSM."""
import logging
import pathlib
import re
import subprocess
import time

from google import genai
from google.genai import errors, types
from pydantic import BaseModel, Field

from flashfuzz import matter_schema
from flashfuzz.fsm import ClusterFSM, Parameter, State, StateVariable, Transition
from flashfuzz.functionality_extractor import ClusterCapabilities
from flashfuzz.utils import env, log_and_print

SPEC_PDF = pathlib.Path("data/matter_spec/matter1.4-cluster.pdf")
FSM_DIR = pathlib.Path("data/fsm")
RETRYABLE = (429, 500, 502, 503, 504)

# Step 1 of the paper (Figure 5) asks the LLM for the base types; they are fixed, so they are written here.
BASE_DATATYPE_KNOWLEDGE = """\
Matter base data types and value ranges:
- bool: 0 (FALSE) or 1 (TRUE)
- map8 / map16 / map32 / map64: bitmap over 8 / 16 / 32 / 64 bits
- enum8: 0..255; enum16: 0..65535
- uint8: 0..255 (nullable: 0..254, 255=null)
- uint16: 0..65535 (nullable max 65534=null)
- uint24: 0..16777215
- uint32: 0..4294967295 (nullable max 4294967294=null)
- uint64: 0..18446744073709551615
- int8: -128..127; int16: -32768..32767; int32: -2147483648..2147483647; int64: full signed 64-bit
- single: IEEE-754 32-bit float; double: IEEE-754 64-bit float
- string: UTF-8 character string; octstr: octet string
- list: ordered sequence of entries of a given type
"""

CHAPTER_HEADING = re.compile(r"^\d+\.\d+\.\s+(\S.*)Cluster\s*$")


def spec_text(pdf_path: pathlib.Path) -> pathlib.Path:
    out = pdf_path.with_suffix(".txt")
    if not out.exists():
        subprocess.run(["pdftotext", "-layout", str(pdf_path), str(out)], check=True)
    return out


def cluster_text(pdf_path: pathlib.Path, cluster_id: int) -> str:
    """The specification chapter of one cluster, cached under clusters/<id>.txt."""
    cache = pdf_path.parent / "clusters" / f"{cluster_id}.txt"
    if cache.exists():
        return cache.read_text()

    # the chapter title is the SDK name with spaces and punctuation ("On/Off" for OnOff)
    name = matter_schema.cluster_name(cluster_id)
    lines = spec_text(pdf_path).read_text().splitlines()
    start = end = None
    for i, line in enumerate(lines):
        match = CHAPTER_HEADING.match(line)
        if match is None:
            continue
        if start is not None:
            end = i
            break
        if re.sub(r"[^a-z0-9]", "", match.group(1).lower()) == name.lower():
            start = i
    if start is None:
        raise ValueError(f"no chapter for cluster {name} ({cluster_id}) in {pdf_path}")
    text = "\n".join(lines[start:end]).strip()
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(text)
    return text


class DerivedDatatype(BaseModel):
    """A cluster-specific datatype and its value range (Figure 6, query 1)."""

    name: str = Field(description="Derived datatype name, e.g. 'StartUpOnOffEnum', 'MoveModeEnum'.")
    values: str = Field(description="Allowed values or range, e.g. '0,1,2' or '0..254'.")


class CommandSpec(BaseModel):
    """A command of the cluster: id, name and typed arguments (Figure 6, queries 2 + 4)."""

    command_id: int
    name: str = Field(description="Command name from the spec, e.g. 'MoveToLevel'.")
    parameters: list[Parameter] = Field(default_factory=list)


class ClusterInfo(BaseModel):
    """Step 2 answer: derived datatypes, commands, attributes (as state variables) and states."""

    cluster_id: int
    cluster_name: str
    derived_datatypes: list[DerivedDatatype] = Field(default_factory=list)
    commands: list[CommandSpec] = Field(default_factory=list)
    state_variables: list[StateVariable] = Field(default_factory=list)
    states: list[State] = Field(default_factory=list)


class CommandFSM(BaseModel):
    """Step 3 answer: the FSM of a single command (its transitions)."""

    command_id: int
    command_name: str
    transitions: list[Transition] = Field(default_factory=list)
    new_states: list[State] = Field(
        default_factory=list,
        description="States this command needs that are not in the predefined state set.",
    )


def cluster_info_prompt(caps: ClusterCapabilities, text: str) -> str:
    """Step 2: derived datatypes, commands, state variables and states of the cluster.
    
    Based on mGPTFuzz: From One Thousand Pages of Specification to Unveiling Hidden Bugs: Large Language Model Assisted Fuzzing of Matter {IoT} Devices
    https://www.usenix.org/conference/usenixsecurity24/presentation/ma-xiaoyue
    ISBN: 978-1-939133-44-1
    """
    return (
        f"The text below describes the {caps.name} cluster. Answer the four queries that follow,\n"
        "in order and in the format given. Report only what this text states. When the text does not\n"
        "answer a query, leave that field empty.\n\n"
        f"[Datatype Knowledge]\n{BASE_DATATYPE_KNOWLEDGE}\n"
        "[Device capabilities] (read from the device; keep every answer consistent with these)\n"
        f"- Cluster: {caps.name} (id {caps.cluster_id})\n"
        f"- FeatureMap (65532) = {caps.feature_map}\n"
        f"- AcceptedCommandList (65529) = {caps.accepted_commands}\n"
        f"- AttributeList (65531) = {caps.attribute_list}\n\n"
        "Queries:\n"
        "1. derived_datatypes: the datatypes this cluster defines itself (enums, bitmaps, structs),\n"
        "   taken from the 'Data Types' section, with their value ranges.\n"
        "2. commands: every command in the 'Commands' section whose id is in the AcceptedCommandList.\n"
        "   Give the command_id, the name as written in the spec, and the arguments (name, Matter\n"
        "   datatype, and the valid range as 'constraint').\n"
        "3. state_variables: the attributes in the 'Attributes' section (ids from the AttributeList)\n"
        "   whose values make up the device state. Include bound attributes such as MinLevel, MaxLevel\n"
        "   or OnLevel when a command refers to them.\n"
        "4. states: the distinct device states, each as a combination of state-variable values. Give\n"
        "   each state a short id, a description, its conditions (variable/op/value, op one of\n"
        "   eq,ne,lt,le,gt,ge,in,any) and its unaccepted_values.\n\n"
        "Example output (OnOff cluster):\n"
        "state {id:'on', description:'Device is On', conditions:[{variable:'OnOff', op:'eq',\n"
        "value:'true'}]}; command {command_id:66, name:'OnWithTimedOff', parameters:[{name:'OnTime',\n"
        "type:'uint16', constraint:'0..65534'}]}.\n\n"
        f"[Cluster Text]\n{text}"
    )


def command_fsm_prompt(caps: ClusterCapabilities, info: ClusterInfo, command: CommandSpec,
                       text: str) -> str:
    """Step 3: the transitions of one command
    
    Based on mGPTFuzz: From One Thousand Pages of Specification to Unveiling Hidden Bugs: Large Language Model Assisted Fuzzing of Matter {IoT} Devices
    https://www.usenix.org/conference/usenixsecurity24/presentation/ma-xiaoyue
    ISBN: 978-1-939133-44-1
    """
    states = "\n".join(
        f"- {s.id}: {s.description} [" + "; ".join(f"{c.variable} {c.op} {c.value}" for c in s.conditions) + "]"
        for s in info.states
    ) or "- (none predefined; define what you need as new_states)"
    derived = "\n".join(f"- {d.name}: {d.values}" for d in info.derived_datatypes) or "- (none)"
    args = ", ".join(f"{p.name}:{p.type}" for p in command.parameters) or "(no arguments)"
    return (
        "Act as a software testing assistant. The text below is part of the specification of the\n"
        f"cluster {caps.name}. Use it to build the finite state machine (FSM) information for\n"
        "black-box test cases. Rely only on this text. If it gives nothing relevant to the query,\n"
        "return no transitions.\n\n"
        "Work through these steps:\n"
        "1. Find the initial and the destination state in the 'Effect' section of the cluster text.\n"
        "   Map each to a predefined state id, or add a new_state.\n"
        "2. For each command argument, find the value range that moves the device from the initial\n"
        "   to the destination state. Use the 'Datatype Knowledge' below for the datatypes and their\n"
        "   ranges, and put the range in 'constraint'.\n"
        "3. Where the cluster text specifies them, find the invalid values of each argument and the\n"
        "   error the device answers with ('invalid_values' and 'expected_error').\n"
        "4. Find the values each state does not accept.\n\n"
        f"[Cluster Text]\n{text}\n\n"
        f"[Datatype Knowledge]\n{BASE_DATATYPE_KNOWLEDGE}\nDerived datatypes of this cluster:\n{derived}\n\n"
        f"[Predefined states]\n{states}\n\n"
        f"From the text, give the FSM information for the command with ID = {command.command_id}\n"
        f"(name {command.name}, arguments [{args}]): one transition for each initial state it\n"
        "applies to, with trigger_type='command'.\n\n"
        "Example:\n"
        "{command_id:0, command_name:'Off', transitions:[{id:'t_on_off', from_state:'on',\n"
        "to_state:'off', trigger_type:'command', command_id:0, command_name:'Off', parameters:[],\n"
        "expected_error:null}]}"
    )


def cluster_fsm(caps: ClusterCapabilities, refresh: bool = False) -> ClusterFSM:
    """The FSM of a cluster, generated once and cached as data/fsm/<cluster>_<featuremap>.json."""
    cache = FSM_DIR / f"{caps.cluster_id}_{caps.feature_map}.json"
    if cache.exists() and not refresh:
        log_and_print(f"Using cached FSM {cache}")
        return ClusterFSM.model_validate_json(cache.read_text())

    client = genai.Client(api_key=env("GEMINI_API_KEY"), http_options=types.HttpOptions(timeout=300_000))
    model = env("GEMINI_MODEL")
    text = cluster_text(SPEC_PDF, caps.cluster_id)

    log_and_print(f"[{caps.name}] step 2: cluster information ...")
    info = ask(client, model, cluster_info_prompt(caps, text), ClusterInfo)
    states = {}
    for s in info.states:
        states[s.id] = s

    transitions = []
    for command_id in caps.accepted_commands:
        command = None
        for c in info.commands:
            if c.command_id == command_id:
                command = c
                break
        if command is None:  # the LLM missed it; take name and arguments from the SDK so it is still fuzzed
            name = matter_schema.accepted_commands(caps.cluster_id).get(command_id, f"cmd_{command_id}")
            command = CommandSpec(command_id=command_id, name=name,
                                  parameters=matter_schema.command_parameters(caps.cluster_id, name))
        log_and_print(f"[{caps.name}] step 3: command {command_id} ({command.name}) ...")
        answer = ask(client, model, command_fsm_prompt(caps, info, command, text), CommandFSM)
        for s in answer.new_states:
            states.setdefault(s.id, s)
        for t in answer.transitions:
            t.command_id, t.command_name, t.trigger_type = command.command_id, command.name, "command"
            transitions.append(t)

    fsm = ClusterFSM(cluster_id=caps.cluster_id, cluster_name=caps.name, feature_map=caps.feature_map,
                     state_variables=info.state_variables, states=list(states.values()),
                     transitions=renumber(transitions), models=[model], spec=SPEC_PDF.name)
    FSM_DIR.mkdir(parents=True, exist_ok=True)
    cache.write_text(fsm.model_dump_json(indent=2))
    log_and_print(f"FSM written to {cache} ({len(fsm.states)} states, {len(fsm.transitions)} transitions)")
    return fsm


def ask(client: genai.Client, model: str, prompt: str, schema):
    """One query whose answer must be JSON of the given pydantic schema, at temperature 0."""
    config = types.GenerateContentConfig(response_mime_type="application/json", response_schema=schema,
                                         temperature=0.0)
    for _ in range(6):
        try:
            response = client.models.generate_content(model=model, contents=[prompt], config=config)
            if response.parsed is not None:
                return response.parsed
            # the SDK returns parsed=None for invalid JSON, e.g. an answer cut off at the token limit
            log_and_print(f"Gemini {model}: answer is not valid {schema.__name__} JSON, asking again",
                          logging.WARNING)
        except errors.APIError as e:
            if e.code not in RETRYABLE:
                raise
            log_and_print(f"Gemini {model}: error {e.code}, waiting 60 s", logging.WARNING)
            time.sleep(60)
    raise ValueError(f"no valid {schema.__name__} answer after 6 attempts")


def renumber(transitions: list[Transition]) -> list[Transition]:
    """Unique transition ids; the same command on the same edge is kept once."""
    out = []
    seen = set()
    for t in transitions:
        key = (t.command_id, t.attribute_id, t.from_state, t.to_state)
        if key in seen:
            continue
        seen.add(key)
        t.id = f"t{len(out)}_{t.command_name or t.attribute_id}"
        out.append(t)
    return out

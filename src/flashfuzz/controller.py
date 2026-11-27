import json
import logging
from dataclasses import dataclass

from websockets.exceptions import ConnectionClosed
from websockets.sync.client import connect

from flashfuzz import matter_schema
from flashfuzz.fuzzing_policies import FuzzCase
from flashfuzz.utils import log_and_print

# reading BasicInformation.DataModelRevision (endpoint 0) works on every node. A failing read means the node is gone
LIVENESS_PROBE = "0/40/0"

# Interaction Model status codes
IM_STATUS = {
    0x00: "SUCCESS", 0x01: "FAILURE", 0x7E: "UNSUPPORTED_ACCESS", 0x7F: "UNSUPPORTED_ENDPOINT",
    0x80: "INVALID_ACTION", 0x81: "UNSUPPORTED_COMMAND", 0x85: "INVALID_COMMAND",
    0x86: "UNSUPPORTED_ATTRIBUTE", 0x87: "CONSTRAINT_ERROR", 0x88: "UNSUPPORTED_WRITE",
    0x89: "RESOURCE_EXHAUSTED", 0x8B: "NOT_FOUND", 0x8C: "UNREPORTABLE_ATTRIBUTE",
    0x8D: "INVALID_DATA_TYPE", 0x8E: "UNSUPPORTED_READ", 0x92: "DATA_VERSION_MISMATCH",
    0x94: "TIMEOUT", 0x9D: "BUSY", 0xC3: "UNSUPPORTED_CLUSTER", 0xC6: "NEEDS_TIMED_INTERACTION",
    0xC7: "UNSUPPORTED_EVENT", 0xC8: "PATHS_EXHAUSTED", 0xC9: "TIMED_REQUEST_MISMATCH",
    0xCA: "FAILSAFE_REQUIRED", 0xCB: "INVALID_IN_STATE", 0xCC: "NO_COMMAND_RESPONSE",
}


def is_error(answer: dict) -> bool:
    # error_code is 0 even for a rejection, so only its presence counts
    return "error_code" in answer


def error_name(answer: dict) -> str:
    """A short status name from an error answer, e.g. ``'InvalidCommand (0x85)'``."""
    details = str(answer.get("details") or "")
    return details.split(": ", 1)[-1] if details else f"error_code {answer.get('error_code')}"


def write_status(answer: dict) -> str:
    """The device's status for an attribute write, from a success answer."""
    result = answer.get("result")
    if isinstance(result, list) and result and isinstance(result[0], dict) and "Status" in result[0]:
        code = result[0]["Status"]
        return IM_STATUS.get(code, f"IM_STATUS_{code}")
    return "SUCCESS"


def response_from_answer(case_kind: str, answer: dict, raw: bool = False) -> "Response":
    """The device's verdict in a server answer. raw: the command went out unchecked, so no error means accepted."""
    if is_error(answer):
        return Response(error_name(answer), answer)
    if case_kind == "command":
        result = answer.get("result")
        # Groups and Scenes answer with a response command that includes the status in its payload
        status = result.get("status") if isinstance(result, dict) else None
        if status:
            return Response(IM_STATUS.get(status, f"status {status}"), answer)
        return Response("SUCCESS" if raw else "SENT", answer)
    return Response(write_status(answer), answer)


@dataclass
class Response:
    """What the device answered to a test message, as far as the server exposes it."""

    status: str  # 'SUCCESS' (accepted by the device), 'SENT' (sanitized command dispatched), an error name, or 'EXCEPTION'
    raw: dict

    @property
    def accepted(self) -> bool:
        return self.status in ("SUCCESS", "SENT")

    @property
    def timed_out(self) -> bool:
        return self.status == "EXCEPTION"


class MatterController:

    def __init__(self, url: str):
        self.socket = connect(url)
        self.socket.recv()
        self.last_id = 0
        log_and_print(f"Connected to Matter server at {url}")

    def call(self, command: str, args: dict | None = None) -> dict:
        """Send one server API message and return its answer."""
        # no start_listening, so the server sends only the answer
        self.last_id += 1
        message = {"message_id": str(self.last_id), "command": command}
        if args is not None:
            message["args"] = args
        logging.debug("-> %s", message)
        self.socket.send(json.dumps(message))
        answer = json.loads(self.socket.recv())
        logging.debug("<- %s", answer)
        return answer

    def diagnostics(self) -> dict:
        return self.call("diagnostics")

    def get_nodes(self) -> list[dict]:
        return self.call("get_nodes").get("result") or []

    def set_wifi(self, ssid: str, psk: str) -> dict:
        return self.call("set_wifi_credentials", {"ssid": ssid, "credentials": psk})

    def commission(self, code: str) -> dict:
        return self.call("commission_with_code", {"code": code})

    def send_command(self, node_id: int, endpoint: int, cluster_id: int,
                     command_name: str, payload: dict | None = None,
                     raw_fields: list | None = None) -> dict:
        """Send a command, renaming payload keys to the SDK field labels first."""
        renamed = {}
        for k, v in (payload or {}).items():
            renamed[matter_schema.sdk_field_name(cluster_id, command_name, k)] = v
        payload = renamed
        args = {"node_id": node_id, "endpoint_id": endpoint, "cluster_id": cluster_id,
                "command_name": command_name, "payload": payload}
        if raw_fields is not None:
            args["raw_fields"] = raw_fields
        return self.call("device_command", args)

    def has_raw_path(self, node_id: int, endpoint: int, cluster_id: int, command_name: str) -> bool:
        """An unpatched server ignores raw_fields and sends the checked command, which would count as accepted."""
        answer = self.send_command(node_id, endpoint, cluster_id, command_name, raw_fields=[[0, 0, "notatype"]])
        return "Unknown TLV type" in str(answer.get("details"))

    def write_attribute(self, node_id: int, path: str, value, value_type: str | None = None) -> dict:
        """Write-Attribute. ``value_type`` forces a TLV wire type (patched server only)."""
        args = {"node_id": node_id, "attribute_path": path, "value": value}
        if value_type is not None:
            args["value_type"] = value_type
        return self.call("write_attribute", args)

    def read_attribute(self, node_id: int, path: str):
        """Fresh value of ``endpoint/cluster/attribute`` straight from the device, or ``None``."""
        try:
            answer = self.call("read_attribute", {"node_id": node_id, "attribute_path": path})
        except ConnectionClosed:
            raise  # the server connection is gone, not the device: not a crash
        except Exception as e:
            logging.debug("read_attribute %s failed: %s", path, e)
            return None
        if is_error(answer):
            return None
        result = answer.get("result")
        if isinstance(result, dict):
            if path in result:
                return result[path]
            for value in result.values():
                return value
            return None
        return result

    def is_alive(self, node_id: int) -> bool:
        """Crash oracle probe (§5.5): does the node still answer a trivial read?"""
        return self.read_attribute(node_id, LIVENESS_PROBE) is not None

    def send(self, node_id: int, case: FuzzCase) -> Response:
        """Send one test message; an exception is not raised but returned as status EXCEPTION."""
        raw_fields = None
        try:
            if case.kind == "command":
                if case.policy != "4":  # Clusters the device does not need also dont need the raw path
                    raw_fields = matter_schema.raw_fields(case.cluster_id, case.command_name,
                                                          case.payload, case.value_types)
                answer = self.send_command(node_id, case.endpoint_id, case.cluster_id,
                                           case.command_name, case.payload, raw_fields)
            else:
                path = f"{case.endpoint_id}/{case.cluster_id}/{case.attribute_id}"
                value = None
                for v in case.payload.values():
                    value = v
                    break
                value_type = None
                for v in case.value_types.values():
                    value_type = v
                    break
                answer = self.write_attribute(node_id, path, value, value_type)
        except Exception as e:
            logging.warning("test message raised: %s", e)
            return Response("EXCEPTION", {})
        return response_from_answer(case.kind, answer, raw_fields is not None)

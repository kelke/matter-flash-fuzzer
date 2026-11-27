import datetime
import json
import logging
import os
import pathlib


def timestamp() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def configure_logging(level: str):
    logfile = pathlib.Path("logs") / (timestamp() + ".log")
    logfile.parent.mkdir(exist_ok=True)
    logging.basicConfig(filename=logfile, level=level.upper(), format="%(asctime)s %(levelname)s: %(message)s")


def log_and_print(message, level: int = logging.INFO):
    logging.log(level, message)
    print(message)


def save_json(file: pathlib.Path, data) -> None:
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(json.dumps(data, indent=2, default=str))


def env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise SystemExit(f"{name} is not set in .env")
    return value

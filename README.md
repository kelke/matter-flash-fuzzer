# flashfuzz

Code for the master's thesis: *Semantic-Aware Fuzzing: Leveraging LLMs for
Vulnerability Discovery in Matter IoT Devices*.

## Setup

Python 3.12 is required. Run `scripts/setup.sh` once to create the  `.venv` and install
the package. Copy `.env.template` to `.env` and fill in the required variables.
`pdftotext` (poppler-utils) is needed to
read the specification PDF.

### Matter specification

The Matter 1.4 application cluster specification is needed, but it is not included
here because redistributing it is prohibited. Download it from

https://csa-iot.org/wp-content/uploads/2024/11/23-27350-005_matter-1-4-application-cluster-specification.pdf?ver=1763071986

and save it as `data/matter_spec/matter1.4-cluster.pdf`.

### Matter server

The fuzzer is a client of a patched python-matter-server. Install it and apply the
patch from this repository:

    git clone https://github.com/home-assistant-libs/python-matter-server.git
    cd python-matter-server
    git checkout 4c820ed
    git apply /path/to/flashfuzz/patches/skip_type_check.patch
    python -m pip install .

If the server fails to start because it cannot parse one of the PAA root
certificates, also apply `patches/handle_malformed_root_ca.patch`.

## Usage

Run the commands from the repository folder as `.venv/bin/flashfuzz <command>`.

- `add-device --code MT:...` commissions a device.
- `prepare --node N` builds the FSMs of the node's clusters and caches them in
  `data/fsm/` (`--refresh` builds them again, `--diagram` writes a Graphviz drawing).
- `fuzz-plan --node N` lists the test messages without sending them.
- `fuzz --node N` (or `--all-nodes`) sends them and saves the run under
  `data/runs/<node>/`. The device state is restored after each cluster.
- `results --node N` prints the summary of the newest run, `--date` picks an older one.
- `restore-node --node N` puts the device back into the state saved at the start of a run.

`--clusters 6 8` limits `prepare`, `fuzz-plan` and `fuzz` to these clusters,
`--seed` changes the random choices.

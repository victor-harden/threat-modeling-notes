# threat-modeling-notes

Practical notes on threat modeling (STRIDE, data-flow diagrams, attack trees) and
a generator that turns a component list into a structured threat model document
with threats, mitigations and a simple risk score.

## Features

- Notes on STRIDE, trust boundaries and attack trees.
- `tools/threat_model.py` generates Markdown or JSON from components such as
  `Web app:web`, `API:api`, `Database:db`, `User:actor`, `Worker:process`.
- Every component type maps to a STRIDE subset with concrete mitigations.
- Risk score = likelihood × impact (1–5 each), sortable in the output.

## Installation

```bash
git clone https://github.com/victor-harden/threat-modeling-notes.git
cd threat-modeling-notes
```

## Usage

```bash
python3 tools/threat_model.py --component "Public web app:web"     --component "API:api" --component "Postgres:db" --component "Customer:actor"
python3 tools/threat_model.py --component "API:api" --json
python3 tools/threat_model.py --component "Cache:db" --out threat-model.md
```

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## License

MIT — see [LICENSE](LICENSE).

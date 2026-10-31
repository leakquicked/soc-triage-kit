# SOC Triage Kit

Triage sanitized alerts using transparent severity heuristics.

## Usage
```bash
python soc_triage_kit.py sample.txt
python soc_triage_kit.py sample.txt --output report.json
```

Python 3.10+, standard library only. The tool reads a local UTF-8 text file and emits JSON findings. It makes no network requests and does not modify input files.

## Rules
- `critical` — critical severity heuristic.
- `auth` — high severity heuristic.

Findings are leads for human review, not proof of compromise. Use only data you own or are authorized to inspect. Do not publish personal or confidential data.

## Tests
Run `python -m unittest discover -s tests -v`.

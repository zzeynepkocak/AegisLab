# AegisLab

A defensive security lab: an intentionally weak corporate AI assistant
with mocked tools (RAG, fake CRM, fake email, fake SQL), used to study
attacks and defenses in a contained environment.

This repository currently contains only the **project skeleton**.
No agent logic, tools, or attacks are implemented yet.

## Status

Skeleton only. See `docs/ARCHITECTURE.md` for planned structure
(headings only, no implementation yet).

## Requirements

- Python 3.12

## Setup

```bash
python -m venv venv
source venv/bin/activate
pip install -e .
```

## Run

The app entrypoint will later be:

```bash
python -m aegislab
```

Not implemented yet.

## Test

```bash
python -m pytest
```

## Safety

This is a defensive security lab.

- All tools are mocked. No real email, no real database outside the
  lab container.
- No network calls to third-party services. Localhost only, and only
  when explicitly allowed.
- Any lab attack payloads live under `/attacks` and are clearly marked
  `LAB-ONLY`. Nothing here targets production systems.

## License

MIT — see `LICENSE`.

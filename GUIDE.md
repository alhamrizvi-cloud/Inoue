# Inoue extension and update guide

This repository now supports three main maintenance workflows:

1. Expand the fingerprint catalog with more services, cloud portals, ICS/SCADA surfaces, and admin panels.
2. Improve version detection by combining header, HTML, script, and path-based heuristics.
3. Update the local clone automatically from the repository via the built-in `update` command.

## 1. Expand the catalog

The main signature catalog is stored in [fingerprints/signatures.py](fingerprints/signatures.py) and is merged with the extended catalog in [fingerprints/extended_catalog.py](fingerprints/extended_catalog.py).

To add a new service:

- Open [fingerprints/signatures.py](fingerprints/signatures.py)
- Add a new entry in the `SIGNATURES` dictionary using the existing schema
- Optionally add a companion entry in [fingerprints/extended_catalog.py](fingerprints/extended_catalog.py) if you want it to be part of the broader generated catalog

Example:

```python
"Example Portal": {
    "category": "Cloud",
    "html": [r"Example Portal", r"example-portal"],
    "paths": [r"/login", r"/admin"],
}
```

## 2. Improve version detection

Version detection now uses a layered approach:

- regex capture groups from headers and body patterns
- nearby version-like strings in response content
- path and script URL hints such as `/v2.3.1/`

When adding a signature, prefer regex groups that capture versions directly, for example:

```python
"Example Service": {
    "category": "Cloud",
    "headers": {"Server": r"ExampleService(?:/([0-9.]+))?"},
}
```

The scanner will normalize versions such as `1.2.3`, `v1.2.3`, `release-2.4`, and similar forms.

## 3. Update the tool automatically

The CLI includes an update command:

```bash
python inoue.py update
```

This command runs:

```bash
git fetch --all --prune
git pull --ff-only
```

If you want the update process to pull from a specific remote branch, adjust the command in [inoue.py](inoue.py).

## 4. Validate changes

Run the regression suite after editing signatures:

```bash
python -m unittest discover -s tests -p 'test*.py' -q
```

And verify the modules still compile:

```bash
python -m compileall core fingerprints inoue.py
```

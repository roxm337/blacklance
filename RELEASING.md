# Releasing osintAgent

## Versioning

- **SemVer 2.0** for the package: `MAJOR.MINOR.PATCH`, git tag `vX.Y.Z`.
- **Pre-1.0** until the R7–R12 shared contracts are validated: breaking
  changes bump MINOR (`0.10.0 → 0.11.0`); fixes bump PATCH. 1.0.0 is a
  promise of stable interfaces — do not claim it early.
- **Single source of truth**: the `VERSION` file. `setup.py` reads it; the
  git tag must match it exactly.
- **Persisted schemas are versioned independently.** `snapshot.json`,
  evidence indexes, `operations.jsonl`, `mutations.jsonl`, traffic and
  matrix reports carry their own `schema_version`. Migrations key off that
  value — never off the package version.
- **Detection content is versioned separately** from the package
  (modules, payloads, wordlists, scanner rules change more often than
  interfaces). Record the content revision in reports so an assessment
  stays reproducible across releases.

## Branch and tag policy

- One branch per change (`feat/*`, `fix/*`, `test/*`, `chore/*`, `docs/*`);
  `main` is the release line and only receives approved merges.
- Tags live on `main`. A release tag is annotated and never moved.
- No pushes to the remote without the owner's explicit confirmation.

## Release checklist

1. Working tree clean on the approved branch; full suite green:
   - `python -m pytest --ignore=tests/test_gui_app.py --ignore=tests/test_gui_graph.py`
   - GUI suite with PySide6: `python -m pytest tests/test_gui_app.py tests/test_gui_graph.py`
2. Lab gates where a lab is available (`OSINT_LAB_URL`, `OSINT_LAB_URL_VULN/_FIXED`);
   they must skip cleanly when unreachable.
3. Bump `VERSION` per SemVer. Draft the changelog from the commits since
   the previous tag: `git log --oneline vPREV..HEAD`.
4. Build and smoke-test the installed wheel:
   - `python -m build --wheel`
   - `python scripts/check_wheel.py dist/*.whl`
   - Locally, a generated `build/` directory can (a) shadow the `build`
     module and (b) contaminate wheel staging. In that case build with a
     fresh base:
     `python setup.py build --build-base /tmp/osint-build bdist_wheel --bdist-dir /tmp/osint-bdist -d /tmp/osint-wheel`
     then run the smoke check against that wheel.
5. Merge the approved branch to `main` (fast-forward when possible) and
   verify `git rev-parse HEAD` is the tested commit.
6. `git tag -a vX.Y.Z -m "vX.Y.Z"` on that commit.
7. Post-release spot checks from the wheel: `osint-agent --list-modules`,
   `osint-agent --tools`.

Publishing (PyPI, container images) and SBOM/provenance pinning are R11
items and require a license decision first.

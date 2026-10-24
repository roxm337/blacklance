"""Install a built wheel into temporary storage and smoke-test outside the checkout."""

import subprocess
import sys
import tempfile
from pathlib import Path
from zipfile import ZipFile


SMOKE = """
import sys, tempfile
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import orchestrator, knowledge
from state.manager import StateManager
from core.reporting import write_report_bundle
from osint_agent_resources import resource_path
root = Path(sys.argv[1]).resolve()
assert Path(orchestrator.__file__).resolve().is_relative_to(root)
assert knowledge.load_pack('juice_shop_lab')
assert (root / 'gui/theme.qss').is_file()
assert resource_path('rules/semgrep/js-sinks.yaml').is_file()
with tempfile.TemporaryDirectory() as output:
    run = orchestrator.Orchestrator('example.test', output)
    assert run.config['wordlists']['misconfig_paths']
    run.state.add_asset('domain', 'domain:example.test', 'example.test')
    evidence_id = run.state.add_evidence('smoke', 'json', 'fixture', {'ok': True})
    run.state.save()
    restored = StateManager(str(run.state.output_dir))
    assert restored.snapshot_file.exists()
    assert restored.verify_evidence(evidence_id)['ok']
    assert restored.assets['nodes'][0]['value'] == 'example.test'
    write_report_bundle(restored, 'example.test')
    run.close()
print('Installed wheel: CLI/resources, transactional state, evidence and reports OK')
"""


def main():
    wheel = Path(sys.argv[1]).resolve()
    with ZipFile(wheel) as archive:
        assert not any(name.startswith("tests/") for name in archive.namelist())
        assert not any(Path(name).name in {".DS_Store", ".env", "config.yaml"}
                       for name in archive.namelist())
    with tempfile.TemporaryDirectory(prefix="osint-wheel-smoke-") as directory:
        installed = Path(directory) / "installed"
        subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", "--no-deps",
                        "--no-index", "--target", str(installed), str(wheel)], check=True)
        subprocess.run([sys.executable, "-I", "-c", SMOKE, str(installed)],
                       cwd=directory, check=True)


if __name__ == "__main__":
    main()

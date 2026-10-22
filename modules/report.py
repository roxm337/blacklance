"""Stage 6: Reporting — writes structured report artifacts."""

import json
from pathlib import Path

from core.reporting import write_report_bundle
from modules.base import BaseModule


class Reporting(BaseModule):
    id = "reporting"
    name = "Reporting"
    stage = 6
    detectability = "low"
    depends_on = []  # Runs after all others

    async def run(self) -> str:
        self.log("Generating report...")

        target = self.domain
        paths = write_report_bundle(self.state, target)

        self.log(f"Report written to {paths['report']}")

        # Diff alerts go to the console, not only into the JSON. A scheduled
        # re-scan is only useful if the new surface and new findings are
        # visible without opening the report first.
        try:
            diff = json.loads(Path(paths["regression"]).read_text())
        except (OSError, ValueError):
            diff = {}
        for item in diff.get("new", []):
            self.log(f"NEW FINDING [{item.get('severity')}] "
                     f"{item.get('title')} {item.get('url', '')}".rstrip())
        assets = diff.get("assets") or {}
        for item in assets.get("new", []):
            self.log(f"NEW ASSET [{item.get('type')}] {item.get('key')}")
        for item in assets.get("resolved", []):
            self.log(f"RESOLVED ASSET [{item.get('type')}] {item.get('key')}")
        self.state.complete_module(self.id)
        return "done"

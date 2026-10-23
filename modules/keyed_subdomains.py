"""Stage 2: Keyed passive subdomain enrichment."""

from modules.base import BaseModule
from tools.wrappers import chaos_subdomains, securitytrails_subdomains


class KeyedSubdomains(BaseModule):
    id = "keyed_subdomains"
    name = "Keyed Subdomain Enrichment"
    stage = 2
    detectability = "low"
    depends_on = ["seed_discovery"]

    async def run(self) -> str:
        sources = []
        if self.keys.has("chaos"):
            sources.append(("chaos", chaos_subdomains, self.keys.get("chaos")))
        if self.keys.has("securitytrails"):
            sources.append((
                "securitytrails",
                securitytrails_subdomains,
                self.keys.get("securitytrails"),
            ))

        if not sources:
            self.state.skip_module(
                self.id,
                "Chaos/SecurityTrails keys missing; set CHAOS_API_KEY or SECURITYTRAILS_API_KEY",
            )
            return "skipped"

        discovered = set()
        for source_name, source_func, api_key in sources:
            try:
                hostnames = await source_func(self.domain, api_key)
            except Exception as exc:
                # One bad key must not kill the other source: record and
                # move on, so a dead Chaos key still leaves SecurityTrails.
                self.log(f"  {source_name} failed ({exc}); continuing")
                self.state.add_evidence(
                    self.id, "keyed_subdomains", source_name,
                    {"source": source_name, "error": str(exc)},
                )
                continue
            self.state.add_evidence(
                self.id,
                "keyed_subdomains",
                source_name,
                {"source": source_name, "count": len(hostnames), "hosts": hostnames[:500]},
            )
            for hostname in hostnames:
                clean = str(hostname or "").strip().lower().lstrip("*.").strip(".")
                if not clean:
                    continue
                discovered.add(clean)
                self.state.add_asset(
                    "subdomain",
                    f"sub:{clean}",
                    clean,
                    confidence="FIRM",
                    sources=[source_name],
                )
                self.state.add_edge(
                    f"domain:{self.domain}",
                    f"sub:{clean}",
                    f"{source_name}_subdomain",
                )

        self.state.complete_module(self.id)
        self.log(f"Keyed subdomains: {len(discovered)} unique")
        return "done"

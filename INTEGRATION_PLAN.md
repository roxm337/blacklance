# Framework reliability and integration backlog

Updated: 2026-10-24. This is the authoritative delivery order. Older roadmaps
are historical design documents, not current completion checklists.

Status vocabulary: **planned** → **implementing** → **implemented** → **validated**.
Implemented means code and regression coverage exist; validated additionally needs
the acceptance evidence below. A unit test, tool match, or module registration is
not evidence of live assessment quality. Scope changes are excluded.

## 1. Current baseline and reliability work

The registry currently contains 79 modules. Preserve the existing module, action,
HTTP, authentication, evidence, reporting, and GUI interfaces while closing gaps.
See [FIX_PROGRESS.md](FIX_PROGRESS.md) for completed verification runs.

| ID | Work | Status | Implementation / acceptance |
|---|---|---|---|
| R1 | Transactional state and stale-writer protection | Implemented | `state/manager.py`, `core/persistence.py`; one authoritative snapshot, revision comparison under a process lock, unique evidence filenames. Two processes cannot silently overwrite; injected pre-commit failure preserves the old generation. |
| R2 | Consistent GUI state reads | Implemented | `gui/app.py`; one snapshot for all stores, legacy-file fallback only when no snapshot exists. Corruption retains previous tables and flags an error. |
| R3 | Conservative history and repeatable exports | Implemented | `core/history.py`, `core/reporting.py`; identical observation exports do not increment occurrences; absence is untested; resolution requires explicit negative-retest keys. JSON artifacts share annotations. |
| R4 | Independent audit writers | Implemented | `core/audit_log.py`; process lock, refresh/verify externally changed tail, contiguous sequences, reject observed truncation/corruption. External anchoring remains R10. |
| R5 | Accurate module retest status | Implemented | `state/manager.py`; starting a retest clears old success/skip/block state; unsuccessful completion cannot retain a success badge. |
| R6 | Origin and assessment isolation; fresh/resume/retest | Planned | `orchestrator.py`, state, GUI. Versioned canonical origin and assessment IDs, separate service/run stores, explicit migration preserving old reports. Two ports on one hostname must not share completion state. No new target-selection restrictions. |
| R7 | One execution and accounting contract | Planned | Orchestrator, registry, all transports/tools. Every started/refused/failed/cancelled operation gets a typed result, accounting, and evidence references. Include browser, raw sockets, subprocesses, and Docker. |
| R8 | Durable mutation/cleanup ledger | Planned | State, auth harness, mutating modules. Record before-state, owned test objects, attempted rollback and verified cleanup; cancellation/resume retries outstanding cleanup. Never imply a rollback succeeded without checking. |
| R9 | Causal chain execution | Planned | `core/chain_executor.py`, action schemas. Typed preconditions, output bindings, branch outcomes, credential references and dependency ordering. A failed prerequisite prevents dependent execution; independent branches remain possible. Existing sorted edge probes are not completed causal chains. |
| R10 | Evidence and credential lifecycle | Planned | Secret-store references, expiry/revocation, redacted exports, externally anchored manifests. Local hashes alone are not signatures or protection against whole-store replacement. |
| R11 | Reproducible releases and compatibility | Planned | Pin scanner images by digest and tool/template versions; record provenance, SBOM and license inventory. Real Docker/parser compatibility jobs, installed-wheel checks, Python matrix, config schema, release/version alignment. Licensing requires the owner's choice. |
| R12 | Measured assessment quality | Planned | Vulnerable/fixed/ambiguous lab pairs, negative controls, precision/recall, request cost, cleanup success, timeout/cancellation and expired-auth cases. Publish measured results before promoting a capability to validated. |

R1 rejects conflicts; it does not merge independent writers or isolate origins/runs.
Packaging also rejects unexpected stale staging files rather than silently shipping
them. Clean installed-wheel state/evidence/report smoke checks are implemented;
the remaining version pinning and compatibility matrix still belong to R11.
Compatibility JSON views are not a multi-file transaction. New StateManager and GUI
readers use the authoritative snapshot. R3 uses an observation digest, not a durable
assessment ID; R6 must supply that later. Automatic collection of endpoint-specific
negative retest evidence is still planned. Report exports do not infer resolution
from module completion or an empty result list.

## 2. Shared contract for every new integration

Implement R6–R8 and an initial R12 harness before enabling new active adapters.
No external tool is installed, enabled, or granted credentials by this plan.

Each adapter must declare:

- Tool/version/image/template provenance, required capabilities, configuration
  schema, timeout, dependency checks, and unsupported-version behavior.
- Typed input/output, identity references (not embedded secrets), request/time/token
  budgets, cancellation, isolated temporary storage, and cleanup ownership.
- Result kind: observation, candidate, proof, error, or unsupported. Schema errors,
  tool exits, HTTP 500s and model-judge scores never automatically mean vulnerability.
- Reproduction evidence, transport coverage, truncation/untested reasons, and stable
  finding fingerprints. Reproduction artifacts must not contain credentials.
- A parser fixture corpus and vulnerable/fixed/ambiguous lab tests. Keep external
  tools in optional dependencies or isolated processes, not the default core runtime.

## 3. Planned integration sequence

Effort is relative: M = moderate adapter/test work; L = architectural or substantial
lab work. These are engineering estimates, not delivery-date promises.

| ID | Capability / proposed files | Dependencies | Effort / acceptance |
|---|---|---|---|
| I1 | Replayable browser traffic: extend `modules/browser_crawl.py`; add `core/traffic.py`, `core/workflows.py` | R6–R8, R12 | M. Capture XHR/fetch methods, request bodies, response relationships and identity provenance; redact persisted data. Replay a lab workflow with fresh tokens and prove cleanup. |
| I2 | Schemathesis adapter: `tools/schemathesis.py`, `modules/api_workflows.py` | I1, R7–R8 | M. Consume discovered OpenAPI/GraphQL schemas, create linked operation sequences, minimize repros. A seeded multi-step defect reproduces; fixed twin passes. Schema violations remain observations unless impact is proven. |
| I3 | Authorization matrix: extend IDOR, BFLA and GraphQL modules | I1–I2, R6 | M. Identity × tenant × operation × object × field; verify ownership, sharing, auth freshness, and revocation. Prove a forbidden canary read/action using configured test identities. |
| I4 | Browser request-flow/CSPT: `modules/cspt_audit.py` | I1, R8 | M. Trace controlled browser inputs to altered API request paths and then impact. Traversal-like strings or normalization alone are not confirmed findings. |
| I5 | ORM/filter leaks: `modules/orm_filter_audit.py`; optional source-rule importer | I2–I3 | M. Target discovered filtering/search surfaces; controlled seeded records prove unauthorized field/relationship access. Avoid real-secret extraction and timing-only promotion. |
| I6 | Stateful business logic and bounded race testing | I1, R7–R8 | L. Declare invariants, serial controls, replay/idempotency expectations and trial limits. Repeated concurrent violation must contrast with serial behavior; final state and cleanup verified. |
| I7 | WebSocket capture/replay and authorization: `tools/websocket_engine.py`, `modules/websocket_audit.py` | I1, R7–R8 | M. Handshake origin, message authorization, subscriptions and revocation. Private canary data/action proves impact; handshake acceptance alone does not. gRPC is a later independent adapter. |
| I8 | AI/MCP assessment pack; evaluate PyRIT vs Promptfoo, choose one first | R7–R8, R10, R12 | M–L. Multi-turn isolation, retrieval/tool authorization, MCP audience/state ownership checks. Confirm a forbidden canary flow or tool action, not merely prompt compliance. Explicitly configure model providers, data handling and token costs. Also test this framework against hostile target content. |
| I9 | Authenticated cloud posture ingestion: Prowler | R6–R7, R10 | M–L. Ingest configurations/identity relationships from an operator-supplied cloud account. Posture findings and inferred paths remain distinct from demonstrated access. Cloud credentials are never inferred from a domain target. |
| I10 | Supplied-artifact software inventory: select Trivy or OSV-Scanner first | R7, R11 | M. Consume supplied repo/image/lockfile/SBOM, preserve package and advisory provenance. A version match is not proof of remotely exploitable deployment. No automatic dependency remediation. |
| I11 | Scenario interchange and defensive validation: Attack Flow, OpenTelemetry; optional selected Stratus lab scenarios | R8–R9, R12 | L. Export dependencies, conditions, outcomes and evidence; correlate separately obtained defensive events. Framework traces alone cannot prove a SIEM alert or a defensive miss. Verify prerequisite failure, delayed telemetry and cleanup in sandbox labs. |

I1–I3 are the first functional integration milestone. Prefer extending existing
sensors over duplicating general scanners. I4–I7 add targeted coverage. I8–I11
are separate optional packs and should not delay the first milestone.

## 4. Research lane (not release commitments)

Track HTTP parser differentials, modern desync, HTTP/3 behavior, and AI-platform
application-security research. New research enters a local lab fixture first,
then a bounded detector, then the measured suite. Recency or a public PoC is not
a release gate. Resolve CVEs against vendor/CNA advisories and CISA KEV with fetch
timestamps; do not hard-code current exploitation status from prose documents.

Scoring remains an explainable prioritization heuristic. Keep severity, observed
exploitability, EPSS, KEV and environment context visible separately; do not label
their arithmetic combination a calibrated risk probability.

## 5. Primary references

Research basis checked 2026-10-24; adapter versions and API compatibility still
require validation when implementation starts.

- [Schemathesis](https://schemathesis.readthedocs.io/en/stable/) — schema-derived and stateful API testing.
- [mitmproxy protocol limitations](https://docs.mitmproxy.org/stable/concepts/protocols/) — optional capture; WebSocket replay and HTTP/3 client replay are not assumed available.
- [Doyensec CSPT research](https://blog.doyensec.com/2024/07/02/cspt2csrf.html).
- [elttam ORM/filter research](https://www.elttam.com/blog/leaking-more-than-you-joined-for).
- [PortSwigger race-condition research](https://portswigger.net/research/smashing-the-state-machine).
- [WebSocket security testing](https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking).
- [PyRIT](https://github.com/microsoft/PyRIT), [Promptfoo MCP testing](https://www.promptfoo.dev/docs/red-team/mcp-security-testing/), [MCP security guidance (draft)](https://modelcontextprotocol.io/docs/draft/tutorials/security/security_best_practices).
- [Prowler](https://github.com/prowler-cloud/prowler), [Stratus sandbox guidance](https://stratus-red-team.cloud/user-guide/getting-started/).
- [Trivy](https://github.com/aquasecurity/trivy), [OSV-Scanner](https://google.github.io/osv-scanner/usage/).
- [Attack Flow dependencies](https://center-for-threat-informed-defense.github.io/attack-flow/introduction/), [OpenTelemetry concepts](https://opentelemetry.io/docs/concepts/).
- [FIRST EPSS guidance](https://www.first.org/epss/faq).
- [HTTP Terminator research](https://portswigger.net/research/can-ai-do-novel-security-research), [Flowise application-security research](https://www.elttam.com/blog/cruising-for-shells-in-flowise).

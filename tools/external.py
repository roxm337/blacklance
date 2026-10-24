"""Wrappers for optional external pentest tools."""

import asyncio
import base64
import json
import os
import shlex
import re
import signal
import shutil
import subprocess
import uuid
from pathlib import Path
from urllib.parse import parse_qsl, urlparse
from typing import List, Optional

from core.deadline import clamp_timeout as _clamp_timeout
from core.deadline import deadline_reached as _deadline_reached
from core.validators import redact_for_log


# ── Tool backend: local binaries or the docker toolchain image ──────
#
# Default is local (zero behavior change). With tools.backend=docker
# (config `tools:` section or OSINT_TOOLS_BACKEND=docker), every binary
# in DOCKER_TOOLS runs inside the image instead: `docker run --rm`
# with the repo root mounted at /work, so file outputs land back in
# reports/ exactly like a local run. Teammates then need only Python
# and Docker — never the toolchain itself.

DOCKER_TOOLS = frozenset({
    "nmap", "naabu", "masscan", "nuclei", "ffuf", "httpx",
    "subfinder", "amass", "dnsx", "gau", "katana",
    "searchsploit", "trufflehog", "testssl.sh", "wpscan",
    "nikto", "whatweb", "gobuster", "feroxbuster",
    "hakrawler", "arjun", "gowitness",
    "dalfox", "sqlmap", "corsy", "smuggler", "openredirex",
    "theHarvester", "maigret", "cmseek", "joomscan", "paramspider",
    "subzy", "assetfinder", "waybackurls", "dig", "whois",
    "jsluice", "gxss", "uro", "gitleaks", "graphql-cop",
    "interactsh-client", "kr", "semgrep",
})

_BACKEND = {
    "mode": "local",
    "image": "osint-tools:latest",
    "network": "bridge",
    "memory": "2g",
    "cpus": "2",
    "pids_limit": 512,
}
_DOCKER_OK: bool | None = None
_TOOL_BUDGET = None

_RAW_SOCKET_TOOLS = frozenset({"nmap", "naabu", "masscan"})


def configure_tool_budget(budget=None) -> None:
    """Attach the engagement budget to external process launches."""
    global _TOOL_BUDGET
    _TOOL_BUDGET = budget


def consume_tool_budget() -> None:
    if _TOOL_BUDGET is not None:
        _TOOL_BUDGET.consume_external_command()


async def terminate_process_tree(proc) -> None:
    """Terminate a timed-out tool and any children it spawned."""
    try:
        if os.name != "nt" and getattr(proc, "pid", None):
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            proc.kill()
    except (ProcessLookupError, PermissionError, AttributeError):
        try:
            proc.kill()
        except Exception:
            return
    try:
        await asyncio.wait_for(proc.wait(), 10)
    except Exception:
        pass


def managed_container(command) -> str:
    try:
        parts = shlex.split(command) if isinstance(command, str) else list(command)
    except ValueError:
        return ""
    for index, part in enumerate(parts[:-1]):
        if part == "--name" and re.fullmatch(r"osint-tool-[a-f0-9]{32}", str(parts[index + 1])):
            return parts[index + 1]
    return ""


async def terminate_tool(proc, command) -> None:
    """Reap local children and remove only the uniquely named container we own."""
    await terminate_process_tree(proc)
    name = managed_container(command)
    if not name:
        return
    cleanup = None
    try:
        cleanup = await asyncio.create_subprocess_exec(
            "docker", "rm", "--force", name,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=os.name != "nt")
        await asyncio.wait_for(cleanup.wait(), 5)
    except (OSError, asyncio.TimeoutError):
        if cleanup is not None:
            await terminate_process_tree(cleanup)


def configure_tool_backend(config: dict | None = None) -> str:
    """Select the tool backend from config, env wins. Returns the mode."""
    global _DOCKER_OK
    tools_cfg = (config or {}).get("tools", {}) or {}
    mode = str(os.environ.get("OSINT_TOOLS_BACKEND", "")
               or tools_cfg.get("backend", "local")).strip().lower()
    image = str(os.environ.get("OSINT_TOOLS_IMAGE", "")
                or tools_cfg.get("image", "osint-tools:latest")).strip()
    network = str(tools_cfg.get("network", "bridge") or "bridge").strip()
    memory = str(tools_cfg.get("memory", "2g") or "2g").strip().lower()
    cpus = str(tools_cfg.get("cpus", "2") or "2").strip()
    try:
        pids_limit = max(32, min(4096, int(
            tools_cfg.get("pids_limit", 512) or 512)))
    except (TypeError, ValueError):
        pids_limit = 512
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", network):
        network = "bridge"
    if not re.fullmatch(r"[1-9][0-9]*(?:[bkmg])?", memory):
        memory = "2g"
    try:
        cpus = str(max(0.1, min(64.0, float(cpus))))
    except ValueError:
        cpus = "2"
    resolved_mode = mode if mode in ("local", "docker") else "local"
    resolved_image = image or "osint-tools:latest"
    # Only invalidate the docker-readiness probe when the backend actually
    # changes. This function is called from every BaseModule.__init__ (once
    # per module), and resetting the cache each time re-ran `docker image
    # inspect` 57 times a run — any one slow or transient failure cached
    # "unreachable", so a docker tool that preflight proved present reported
    # "not installed" for the rest of the run. Stable config → one probe.
    if resolved_mode != _BACKEND["mode"] or resolved_image != _BACKEND["image"]:
        _DOCKER_OK = None
    _BACKEND["mode"] = resolved_mode
    _BACKEND["image"] = resolved_image
    _BACKEND["network"] = network
    _BACKEND["memory"] = memory
    _BACKEND["cpus"] = cpus
    _BACKEND["pids_limit"] = pids_limit
    return _BACKEND["mode"]


def tool_backend() -> str:
    """Current backend mode ("local" unless configured otherwise)."""
    return _BACKEND["mode"]


def _docker_ready() -> bool:
    """The image resolves locally. Cached per process; restart to re-check.

    Tries the configured reference, then the fully-qualified
    docker.io/library/ form: some Docker Desktop releases resolve short
    names for run/pull but not for `image inspect`, so the short form
    alone reports a present image as missing.
    """
    global _DOCKER_OK
    if _DOCKER_OK is not None:
        return _DOCKER_OK
    image = _BACKEND["image"]
    candidates = [image]
    if "/" not in image:
        candidates.append(f"docker.io/library/{image}")
    try:
        for candidate in candidates:
            proc = subprocess.run(
                ["docker", "image", "inspect", candidate],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=15,
            )
            if proc.returncode == 0:
                _DOCKER_OK = True
                return True
        listed = subprocess.run(
            ["docker", "images", "-q", image],
            capture_output=True, text=True, timeout=15,
        )
        _DOCKER_OK = bool(listed.stdout.strip())
    except Exception:
        _DOCKER_OK = False
    return _DOCKER_OK


def _docker_wants(args: List[str]) -> bool:
    return (_BACKEND["mode"] == "docker" and bool(args)
            and str(args[0]) in DOCKER_TOOLS and _docker_ready())


def _rewrite_arg(arg: str, cwd: str) -> str:
    """Map a host path under the repo root to its /work twin inside."""
    if not arg or arg.startswith("-") or "://" in arg:
        return arg
    if "/" not in arg:
        # Bare tokens are not paths: the binary name itself, keywords
        # (FUZZ), counts, modes. The old parent-exists heuristic rewrote
        # every one of these (parent == cwd always exists), turning
        # `openredirex -k FUZZ` into `/work/openredirex -k /work/FUZZ`
        # and every docker-routed call into exit 127. The container cwd
        # is /work, so a bare filename resolves identically either way.
        return arg
    try:
        path = Path(arg)
        if not path.is_absolute():
            candidate = Path(cwd) / arg
            try:
                rel = candidate.relative_to(cwd)
            except ValueError:
                return arg
            # Output files (ffuf -o, arjun -oJ) do not exist yet: rewrite
            # when the parent does, or the container writes into its own
            # filesystem and the host parses a stale/empty file.
            if candidate.exists() or candidate.parent.exists():
                return f"/work/{rel.as_posix()}"
            return arg
        try:
            return f"/work/{path.relative_to(cwd).as_posix()}"
        except ValueError:
            return arg
    except Exception:
        return arg


def docker_run_args(args: List[str], stdin: bool = False) -> List[str]:
    """Wrap a tool invocation for the container. Pure function (testable)."""
    cwd = os.getcwd()
    cmd = ["docker", "run", "--rm"]
    if stdin:
        cmd.append("-i")
    cmd += ["--name", f"osint-tool-{uuid.uuid4().hex}"]
    cmd += _docker_policy_args(str(args[0]) if args else "")
    # argv form (no shell): the space in the path is safe as one element.
    cmd += ["-v", f"{cwd}:/work", "-w", "/work", _BACKEND["image"]]
    return cmd + [_rewrite_arg(str(a), cwd) for a in args]


def _docker_policy_args(tool: str = "") -> List[str]:
    args = [
        "--security-opt", "no-new-privileges:true",
        "--cap-drop", "ALL",
        "--pids-limit", str(_BACKEND["pids_limit"]),
        "--memory", str(_BACKEND["memory"]),
        "--cpus", str(_BACKEND["cpus"]),
        "--network", str(_BACKEND["network"]),
    ]
    if tool in _RAW_SOCKET_TOOLS:
        args += ["--cap-add", "NET_RAW", "--cap-add", "NET_ADMIN"]
    return args


def _shell_tool(command: str) -> str:
    """Which baked binary a shell one-liner actually invokes, if any."""
    padded = f" {command} "
    for tool in DOCKER_TOOLS:
        if (padded.startswith(f" {tool} ")
                or f"| {tool} " in padded
                or f"|| {tool} " in padded):
            return tool
    return ""


def docker_wrap_shell(command: str) -> str:
    """Wrap a shell one-liner for the container (wrappers.py helpers).

    Local mode returns the command untouched. Docker mode base64s it
    through stdin so no quoting layer can corrupt pipes, quotes, or
    redirects — the container shell receives the exact bytes.
    """
    if _BACKEND["mode"] != "docker" or not _docker_ready():
        return command
    if not _shell_tool(command):
        return command
    encoded = base64.b64encode(command.encode()).decode()
    cwd = os.getcwd()
    # Host paths under the repo root mean /work paths inside.
    pinned = command.replace(cwd, "/work")
    if pinned != command:
        encoded = base64.b64encode(pinned.encode()).decode()
    # shlex.quote: repo paths routinely contain spaces.
    volume = shlex.quote(f"{cwd}:/work")
    tool = _shell_tool(command)
    policy = " ".join(shlex.quote(part) for part in _docker_policy_args(tool))
    image = shlex.quote(str(_BACKEND["image"]))
    return (f"printf %s {encoded} | base64 -d | docker run --rm -i "
            f"--name osint-tool-{uuid.uuid4().hex} {policy} -v {volume} -w /work {image} sh")


def tool_available(name: str) -> bool:
    if _BACKEND["mode"] == "docker" and name in DOCKER_TOOLS:
        return _docker_ready()
    return shutil.which(name) is not None


def tools_available() -> dict:
    """Return availability status of all known external tools."""
    tools = [
        "nmap", "naabu", "masscan", "nuclei", "ffuf", "httpx",
        "subfinder", "amass", "dnsx", "gau", "katana",
        "searchsploit", "trufflehog", "testssl.sh", "wpscan",
        "nikto", "whatweb", "gobuster", "feroxbuster",
        "hakrawler", "arjun", "paramspider", "gowitness",
        "dalfox", "sqlmap", "corsy", "smuggler", "openredirex",
        "kr", "semgrep",
    ]
    return {t: tool_available(t) for t in tools}

async def run_command(args: List[str], timeout: int = 120,
                      stdin_data: str = "") -> dict:
    """Run a command without shell interpolation.

    Docker backend: tool binaries run inside the toolchain image with
    the repo mounted at /work, so outputs land back in reports/.
    """
    # Past the module deadline, do not launch a tool that would run its own
    # (often multi-minute) timeout straight through the orchestrator's
    # guillotine. Return the empty result the callers already handle.
    if _deadline_reached():
        return {"stdout": "", "stderr": "", "exit_code": -1,
                "error": "deadline_exceeded"}
    timeout = _clamp_timeout(timeout)
    consume_tool_budget()
    if _docker_wants(args):
        args = docker_run_args(args, stdin=bool(stdin_data))
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE if stdin_data else None,
            start_new_session=os.name != "nt",
        )
        stdin_bytes = stdin_data.encode() if stdin_data else None
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input=stdin_bytes), timeout
        )
        return {
            "stdout": stdout.decode("utf-8", errors="replace"),
            "stderr": stderr.decode("utf-8", errors="replace"),
            "exit_code": proc.returncode or 0,
            "error": None,
        }
    except asyncio.TimeoutError:
        await terminate_tool(proc, args)
        return {"stdout": "", "stderr": "timeout", "exit_code": -1, "error": "timeout"}
    except asyncio.CancelledError:
        if "proc" in locals():
            await asyncio.shield(terminate_tool(proc, args))
        raise
    except Exception as exc:
        return {"stdout": "", "stderr": str(exc), "exit_code": -1, "error": str(exc)}


def parse_searchsploit_json(text: str, limit: int = 20) -> List[dict]:
    try:
        data = json.loads(text or "{}")
    except json.JSONDecodeError:
        return []

    results = data.get("RESULTS_EXPLOIT", [])
    parsed = []
    for item in results[:limit]:
        parsed.append({
            "title": item.get("Title", ""),
            "edb_id": str(item.get("EDB-ID", "")),
            "date": item.get("Date", ""),
            "author": item.get("Author", ""),
            "type": item.get("Type", ""),
            "platform": item.get("Platform", ""),
            "path": item.get("Path", ""),
        })
    return parsed


async def searchsploit(term: str, limit: int = 20) -> dict:
    if not tool_available("searchsploit"):
        return {"available": False, "term": term, "results": [], "error": "missing"}

    result = await run_command(["searchsploit", "--json", term], timeout=60)
    return {
        "available": True,
        "term": term,
        "results": parse_searchsploit_json(result["stdout"], limit=limit),
        "raw": result["stdout"][:10000],
        "stderr": result["stderr"][:2000],
        "exit_code": result["exit_code"],
        "error": result.get("error"),
    }


def parse_ffuf_json(text: str) -> List[dict]:
    try:
        data = json.loads(text or "{}")
    except json.JSONDecodeError:
        return []

    parsed = []
    for item in data.get("results", []):
        parsed.append({
            "url": item.get("url", ""),
            "status": item.get("status", 0),
            "length": item.get("length", 0),
            "words": item.get("words", 0),
            "lines": item.get("lines", 0),
            "content_type": item.get("content-type", ""),
            "redirectlocation": item.get("redirectlocation", ""),
            "duration": item.get("duration", 0),
        })
    return parsed


def parse_nuclei_jsonl(text: str) -> List[dict]:
    parsed = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = item.get("info") or {}
        parsed.append({
            "template_id": item.get("template-id", ""),
            "name": info.get("name", ""),
            "severity": str(info.get("severity", "info")).upper(),
            "type": item.get("type", ""),
            "matched_at": item.get("matched-at", item.get("host", "")),
            "matcher_name": item.get("matcher-name", ""),
            "extracted_results": item.get("extracted-results", []),
            "tags": info.get("tags", []),
            "reference": info.get("reference", []),
            "curl_command": item.get("curl-command", ""),
            "ip": item.get("ip", ""),
        })
    return parsed


async def ffuf(url_template: str, wordlist: str, output_file: str,
               rate: Optional[int] = None,
               timeout: int = 240,
               extra_args: Optional[List[str]] = None) -> dict:
    if not tool_available("ffuf"):
        return {"available": False, "results": [], "error": "missing"}

    args = [
        "ffuf",
        "-u", url_template,
        "-w", wordlist,
        "-of", "json",
        "-o", output_file,
        "-mc", "200,204,301,302,307,308,401,403,405",
        "-t", "20",
        "-timeout", "8",
        "-s",
        "-fc", "404",
    ]
    if rate:
        args.extend(["-rate", str(rate)])
    if extra_args:
        args.extend(extra_args)

    result = await run_command(args, timeout=timeout)
    return {
        "available": True,
        "stdout": result["stdout"][:5000],
        "stderr": result["stderr"][:5000],
        "exit_code": result["exit_code"],
        "error": result.get("error"),
    }


async def nuclei_templates_info() -> dict:
    """Where the templates live and how stale they are.

    No git metadata survives in the image (and host checkouts often
    lack it too), so directory mtime is the freshness signal. Runs on
    whichever side the backend selects — GNU stat in the container,
    BSD stat on a macOS host — trying each in turn.
    """
    if not tool_available("nuclei"):
        return {"available": False, "dir": "", "age_days": None,
                "templates": 0}
    from tools.wrappers import bash as _bash
    probe = (
        "for d in \"$NUCLEI_TEMPLATES_DIR\" \"$HOME/nuclei-templates\" "
        "\"$HOME/.local/nuclei-templates\"; do "
        "[ -d \"$d\" ] || continue; "
        "mt=$(stat -c %Y \"$d\" 2>/dev/null || stat -f %m \"$d\" 2>/dev/null); "
        "n=$(find \"$d\" -name '*.yaml' 2>/dev/null | wc -l); "
        "echo \"$mt|$d|$n\"; break; done"
    )
    stdout = ""
    try:
        # stat/find are not baked binaries, so the shell helper would
        # run them on the host even in docker mode. Route explicitly,
        # mirroring the interactsh session spawn below.
        import asyncio as _asyncio
        if _BACKEND["mode"] == "docker" and _docker_ready():
            proc = await _asyncio.create_subprocess_exec(
                *docker_run_args(["sh", "-c", probe]),
                stdout=_asyncio.subprocess.PIPE,
                stderr=_asyncio.subprocess.STDOUT,
            )
            out, _ = await _asyncio.wait_for(proc.communicate(), 60)
            stdout = out.decode("utf-8", errors="replace")
        else:
            result = await _bash(probe)
            stdout = str(result.get("stdout", "") or "")
    except Exception as exc:
        return {"available": False, "dir": "", "age_days": None,
                "templates": 0, "error": str(exc)[:200]}
    import time as _time
    for line in stdout.splitlines():
        parts = line.strip().split("|")
        if len(parts) != 3:
            continue
        try:
            mtime = int(parts[0])
            count = int(parts[2])
        except (TypeError, ValueError):
            continue
        age = max(0.0, (_time.time() - mtime) / 86400.0)
        return {"available": True, "dir": parts[1],
                "age_days": round(age, 1), "templates": count}
    return {"available": True, "dir": "", "age_days": None, "templates": 0,
            "error": "no template directory found"}


async def nuclei_update_templates(timeout: int = 600) -> dict:
    """Refresh templates explicitly (`nuclei -update-templates`).

    Scans pass -duc precisely because an implicit update burns minutes
    on a cold run, so refresh is a separate, operator-approved step —
    never a side effect of scanning.
    """
    if not tool_available("nuclei"):
        return {"available": False, "error": "missing"}
    result = await run_command(
        ["nuclei", "-update-templates", "-silent"], timeout=timeout)
    return {
        "available": True,
        "exit_code": result.get("exit_code"),
        "error": result.get("error"),
        "tail": (result.get("stdout", "") or "")[-2000:],
    }


async def nuclei_scan(target_url: str,
                      rate_limit: int = 10,
                      timeout: int = 600,
                      tags: Optional[List[str]] = None,
                      severity: Optional[List[str]] = None,
                      templates: Optional[str] = None,
                      ids: Optional[List[str]] = None) -> dict:
    if not tool_available("nuclei"):
        return {"available": False, "results": [], "error": "missing"}

    args = [
        "nuclei",
        "-u", target_url,
        "-jsonl",
        "-silent",
        "-no-color",
        "-duc",  # skip the template update check: on a cold run it burns
        # minutes of wall clock before any template runs
        "-rate-limit", str(rate_limit),
        "-timeout", "8",
        "-retries", "2",
        "-stats",
    ]
    if tags:
        args.extend(["-tags", ",".join(tags)])
    if severity:
        args.extend(["-severity", ",".join(severity)])
    if templates:
        args.extend(["-t", templates])
    if ids:
        # `-id` is the documented selector for template IDs (CVE-2026-…);
        # `-t` expects a path and only sometimes resolves an id.
        args.extend(["-id", ",".join(ids)])

    result = await run_command(args, timeout=timeout)
    return {
        "available": True,
        "results": parse_nuclei_jsonl(result["stdout"]),
        "raw": result["stdout"][:50000],
        "stderr": result["stderr"][:5000],
        "exit_code": result["exit_code"],
        "error": result.get("error"),
    }


async def nuclei_multi(targets: list,
                       rate_limit: int = 10,
                       timeout: int = 600,
                       tags: Optional[List[str]] = None,
                       severity: Optional[List[str]] = None) -> dict:
    """Run nuclei against multiple targets."""
    if not tool_available("nuclei"):
        return {"available": False, "results": [], "error": "missing"}

    targets_input = "\n".join(targets)
    args = [
        "nuclei",
        "-jsonl", "-silent", "-no-color",
        "-duc",  # skip the template update check (see nuclei_scan)
        "-rate-limit", str(rate_limit),
        "-timeout", "8",
        "-retries", "2",
    ]
    if tags:
        args.extend(["-tags", ",".join(tags)])
    if severity:
        args.extend(["-severity", ",".join(severity)])

    result = await run_command(args, timeout=timeout, stdin_data=targets_input)
    return {
        "available": True,
        "results": parse_nuclei_jsonl(result["stdout"]),
        "exit_code": result["exit_code"],
        "error": result.get("error"),
    }


async def httpx_probe(targets: list,
                      timeout: int = 10,
                      follow_redirects: bool = True) -> List[dict]:
    """Probe HTTP services with httpx for status, title, tech."""
    if not tool_available("httpx"):
        return []

    targets_input = "\n".join(targets)
    args = [
        "httpx",
        "-silent",
        "-status-code",
        "-title",
        "-tech-detect",
        "-web-server",
        "-json",
        "-follow-redirects" if follow_redirects else "",
        "-timeout", str(timeout),
        "-threads", "20",
    ]
    args = [a for a in args if a]

    result = await run_command(args, timeout=120, stdin_data=targets_input)
    probed = []
    for line in result["stdout"].strip().split("\n"):
        if not line.strip():
            continue
        try:
            probed.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return probed


async def katana_crawl(target: str,
                       depth: int = 2,
                       timeout: int = 120) -> List[str]:
    """Crawl a target with katana to find URLs."""
    if not tool_available("katana"):
        return []

    args = [
        "katana",
        "-u", target,
        "-d", str(depth),
        "-silent",
        "-jc",
        "-timeout", "5",
    ]
    result = await run_command(args, timeout=timeout)
    return [u.strip() for u in result["stdout"].split("\n") if u.strip()]


async def hakrawler_crawl(target: str,
                          depth: int = 2,
                          timeout: int = 120) -> List[str]:
    """Crawl a target with hakrawler to find URLs."""
    if not tool_available("hakrawler"):
        return []

    args = ["hakrawler", "-d", str(depth), "-subs"]
    result = await run_command(args, timeout=timeout, stdin_data=target)
    return [u.strip() for u in result["stdout"].split("\n") if u.strip()]


def extract_parameters_from_urls(urls: List[str]) -> List[dict]:
    """Extract query parameters from URLs into stable structured records."""
    records = {}
    for url in urls:
        parsed = urlparse(url)
        if not parsed.query:
            continue
        base = parsed._replace(query="", fragment="").geturl()
        for name, value in parse_qsl(parsed.query, keep_blank_values=True):
            key = (base, name)
            item = records.setdefault(
                key,
                {
                    "url": base,
                    "parameter": name,
                    "example_value": value,
                    "sources": [],
                },
            )
            if url not in item["sources"] and len(item["sources"]) < 5:
                item["sources"].append(url)
    return list(records.values())


def parse_arjun_json(text: str) -> List[dict]:
    """Parse common Arjun JSON outputs."""
    try:
        data = json.loads(text or "{}")
    except json.JSONDecodeError:
        return []

    parsed = []
    if isinstance(data, dict):
        for url, params in data.items():
            if isinstance(params, dict):
                params = params.get("params", params.get("parameters", []))
            for param in params or []:
                parsed.append({"url": url, "parameter": str(param), "source": "arjun"})
    elif isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            url = item.get("url", "")
            for param in item.get("params", item.get("parameters", [])) or []:
                parsed.append({"url": url, "parameter": str(param), "source": "arjun"})
    return parsed


async def arjun_scan(target: str, output_file: str,
                     timeout: int = 240) -> dict:
    """Run Arjun hidden parameter discovery."""
    if not tool_available("arjun"):
        return {"available": False, "results": [], "error": "missing"}

    args = ["arjun", "-u", target, "-oJ", output_file, "--stable"]
    result = await run_command(args, timeout=timeout)
    output_text = Path(output_file).read_text() if Path(output_file).exists() else result["stdout"]
    return {
        "available": True,
        "results": parse_arjun_json(output_text),
        "stdout": result["stdout"][:5000],
        "stderr": result["stderr"][:5000],
        "exit_code": result["exit_code"],
        "error": result.get("error"),
    }


async def paramspider_scan(domain: str, timeout: int = 180) -> dict:
    """Run ParamSpider for archived parameterized URLs.

    Real CLI (devanshbatham package): -d domain, -s streams URLs to
    stdout; there is NO --exclude flag (extensions are hardcoded
    upstream) — passing one aborts with exit 2. results/<domain>.txt
    also lands in the working dir, so it is read when present and
    removed to avoid littering the repo.
    """
    if not tool_available("paramspider"):
        return {"available": False, "urls": [], "error": "missing"}

    result = await run_command(
        ["paramspider", "-d", domain, "-s"],
        timeout=timeout,
    )
    urls = [line.strip() for line in result["stdout"].splitlines() if line.startswith("http")]
    leftover = Path("results") / f"{domain}.txt"
    try:
        if leftover.exists():
            urls.extend(line.strip() for line in leftover.read_text().splitlines()
                        if line.strip().startswith("http"))
            leftover.unlink()
    except OSError:
        pass
    urls = list(dict.fromkeys(urls))
    return {
        "available": True,
        "urls": urls,
        "parameters": extract_parameters_from_urls(urls),
        "stderr": result["stderr"][:5000],
        "exit_code": result["exit_code"],
        "error": result.get("error"),
    }


async def gowitness_scan(targets: List[str], output_dir: str,
                         timeout: int = 300) -> dict:
    """Run gowitness screenshots against a list of URLs."""
    if not tool_available("gowitness"):
        return {"available": False, "screenshots": [], "error": "missing"}

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    args = ["gowitness", "scan", "file", "-", "--screenshot-path", output_dir, "--write-jsonl"]
    result = await run_command(args, timeout=timeout, stdin_data="\n".join(targets))
    screenshots = []
    for line in result["stdout"].splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        screenshots.append(item)
    return {
        "available": True,
        "screenshots": screenshots,
        "output_dir": output_dir,
        "stdout": result["stdout"][:10000],
        "stderr": result["stderr"][:5000],
        "exit_code": result["exit_code"],
        "error": result.get("error"),
    }


def parse_dalfox_jsonl(text: str) -> List[dict]:
    """Parse Dalfox JSONL output (v3 shape, v2 tolerant).

    v3 finding lines carry `type` (V/A/R/I tier), `type_description`,
    `inject_type` and the PoC; v2 lines carried `data`/`poc`. Field
    fallbacks keep both readable — a finding is kept when any of its
    URL-carrying fields is present.
    """
    findings = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict):
            continue
        url = (item.get("url") or item.get("data") or item.get("target")
               or item.get("poc_url") or item.get("poc") or "")
        if not url:
            # Tier-only lines (blind-session banners, summaries) carry no
            # URL to attribute: keeping them mints findings with empty
            # URLs that no module can triage or reproduce.
            continue
        findings.append({
            "type": item.get("type", item.get("poc_type", "")),
            "url": url,
            "payload": item.get("payload", item.get("poc", "")),
            "evidence": (item.get("evidence") or item.get("poc")
                         or item.get("type_description", "")),
            # v3 tier context, empty on v2 lines: V = exploitable,
            # A = AST-detected, R = reflected, I = informational.
            "inject_type": item.get("inject_type", ""),
            "method": item.get("method", ""),
        })
    return findings


async def dalfox_scan(urls: List[str], timeout: int = 600,
                      blind: Optional[str] = None,
                      blind_oob: bool = False,
                      rate_limit: int = 0) -> dict:
    """Run Dalfox v3 in conservative pipe mode.

    v3 notes: `pipe` stays as a legacy alias for `scan -i pipe`;
    line-delimited output is `-f jsonl` now (plain `json` emits one
    document); `--skip-bav` is gone (the V/A/R/I tiers replaced it —
    `--only-poc v` keeps the exploitable tier); exit 1 means findings,
    which is normal and not an error here.

    `blind` is an out-of-band callback URL (interactsh): dalfox injects
    blind payloads that phone home, and a callback is execution proof
    for stored/blind contexts the response scan cannot see. `blind_oob`
    instead lets dalfox run its own interactsh session (`--blind-oob`,
    public mesh) — no framework callback to poll, so those findings
    stay FIRM: dalfox saw the callback, we did not.
    """
    if not tool_available("dalfox"):
        return {"available": False, "results": [], "error": "missing"}

    args = [
        "dalfox", "pipe",
        "-S",
        "-f", "jsonl",
        "--only-poc", "v",
    ]
    if blind:
        args.extend(["--blind", blind])
    if blind_oob:
        args.append("--blind-oob")
    if rate_limit and int(rate_limit) > 0:
        args.extend(["--rate-limit", str(int(rate_limit))])
    result = await run_command(args, timeout=timeout, stdin_data="\n".join(urls))
    return {
        "available": True,
        "results": parse_dalfox_jsonl(result["stdout"]),
        "stdout": result["stdout"][:20000],
        "stderr": result["stderr"][:5000],
        "exit_code": result["exit_code"],
        "error": result.get("error"),
    }


def parse_kiterunner_json(text: str) -> List[dict]:
    """Parse `kr brute/scan -o json` hit lines.

    Hits look like
    `{"method":"GET","target":"https://h","path":"/api",
    "responses":[{"uri":"","sc":200,"len":123}]}`; log lines carry
    `"level"` instead of `"responses"` and are skipped. Only the
    first response per path is kept — one path, one verdict.
    """
    hits = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict) or "responses" not in item:
            continue
        responses = item.get("responses") or []
        first = responses[0] if responses else {}
        if not isinstance(first, dict):
            first = {}
        target = str(item.get("target", "") or "").rstrip("/")
        path = str(item.get("path", "") or "")
        if not target or not path:
            continue
        hits.append({
            "url": target + (path if path.startswith("/") else f"/{path}"),
            "method": str(item.get("method", "GET") or "GET"),
            "status": _safe_int(first.get("sc")),
            "length": _safe_int(first.get("len")),
        })
    return hits


def _safe_int(value: object) -> int:
    """int() that survives '200 OK' strings, None, and floats."""
    try:
        return int(str(value).strip().split()[0])
    except (ValueError, TypeError, IndexError):
        return 0


async def kiterunner_scan(targets: List[str], timeout: int = 900,
                          wordlist: str = "apiroutes-260227",
                          max_routes: int = 1500,
                          fail_codes: str = "400,401,403,404,426,411",
                          delay_ms: int = 100,
                          connections: int = 3) -> dict:
    """Brute-force API routes with kiterunner (assetnote wordlists).

    `kr brute <target> -A=<wordlist>:<N> -o json`: the wordlist
    downloads from wordlist.assetnote.io at scan time, so nothing is
    baked into the image. Bounded by max_routes per target; `--delay`
    keeps the request rate polite. One invocation per target so a
    slow host cannot starve the rest.
    """
    if not tool_available("kr"):
        return {"available": False, "results": [], "error": "missing"}
    try:
        max_routes = max(1, min(20000, int(max_routes)))
    except (TypeError, ValueError):
        max_routes = 1500
    try:
        connections = max(1, min(10, int(connections)))
    except (TypeError, ValueError):
        connections = 3
    hits: List[dict] = []
    exit_codes: List[int] = []
    errors: List[str] = []
    for target in targets:
        args = [
            "kr", "brute", target,
            "-A", f"{wordlist}:{max_routes}",
            "-o", "json",
            "-q", "--progress=false",
            "-x", str(connections),
            "-j", "1",
            "--delay", f"{max(0, int(delay_ms or 0))}ms",
            "-t", "10s",
        ]
        if fail_codes:
            args.extend(["--fail-status-codes", str(fail_codes)])
        result = await run_command(args, timeout=timeout)
        exit_codes.append(int(result.get("exit_code") or 0))
        if result.get("error"):
            errors.append(str(result["error"])[:200])
        hits.extend(parse_kiterunner_json(result.get("stdout", "")))
    return {
        "available": True,
        "results": hits,
        "targets": list(targets),
        "wordlist": wordlist,
        "max_routes": max_routes,
        "exit_codes": exit_codes,
        "error": "; ".join(errors) or None,
    }


def parse_sqlmap_text(text: str) -> List[dict]:
    """Extract high-signal SQLMap vulnerability lines.

    Each finding keeps the target URL so a caller can attribute an out-of-band
    confirmation to the one request that produced it. sqlmap prints the URL on
    the connection line, so that is where it is recovered from.

    Only lines that *assert* an injection count. The old rule was "the line
    mentions a GET or POST parameter", which is every other line sqlmap
    prints: `testing if GET parameter 'to' is dynamic`,
    `GET parameter 'to' does not appear to be dynamic`, `skipping GET
    parameter 'to'` each became a CRITICAL finding. Four of them came out of
    one run against a parameter sqlmap had rejected outright, reported as
    FIRM evidence of SQL injection. The verdict words are the test.
    """
    positives = ("is vulnerable", "is injectable", "appears to be injectable",
                 "injection point", "injection was found")
    negations = ("not injectable", "might not", "does not appear",
                 "is not dynamic", "does not seem", "skipping")
    findings = []
    current_url = ""
    marker = "testing connection to the target URL:"
    for line in (text or "").splitlines():
        stripped = line.strip()
        if marker in stripped:
            # Split on the marker, not on the first colon: the line starts with
            # a "[HH:MM:SS]" timestamp that would otherwise become the URL.
            _, _, tail = stripped.partition(marker)
            current_url = tail.strip() or current_url
        low = stripped.lower()
        if not any(what in low for what in positives):
            continue
        if any(what in low for what in negations):
            continue
        findings.append({"url": current_url, "evidence": stripped})
    return findings


# sqlmap reports an out-of-band confirmation on its own terms. Blind payloads
# never touch the response, so without this a real finding is stuck at FIRM.
_OAST_MARKERS = (
    "oast",
    "interactsh",
    "out-of-band",
    "out of band",
    "dns exfiltration",
    "parameter is injectable",
)


def _has_oast(text: str) -> bool:
    low = (text or "").lower()
    return any(marker in low for marker in _OAST_MARKERS)


async def sqlmap_scan(url: str, timeout: int = 900,
                      interactsh_url: str = "",
                      risk: int = 1, level: int = 1,
                      cookie: str = "", headers: str = "") -> dict:
    """Run sqlmap with caller-chosen risk/level and optional auth.

    `interactsh_url` turns on sqlmap's own out-of-band mode, which is the only
    way a blind injection gets proof: an in-band response looks identical
    whether or not the query executed. Left empty, nothing changes.
    `cookie`/`headers` carry an authorized session so authenticated
    endpoints are tested as the user, not as anonymous.
    """
    if not tool_available("sqlmap"):
        return {"available": False, "results": [], "error": "missing"}
    try:
        risk = max(1, min(3, int(risk)))
    except (TypeError, ValueError):
        risk = 1
    try:
        level = max(1, min(5, int(level)))
    except (TypeError, ValueError):
        level = 1

    args = [
        "sqlmap", "-u", url,
        "--batch",
        "--risk", str(risk),
        "--level", str(level),
        "--threads", "1",
        "--smart",
        "--flush-session",
    ]
    if interactsh_url:
        args += ["--oast", "--interactsh-url", interactsh_url]
    if cookie:
        args += ["--cookie", cookie]
    if headers:
        args += ["--headers", headers]
    result = await run_command(args, timeout=timeout)
    oast = _has_oast(result["stdout"]) or _has_oast(result["stderr"])
    return {
        "available": True,
        "results": parse_sqlmap_text(result["stdout"]),
        # Session credentials ride on argv (--cookie/--headers) and sqlmap
        # echoes its config: scrub persisted output, never the parse.
        "stdout": redact_for_log(result["stdout"][:20000]),
        "stderr": redact_for_log(result["stderr"][:5000]),
        "exit_code": result["exit_code"],
        "oast": oast,
        "error": result.get("error"),
    }


def parse_corsy_json(text: str) -> List[dict]:
    try:
        data = json.loads(text or "[]")
    except json.JSONDecodeError:
        return []
    items = data if isinstance(data, list) else data.get("results", [])
    return [item for item in items if isinstance(item, dict)]


async def corsy_scan(target: str, timeout: int = 180) -> dict:
    """Run Corsy against a target URL."""
    if not tool_available("corsy"):
        return {"available": False, "results": [], "error": "missing"}
    result = await run_command(["corsy", "-u", target, "-j"], timeout=timeout)
    return {
        "available": True,
        "results": parse_corsy_json(result["stdout"]),
        "stdout": result["stdout"][:10000],
        "stderr": result["stderr"][:5000],
        "exit_code": result["exit_code"],
        "error": result.get("error"),
    }


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _parse_openredirex_hits(stdout: str) -> list:
    """[FOUND] lines, ANSI-stripped. The banner, progress bar, and [INFO]
    lines never qualify."""
    hits = []
    for line in stdout.splitlines():
        if "[FOUND]" in line:
            hits.append(_ANSI_RE.sub("", line).strip())
    return hits


async def openredirex_scan(urls: List[str], timeout: int = 300) -> dict:
    """Run openredirex against URL candidates (devanshbatham Python build:
    URLs on stdin, -k keyword swapped for payloads, hardcoded payload list
    unless -p is given — so -p is left off. Concurrency stays low: this is
    corroboration, not a fuzzing campaign)."""
    if not tool_available("openredirex"):
        return {"available": False, "results": [], "error": "missing"}
    result = await run_command(["openredirex", "-k", "FUZZ", "-c", "10"],
                               timeout=timeout, stdin_data="\n".join(urls))
    return {
        "available": True,
        "results": _parse_openredirex_hits(result["stdout"]),
        "stdout": result["stdout"][:20000],
        "stderr": result["stderr"][:5000],
        "exit_code": result["exit_code"],
        "error": result.get("error"),
    }


async def smuggler_scan(target: str, timeout: int = 300) -> dict:
    """Run smuggler against one URL."""
    if not tool_available("smuggler"):
        return {"available": False, "results": [], "error": "missing"}
    result = await run_command(["smuggler", "-u", target], timeout=timeout)
    hits = [
        line.strip() for line in result["stdout"].splitlines()
        if "potential" in line.lower() or "vulnerable" in line.lower()
    ]
    return {
        "available": True,
        "results": hits,
        "stdout": result["stdout"][:20000],
        "stderr": result["stderr"][:5000],
        "exit_code": result["exit_code"],
        "error": result.get("error"),
    }


async def maigret_scan(username: str, timeout: int = 240) -> dict:
    """Run maigret for username presence checks."""
    if not tool_available("maigret"):
        return {"available": False, "results": [], "error": "missing"}
    result = await run_command(
        ["maigret", username, "--json", "-", "--no-progressbar"],
        timeout=timeout,
    )
    return {
        "available": True,
        "results": parse_maigret_json(result["stdout"]),
        "stdout": result["stdout"][:20000],
        "stderr": result["stderr"][:5000],
        "exit_code": result["exit_code"],
        "error": result.get("error"),
    }


def parse_maigret_json(text: str) -> List[dict]:
    try:
        data = json.loads(text or "{}")
    except json.JSONDecodeError:
        return []
    results = []
    items = data.values() if isinstance(data, dict) else data
    for item in items:
        if not isinstance(item, dict):
            continue
        status = item.get("status", {})
        if isinstance(status, dict) and status.get("status") in ("Claimed", "Found"):
            results.append({
                "site": item.get("name", item.get("site_name", "")),
                "url": item.get("url_user", item.get("url", "")),
                "status": status.get("status"),
            })
    return results


async def holehe_scan(email: str, timeout: int = 180) -> dict:
    """Run holehe for account-registration checks."""
    if not tool_available("holehe"):
        return {"available": False, "results": [], "error": "missing"}
    result = await run_command(["holehe", email, "--no-color"], timeout=timeout)
    hits = [
        line.strip() for line in result["stdout"].splitlines()
        if "[+]" in line or "exists" in line.lower()
    ]
    return {
        "available": True,
        "results": hits,
        "stdout": result["stdout"][:20000],
        "stderr": result["stderr"][:5000],
        "exit_code": result["exit_code"],
        "error": result.get("error"),
    }


async def theharvester_scan(domain: str, timeout: int = 240) -> dict:
    """Run theHarvester for domain identity OSINT."""
    if not tool_available("theHarvester"):
        return {"available": False, "emails": [], "hosts": [], "error": "missing"}
    result = await run_command(
        ["theHarvester", "-d", domain, "-b", "bing,duckduckgo,crtsh"],
        timeout=timeout,
    )
    emails = sorted(set(re.findall(r"[\w.+-]+@" + re.escape(domain), result["stdout"], re.I)))
    hosts = sorted(set(re.findall(r"(?:[a-z0-9_-]+\.)+" + re.escape(domain), result["stdout"], re.I)))
    return {
        "available": True,
        "emails": emails,
        "hosts": hosts,
        "stdout": result["stdout"][:20000],
        "stderr": result["stderr"][:5000],
        "exit_code": result["exit_code"],
        "error": result.get("error"),
    }


async def gitleaks_scan_path(path: str, timeout: int = 240) -> dict:
    """Run gitleaks detect against a local path."""
    if not tool_available("gitleaks"):
        return {"available": False, "results": [], "error": "missing"}
    result = await run_command(
        ["gitleaks", "detect", "--no-git", "--source", path, "--report-format", "json", "--no-banner"],
        timeout=timeout,
    )
    try:
        findings = json.loads(result["stdout"] or "[]")
    except json.JSONDecodeError:
        findings = []
    return {
        "available": True,
        "results": findings if isinstance(findings, list) else [],
        "stdout": result["stdout"][:20000],
        "stderr": result["stderr"][:5000],
        "exit_code": result["exit_code"],
        "error": result.get("error"),
    }


async def joomscan_scan(target: str, timeout: int = 300) -> dict:
    """Run joomscan against a Joomla target."""
    if not tool_available("joomscan"):
        return {"available": False, "results": [], "error": "missing"}
    result = await run_command(["joomscan", "-u", target, "--no-report"], timeout=timeout)
    return {
        "available": True,
        "results": parse_cms_text_findings(result["stdout"]),
        "stdout": result["stdout"][:20000],
        "stderr": result["stderr"][:5000],
        "exit_code": result["exit_code"],
        "error": result.get("error"),
    }


async def droopescan_scan(target: str, cms: str = "", timeout: int = 300) -> dict:
    """Run droopescan against Drupal/Joomla/WordPress targets."""
    if not tool_available("droopescan"):
        return {"available": False, "results": [], "error": "missing"}
    args = ["droopescan", "scan", "drupal", "-u", target, "--output", "json"]
    if cms:
        args[2] = cms.lower()
    result = await run_command(args, timeout=timeout)
    try:
        data = json.loads(result["stdout"] or "{}")
    except json.JSONDecodeError:
        data = {}
    return {
        "available": True,
        "results": data,
        "stdout": result["stdout"][:20000],
        "stderr": result["stderr"][:5000],
        "exit_code": result["exit_code"],
        "error": result.get("error"),
    }


async def cmseek_scan(target: str, timeout: int = 300) -> dict:
    """Run CMSeek for CMS detection/vulnerability hints."""
    if not tool_available("cmseek"):
        return {"available": False, "results": {}, "error": "missing"}
    result = await run_command(["cmseek", "-u", target, "--batch", "--random-agent"], timeout=timeout)
    return {
        "available": True,
        "results": parse_cms_text_findings(result["stdout"]),
        "stdout": result["stdout"][:20000],
        "stderr": result["stderr"][:5000],
        "exit_code": result["exit_code"],
        "error": result.get("error"),
    }


def parse_cms_text_findings(text: str) -> List[dict]:
    findings = []
    for line in (text or "").splitlines():
        stripped = line.strip()
        lowered = stripped.lower()
        if any(token in lowered for token in ("vulnerab", "outdated", "version", "cve-", "admin")):
            findings.append({"evidence": stripped})
    return findings[:100]


async def wpscan(target: str, api_token: str = "",
                 timeout: int = 300) -> dict:
    """Run WPScan for WordPress vulnerability detection."""
    if not tool_available("wpscan"):
        return {"available": False, "results": [], "error": "missing"}

    args = ["wpscan", "--url", target, "--no-banner",
            "--format", "json", "--random-user-agent"]
    if api_token:
        args.extend(["--api-token", api_token])

    result = await run_command(args, timeout=timeout)
    try:
        data = json.loads(result["stdout"])
        return {"available": True, "results": data, "exit_code": result["exit_code"]}
    except json.JSONDecodeError:
        return {"available": True, "results": {},
                "raw": redact_for_log(result["stdout"][:10000]),
                "exit_code": result["exit_code"]}


async def whatweb_scan(target: str, timeout: int = 60) -> dict:
    """Run whatweb for technology fingerprinting."""
    if not tool_available("whatweb"):
        return {"available": False, "results": {}, "error": "missing"}

    result = await run_command(
        ["whatweb", "--color=never", "--log-json=-", target],
        timeout=timeout
    )
    try:
        data = json.loads(result["stdout"])
        if isinstance(data, list) and data:
            return {"available": True, "results": data[0]}
    except (json.JSONDecodeError, IndexError):
        pass
    return {"available": True, "results": {}, "raw": result["stdout"][:5000]}


async def nikto_scan(target: str, timeout: int = 300) -> dict:
    """Run nikto web server scanner."""
    if not tool_available("nikto"):
        return {"available": False, "results": [], "error": "missing"}

    result = await run_command(
        ["nikto", "-h", target, "-Format", "json", "-output", "/dev/stdout",
         "-nointeractive", "-Tuning", "013479"],
        timeout=timeout
    )
    try:
        data = json.loads(result["stdout"])
        return {"available": True, "results": data}
    except json.JSONDecodeError:
        return {"available": True, "results": {}, "raw": result["stdout"][:10000]}


async def naabu_scan(target: str, ports: str = "top-1000",
                     timeout: int = 300) -> List[dict]:
    """Fast port scan with naabu."""
    if not tool_available("naabu"):
        return []

    port_arg = f"-top-ports {ports}" if ports.startswith("top") else f"-p {ports}"
    result = await run_command(
        ["naabu", "-host", target, "-silent", "-json"] + port_arg.split(),
        timeout=timeout
    )
    ports_found = []
    for line in result["stdout"].strip().split("\n"):
        if not line.strip():
            continue
        try:
            data = json.loads(line)
            ports_found.append({"host": data.get("host", ""), "port": data.get("port", 0)})
        except json.JSONDecodeError:
            if ":" in line:
                parts = line.strip().split(":")
                if len(parts) == 2 and parts[1].isdigit():
                    ports_found.append({"host": parts[0], "port": int(parts[1])})
    return ports_found



async def jsluice_urls(js_body: str, timeout: int = 60) -> list:
    """Extract URLs and paths from a JS bundle via jsluice (BishopFox).

    The bundle body is staged to a temp file under the repo root so the
    docker backend maps it into /work; the file is removed afterwards.
    jsluice emits one JSON object per finding — the url field of each
    is returned (plain-text lines pass through untouched).
    """
    if not tool_available("jsluice"):
        return []
    import tempfile
    path = ""
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False,
                                         dir=os.getcwd()) as handle:
            handle.write(js_body)
            path = handle.name
        result = await run_command(["jsluice", "urls", path],
                                   timeout=timeout)
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass
    found = []
    for line in result.get("stdout", "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except (ValueError, TypeError):
            data = None
        if isinstance(data, dict) and data.get("url"):
            found.append(str(data["url"]))
        elif data is None and _looks_like_url(line):
            # Plain-text URL lines pass through; error banners and log
            # lines do not. The old code appended every non-JSON line
            # verbatim and downstream scans probed banner text as URLs.
            found.append(line)
    return found


def _looks_like_url(line: str) -> bool:
    text = (line or "").strip()
    if text.startswith(("http://", "https://", "//", "/")):
        return True
    # Bare host/path without scheme (api.example.com/v1, app.js?v=2).
    return bool(re.match(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}([/?#].*)?$", text))


async def semgrep_scan(sources: dict, rules: str = "rules/semgrep",
                       timeout: int = 300) -> dict:
    """Run Semgrep SAST over in-memory JS/TS sources.

    Bodies are staged to a temp dir under the repo root (so the docker
    backend maps it into /work) and scanned with repo-local rules —
    offline and deterministic: `--metrics off --disable-version-check`,
    no registry. Returns one entry per rule hit with the source URL it
    came from. Static by construction: callers must grade these as
    inventory (LOW) or reading-list (MEDIUM/TENTATIVE), never as
    execution proof.
    """
    if not tool_available("semgrep"):
        return {"available": False, "results": [], "error": "missing"}
    if not sources:
        return {"available": True, "results": [], "error": None}
    if rules == "rules/semgrep" and not Path(rules).exists():
        from osint_agent_resources import resource_path
        rules = str(resource_path(rules))
    import tempfile
    tmpdir = ""
    names: dict[str, str] = {}
    result: dict = {}
    staging_error: str | None = None
    try:
        tmpdir = tempfile.mkdtemp(prefix="semgrep-", dir=os.getcwd())
        for index, (source_url, body) in enumerate(sources.items()):
            text = body if isinstance(body, str) else str(body or "")
            if not text or len(text) < 50:
                continue
            relname = f"bundle-{index}.js"
            with open(os.path.join(tmpdir, relname), "w") as handle:
                handle.write(text[:2_000_000])
            names[relname] = str(source_url)
        result = await run_command(
            ["semgrep", "--config", rules, "--json",
             "--metrics", "off", "--disable-version-check",
             "--include=*.js", "--include=*.ts", tmpdir],
            timeout=timeout)
    except OSError as exc:
        # Staging failure (no scratch space, read-only cwd): degrade to
        # empty results with the error surfaced, never UnboundLocalError
        # from the unbound `result` below.
        staging_error = f"staging failed: {exc}"
    finally:
        if tmpdir:
            import shutil as _shutil
            try:
                _shutil.rmtree(tmpdir, ignore_errors=True)
            except OSError:
                pass
    findings = []
    try:
        data = json.loads(result.get("stdout") or "{}")
    except (ValueError, TypeError):
        data = {}
    errors = (data.get("errors") or []) if isinstance(data, dict) else []
    for item in (data.get("results") or []):
        if not isinstance(item, dict):
            continue
        relname = str(item.get("path", "") or "").split("/")[-1]
        extra = item.get("extra") or {}
        findings.append({
            "rule": str(item.get("check_id", "") or "").split(".")[-1],
            "severity": str(extra.get("severity", "INFO") or "INFO").upper(),
            "message": str(extra.get("message", "") or "")[:300],
            "source": names.get(relname, relname),
            "line": int((item.get("start") or {}).get("line") or 0),
            "snippet": str(extra.get("lines", "") or "")[:400],
        })
    return {
        "available": True,
        "results": findings,
        "scanned": len(names),
        "rule_errors": len(errors),
        "exit_code": result.get("exit_code"),
        "error": result.get("error") or staging_error,
    }


async def graphql_cop_scan(endpoint: str, timeout: int = 180) -> dict:
    """Corroborate GraphQL posture with graphql-cop (dolevf, -o json)."""
    if not tool_available("graphql-cop"):
        return {"available": False, "results": {}, "error": "missing"}
    result = await run_command(
        ["graphql-cop", "-t", endpoint, "-o", "json"], timeout=timeout)
    try:
        data = json.loads(result.get("stdout") or "{}")
    except (ValueError, TypeError):
        data = {}
    return {
        "available": True,
        "results": data,
        "exit_code": result.get("exit_code"),
        "error": result.get("error"),
    }


# ── Public interactsh sessions (Option A: no self-hosted infra) ────
#
# One client process per scan (multiplexed, killed on exit) holds a
# session against the public interactsh server. Every payload gets the
# same correlation domain with a distinct path; poll() matches the
# full request URL, so parallel probes stay distinguishable.
# PublicInteractshClient below speaks the same
# register_callback/callback_url/poll interface as InteractshClient,
# which is why BaseModule.oob() can hand it to every module unchanged.

_PUBLIC_SESSION: dict = {}


def _parse_interactsh_session_line(line: str, domains: tuple = ()) -> str:
    """Extract the assigned correlation hostname from a client line.

    The client prints a bare `[INF] <corr>.<server>` line (no scheme,
    no JSON on stdout), so matching anchors on the server domains the
    session was opened against — never on a generic hostname, which
    would catch banner text like projectdiscovery.io first.
    """
    text = line.strip()
    if not text:
        return ""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        data = None
    if isinstance(data, dict):
        for key in ("url", "correlation-id", "correlation_id",
                    "domain", "host"):
            value = data.get(key)
            if isinstance(value, str) and "." in value:
                return value.split("://", 1)[-1].split("/", 1)[0]
    match = re.search(r"https?://([A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,})",
                      text)
    if match:
        return match.group(1)
    for domain in domains:
        domain = domain.strip().lower()
        if not domain:
            continue
        match = re.search(
            r"\b([A-Za-z0-9][A-Za-z0-9-]*\." + re.escape(domain) + r")",
            text, re.IGNORECASE)
        if match:
            return match.group(1).lower()
    return ""


def _poll_interactsh_log(path: str, since: int) -> tuple:
    """Read new client log lines, returning (interactions, new_offset)."""
    interactions = []
    try:
        with open(path, "r", errors="replace") as handle:
            handle.seek(since)
            chunk = handle.read()
            offset = handle.tell()
    except (OSError, ValueError):
        return [], since
    for line in chunk.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except (ValueError, TypeError):
            data = None
        if isinstance(data, dict) and (
                data.get("raw-request") or data.get("full-id")
                or data.get("unique-id") or "interaction" in line.lower()):
            interactions.append(data)
        elif "interactsh" in line.lower() and (
                "dns" in line.lower() or "http" in line.lower()
                or "request" in line.lower()):
            interactions.append({"raw": line})
    return interactions, offset


async def interactsh_session(server: str = "oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me",
                             log_dir: str | None = None,
                             timeout: int = 60) -> dict:
    """Start (or reuse) the process-wide public interactsh session."""
    import asyncio as _asyncio
    import tempfile as _tempfile
    import time as _time
    global _PUBLIC_SESSION
    active = _PUBLIC_SESSION.get(server)
    if active and active.get("proc") is not None \
            and active["proc"].returncode is None:
        return {"available": True, **{k: v for k, v in active.items()
                                      if k != "proc"},
                "reused": True}
    if not tool_available("interactsh-client"):
        return {"available": False, "error": "missing"}
    directory = log_dir or os.path.join(os.getcwd(), "reports")
    os.makedirs(directory, exist_ok=True)
    handle = _tempfile.NamedTemporaryFile(
        "w", prefix="interactsh-", suffix=".jsonl",
        delete=False, dir=directory)
    log_path = handle.name
    handle.close()
    try:
        current = ["interactsh-client", "-server", server,
                   "-json", "-duc", "-o", log_path]
        proc = await _asyncio.create_subprocess_exec(
            *(docker_run_args(current, stdin=False)
              if _BACKEND["mode"] == "docker" else current),
            stdout=_asyncio.subprocess.PIPE,
            stderr=_asyncio.subprocess.STDOUT,
        )
    except Exception as exc:
        return {"available": False, "error": str(exc)}
    host = ""
    deadline = _time.monotonic() + timeout
    buffer = b""
    while _time.monotonic() < deadline:
        try:
            chunk = await _asyncio.wait_for(
                proc.stdout.read(1024),
                timeout=max(1.0, deadline - _time.monotonic()))
        except Exception:
            break
        if not chunk:
            break
        buffer += chunk
        domains = tuple(
            part.split("://", 1)[-1].strip().lower()
            for part in server.split(","))
        for line in buffer.decode(errors="replace").splitlines():
            host = _parse_interactsh_session_line(line, domains) or host
        if host:
            break
    if not host:
        try:
            proc.kill()
        except Exception:
            pass
        return {"available": False,
                "error": "no session domain published"}
    _PUBLIC_SESSION[server] = {"proc": proc, "url": host,
                               "log": log_path, "offset": 0}
    return {"available": True, "url": host, "log": log_path,
            "offset": 0, "reused": False}


def close_interactsh_sessions() -> None:
    """Terminate multiplexed interactsh clients (atexit safety net)."""
    for session in list(_PUBLIC_SESSION.values()):
        proc = session.get("proc")
        try:
            if proc is not None and proc.returncode is None:
                proc.kill()
        except Exception:
            pass
    _PUBLIC_SESSION.clear()


class PublicInteractshClient:
    """InteractshClient-compatible facade over a public session.

    register_callback hands back the session domain (payloads ride in
    distinct paths via callback_url); poll matches the full request
    URL so parallel probes stay distinguishable. The process is shared
    scan-wide and reaped on interpreter exit.
    """

    def __init__(self, server: str = "oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me",
                 poll_interval: float = 2.0,
                 poll_timeout: float = 30.0):
        self.server = server
        self.poll_interval = poll_interval
        self.poll_timeout = poll_timeout
        self.enabled = True
        self._corr = ""
        self._offset = 0

    async def register_callback(self, payload: str) -> str:
        import atexit as _atexit
        session = await interactsh_session(self.server)
        if not session.get("available"):
            self.enabled = False
            return ""
        _atexit.register(close_interactsh_sessions)
        self._corr = str(session.get("url", ""))
        self._offset = int(session.get("offset", 0))
        return self._corr

    def callback_url(self, corr_id: str, path: str = "/") -> str:
        host = corr_id or self._corr
        if not host:
            return f"http://unregistered.oob.invalid{path}"
        if "://" in host:
            base = host.rstrip("/")
        else:
            base = f"https://{host}"
        if not path.startswith("/"):
            path = "/" + path
        return f"{base}{path}"

    async def poll(self, corr_id: str) -> list[dict]:
        import asyncio as _asyncio
        import time as _time
        needle = (corr_id or self._corr).strip().lower()
        if not needle:
            # Unregistered session: nothing to attribute, and polling the
            # full timeout per silent point burns minutes per run.
            return []
        session = _PUBLIC_SESSION.get(self.server) or {}
        log_path = str(session.get("log", "") or "")
        if not log_path:
            return []
        deadline = _time.monotonic() + self.poll_timeout
        offset = self._offset
        while _time.monotonic() < deadline:
            interactions, offset = _poll_interactsh_log(log_path, offset)
            hits = [item for item in interactions
                    if needle and needle in json.dumps(item).lower()]
            if hits:
                self._offset = offset
                return hits
            await _asyncio.sleep(self.poll_interval)
        self._offset = offset
        return []

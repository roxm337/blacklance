"""Desktop GUI for OSINT Agent."""

from __future__ import annotations

import csv
import importlib.util
import json
import os
import re
import sys
import time
from html import escape as html_escape
from pathlib import Path
from urllib.parse import urlparse

import yaml
from PySide6.QtCore import (
    QEasingCurve,
    QEvent,
    QProcess,
    QPropertyAnimation,
    QSize,
    QSettings,
    Qt,
    QTimer,
    QUrl,
)
from PySide6.QtGui import QAction, QColor, QDesktopServices, QFont, QKeySequence, QPalette, QShortcut
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGridLayout,
    QGraphicsOpacityEffect,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QPlainTextEdit,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QSplitter,
    QStackedWidget,
    QStyle,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from gui.graph import (
    analyze_display_graph,
    build_display_graph,
    count_relations,
    filter_display_graph,
    render_attack_html,
    render_gravis_html,
)
from actions import ActionRegistry
from agents import get_llm_config
from core.keyvault import KEY_SPECS, KeyVault
from core.assessments import AssessmentStore, new_assessment_id
from modules import MODULE_REGISTRY, get_all_module_ids
from tools.external import (
    DOCKER_TOOLS,
    configure_tool_backend,
    tool_available,
)
from tools.schemathesis import schemathesis_available
from tools.tool_manager import TOOL_DEFINITIONS


# Container-only tools (baked into docker/Dockerfile.tools) that have no
# TOOL_DEFINITIONS entry. Shown in Settings → Tools so operators see the
# full container toolchain, not just the host-installable subset.
EXTRA_CONTAINER_TOOLS: dict[str, tuple[list[str], str]] = {
    "jsluice": (["web", "js", "endpoints"], "JS endpoint and secret extraction (Tier-1)"),
    "gxss": (["web", "xss", "param"], "Reflect candidate parameters for XSS (Tier-1)"),
    "uro": (["web", "dedup"], "URL dedup and normalisation for fuzz lists (Tier-1)"),
    "graphql-cop": (["web", "graphql"], "GraphQL security tester (Tier-1)"),
    "interactsh-client": (["oob", "callback"], "Free OOB callbacks via public interactsh"),
    "kr": (["web", "api", "fuzzing"], "API route brute force, assetnote wordlists (Tier-2)"),
    "semgrep": (["web", "sast", "js"], "SAST over JS bundles, repo-local rules (Tier-2)"),
    "gobuster": (["web", "fuzzing"], "Directory and DNS brute-forcer"),
    "feroxbuster": (["web", "fuzzing"], "Recursive content discovery"),
    "assetfinder": (["dns", "subdomain"], "Subdomain discovery via public sources"),
    "waybackurls": (["web", "recon"], "Historic URLs from the Wayback Machine"),
    "subzy": (["dns", "takeover"], "Subdomain takeover checker"),
    "dig": (["dns", "probe"], "DNS lookup utility"),
    "whois": (["recon", "whois"], "Domain registration lookup"),
}


ROOT_DIR = Path(__file__).resolve().parent.parent
ORCHESTRATOR = ROOT_DIR / "orchestrator.py"
TOOLS_REQUIREMENTS = ROOT_DIR / "tools_requirements.txt"

STATUS_COLORS = {
    "completed": "#4ade80",
    "complete": "#4ade80",
    "running": "#7dd3fc",
    "timeout": "#fbbf24",
    "incomplete": "#fbbf24",
    "interrupted": "#fbbf24",
    "cancelled": "#fbbf24",
    "stopped": "#fbbf24",
    "error": "#f87171",
    "failed": "#f87171",
    "blocked": "#fb923c",
    "skipped": "#94a3b8",
}

SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
SEVERITY_COLORS = {
    "CRITICAL": "#fb7185",
    "HIGH": "#fdba74",
    "MEDIUM": "#fde047",
    "LOW": "#93c5fd",
    "INFO": "#94a3b8",
}
CONFIDENCE_RANK = {"TENTATIVE": 0, "FIRM": 1, "CONFIRMED": 2}

EMPTY_GRAPH_HTML = (
    "<html><body style='font-family:Arial;background:#0a0f14;padding:24px;"
    "color:#d8e2ea;'>{message}</body></html>"
)
VERDICT_LABELS = {
    "": "-",
    "true_positive": "true positive",
    "false_positive": "false positive",
    "out_of_scope": "out of scope",
}
VERDICT_COLORS = {
    "true_positive": "#4ade80",
    "false_positive": "#f87171",
    "out_of_scope": "#fbbf24",
}

# I2 grading ladder (tools/schemathesis.py + modules/api_workflows.py). The
# tier colours are deliberately distinct from SEVERITY_COLORS: a schema
# violation is not a vulnerability, and the screen must never blur that.
SCHEMA_TIERS = ("PROOF", "CANDIDATE", "OBSERVATION")
SCHEMA_TIER_RANK = {tier: index for index, tier in enumerate(SCHEMA_TIERS)}
SCHEMA_TIER_COLORS = {
    "PROOF": "#4ade80",
    "CANDIDATE": "#fdba74",
    "OBSERVATION": "#93c5fd",
}
SCHEMA_TIER_MEANING = {
    "PROOF": "the framework replayed the case and an impact probe re-read "
             "confirmed the corrupted state",
    "CANDIDATE": "the server misbehaved under fuzzing; impact is not "
                 "independently confirmed",
    "OBSERVATION": "response/schema conformance drift — a spec violation, "
                   "not a demonstrated vulnerability",
}
SCHEMA_EVIDENCE_TYPES = {"schemathesis", "schemathesis_impact"}
SCHEMA_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
SCHEMA_OPS = {"eq": "=", "lt": "<", "gt": ">", "contains": "contains"}

# I3 authorization matrix. The engine only ever files a leak or a canary
# proof, so the screen grades every cell into the same ladder and shows the
# healthy cells too — a matrix that only displays leaks cannot show coverage.
AUTHZ_EVIDENCE_TYPE = "matrix_report"
AUTHZ_TIERS = ("PROOF", "CANDIDATE", "OBSERVATION", "HEALTHY")
AUTHZ_TIER_RANK = {tier: index for index, tier in enumerate(AUTHZ_TIERS)}
AUTHZ_TIER_COLORS = {
    "PROOF": "#4ade80",
    "CANDIDATE": "#fdba74",
    "OBSERVATION": "#93c5fd",
    "HEALTHY": "#5b7181",
}
AUTHZ_TIER_MEANING = {
    "PROOF": "a canary the forbidden identity actually read back, with the "
             "owner re-read intact and cleanup verified",
    "CANDIDATE": "the cell returned another identity's data; attribution came "
                 "from the victim's own baseline, impact is not proven",
    "OBSERVATION": "the read is not classifiable — login page, session loss, "
                   "server error, or a body identical to the absent control",
    "HEALTHY": "the read was denied or the object was absent for this "
               "identity, and a canary's seeded object was cleaned up — "
               "correct behaviour, shown so coverage is visible",
}
# Outcome -> tier. "allowed" lands on OBSERVATION, not HEALTHY: a 200 that
# returns someone else's endpoint without carrying their markers still needs
# a human look before it is called safe.
AUTHZ_OUTCOME_TIER = {
    "leak": "CANDIDATE",
    "field_leak": "CANDIDATE",
    "allowed": "OBSERVATION",
    "ambiguous": "OBSERVATION",
    "error": "OBSERVATION",
    "denied": "HEALTHY",
    "absent": "HEALTHY",
}
AUTHZ_MODULES = ("idor_differ", "bfla_audit", "graphql_audit")
AUTHZ_FINDING_CATEGORIES = ("Authorization Matrix",
                            "Broken Function Level Authorization")

# I4 client-side path traversal (modules/cspt_audit.py). The module's own
# three states ARE the ladder: a token that never reached an XHR/fetch is an
# unproven inject point, one that stayed under the natural prefix is clean,
# and one that escaped is a candidate. Only the framework's own replay of the
# altered URL — against an absent-reference control — promotes it.
CSPT_MODULE_ID = "cspt_audit"
CSPT_EVIDENCE_TYPE = "cspt_report"
CSPT_IMPACT_TYPE = "cspt_impact"
CSPT_TIERS = ("PROOF", "CANDIDATE", "OBSERVATION", "HEALTHY")
CSPT_TIER_RANK = {tier: index for index, tier in enumerate(CSPT_TIERS)}
CSPT_TIER_COLORS = {
    "PROOF": "#4ade80",
    "CANDIDATE": "#fdba74",
    "OBSERVATION": "#93c5fd",
    "HEALTHY": "#5b7181",
}
CSPT_TIER_MEANING = {
    "PROOF": "the altered URL was replayed and returned the configured impact "
             "value the natural request does not return, and an "
             "absent-reference control came back a different shape",
    "CANDIDATE": "a traversal payload resolved outside the natural prefix; "
                 "impact is not independently confirmed",
    "OBSERVATION": "the injected value never appeared in an XHR/fetch request "
                   "— this inject point is unproven, not clean",
    "HEALTHY": "the injected value reached a request and the resolved path "
               "stayed under the natural prefix — correct behaviour, shown so "
               "coverage is visible",
}
CSPT_STATE_TIER = {
    "path_altered": "CANDIDATE",
    "not_reached": "OBSERVATION",
    "unchanged": "HEALTHY",
}
CSPT_STATES = ("path_altered", "not_reached", "unchanged")
CSPT_INJECT_POINTS = ("query", "fragment", "path")
CSPT_FINDING_CATEGORY = "Client-Side Path Traversal"

ORM_MODULE_ID = "orm_filter_audit"
ORM_EVIDENCE_TYPE = "orm_filter_report"
ORM_CANARY_EVIDENCE_TYPE = "orm_filter_canary"
ORM_TIERS = ("PROOF", "CANDIDATE", "OBSERVATION", "HEALTHY")
ORM_TIER_RANK = {tier: index for index, tier in enumerate(ORM_TIERS)}
ORM_TIER_COLORS = {
    "PROOF": "#4ade80",
    "CANDIDATE": "#fdba74",
    "OBSERVATION": "#93c5fd",
    "HEALTHY": "#5b7181",
}
ORM_TIER_MEANING = {
    "PROOF": "a record this pass seeded for its owner came back through the "
             "filter to an identity whose direct read of the same record was "
             "denied, and cleanup was verified by a re-read",
    "CANDIDATE": "a filter value returned rows attributable to another "
                 "identity that neither the direct read nor an absent-value "
                 "control exposes — real records only, values never stored, "
                 "so a seeded canary has to confirm it",
    "OBSERVATION": "a canary ran but cannot be read as a clean negative: a "
                   "prerequisite failed, or the seeded record's cleanup is "
                   "unverified",
    "HEALTHY": "driven and came back clean — for a surface, every configured "
               "filter value returned no cross-identity rows; for a canary, "
               "the seeded record stayed private through the filter and its "
               "cleanup was verified",
}
ORM_VECTOR_MEANING = {
    "inclusion": "filter/where vector — the value selects records, so a row "
                 "belonging to another identity is an authorisation miss",
    "field": "projection vector — include/fields/select ask the ORM to attach "
             "related records or columns to the response",
    "ordering": "sort/order — an oracle only: it can reveal that a field "
                "exists, and the engine never files a finding from it",
}
ORM_FINDING_CATEGORY = "ORM Filter Leak"
ORM_CLEANUP_VERIFIED = "verified"


def _browser_driver_present() -> bool:
    """Whether the real browser cspt_audit drives is actually installed.

    Uses a spec lookup instead of an import: the GUI must say "missing"
    without paying for a Playwright import on every settings load.
    """
    return importlib.util.find_spec("playwright") is not None


def _describe_expectation(expect) -> str:
    """Render an impact-probe expectation as the operator reads it."""
    if not isinstance(expect, dict) or not expect:
        return "-"
    op = SCHEMA_OPS.get(str(expect.get("op") or "eq"), "=?")
    value = expect.get("value")
    rendered = json.dumps(value) if isinstance(value, str) else str(value)
    return f"{op} {rendered}"


def _priority_rank(priority: str) -> int:
    """P0 sorts first; anything unparseable sinks to the bottom."""
    text = str(priority or "").strip().upper()
    if text.startswith("P") and text[1:].isdigit():
        return int(text[1:])
    return 99


def _bold_font() -> QFont:
    font = QFont()
    font.setBold(True)
    return font


def code_font(size: int = 12) -> QFont:
    """Monospace font stack that exists on macOS, Linux, and Windows."""
    font = QFont()
    font.setFamilies(["SF Mono", "Menlo", "Consolas", "DejaVu Sans Mono", "monospace"])
    font.setPointSize(size)
    return font


def _dark_palette() -> QPalette:
    """Dark Fusion palette.

    Stylesheets do not cover every paint path — the tab-bar base line,
    scroll-area corners and disabled texts still read the app palette, which
    defaults to the light system theme and leaks white lines into the UI.
    """
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor("#111820"))
    palette.setColor(QPalette.WindowText, QColor("#d8e2ea"))
    palette.setColor(QPalette.Base, QColor("#0c1218"))
    palette.setColor(QPalette.AlternateBase, QColor("#101820"))
    palette.setColor(QPalette.ToolTipBase, QColor("#18232d"))
    palette.setColor(QPalette.ToolTipText, QColor("#e5ecef"))
    palette.setColor(QPalette.Text, QColor("#e5ecef"))
    palette.setColor(QPalette.Button, QColor("#18232d"))
    palette.setColor(QPalette.ButtonText, QColor("#d8e2ea"))
    palette.setColor(QPalette.BrightText, QColor("#f87171"))
    palette.setColor(QPalette.Link, QColor("#70daca"))
    palette.setColor(QPalette.LinkVisited, QColor("#93c5fd"))
    palette.setColor(QPalette.Highlight, QColor("#1b7469"))
    palette.setColor(QPalette.HighlightedText, QColor("#ffffff"))
    # Grayscale roles: QStyle frame/base lines (tab-bar base, scroll corners)
    # read Light/Mid/Dark and would otherwise stay light-theme white.
    palette.setColor(QPalette.Light, QColor("#47606c"))
    palette.setColor(QPalette.Midlight, QColor("#32404d"))
    palette.setColor(QPalette.Mid, QColor("#25313c"))
    palette.setColor(QPalette.Dark, QColor("#17222b"))
    palette.setColor(QPalette.Shadow, QColor("#000000"))
    palette.setColor(QPalette.Disabled, QPalette.WindowText, QColor("#5b6a80"))
    palette.setColor(QPalette.Disabled, QPalette.Text, QColor("#5b6a80"))
    palette.setColor(QPalette.Disabled, QPalette.ButtonText, QColor("#5b6a80"))
    palette.setColor(QPalette.Disabled, QPalette.HighlightedText, QColor("#5b6a80"))
    return palette


# Name of the derived config the r10xM preset writes beside the user's config
# so their own config.yaml is never clobbered. Gitignored like config.yaml.
R10XM_CONFIG_NAME = "config.r10xm.generated.yaml"


def _deep_merge(base: dict, overlay: dict) -> dict:
    """Recursively merge `overlay` onto a copy of `base` (overlay wins).

    Nested mappings merge key-by-key; every other value (including lists) is
    replaced wholesale. Used to lay the r10xM preset over the operator's own
    config without discarding the keys the preset does not touch.
    """
    out = dict(base) if isinstance(base, dict) else {}
    for key, value in (overlay or {}).items():
        current = out.get(key)
        if isinstance(current, dict) and isinstance(value, dict):
            out[key] = _deep_merge(current, value)
        else:
            out[key] = value
    return out


def r10xm_config_overlay(base: dict | None = None) -> dict:
    """The r10xM 'maximum autonomous' config, merged onto `base`.

    One switch, no hand configuration: Docker toolchain by default, deep
    target coverage, every resource cap released (unlimited requests, wall
    clock, LLM calls, external commands) and a high per-prompt token ceiling
    so the LLM phases are never truncated mid-reasoning. It does NOT touch the
    target/auth/scope keys — authorisation stays the operator's to set, and
    the engagement-confirmation gate still fires before any action executes.
    """
    overlay = {
        "tools": {"backend": "docker", "image": "osint-tools:latest"},
        "target": {"mode": "deep"},
        "detectability": {"default": "high"},
        "llm": {"max_tokens": 8192},
        "budget_limits": {
            "max_requests": 0,
            "max_wall_clock_seconds": 0,
            "max_llm_calls": 0,
            "max_external_commands": 0,
            "max_concurrent_actions": 10,
        },
        "module_timeout": 1800,
    }
    return _deep_merge(base or {}, overlay)


def build_scan_args(
    target: str,
    output_dir: Path | str,
    config_path: Path | str,
    mode: str = "Auto",
    active: bool = False,
    module: str | None = None,
    pentest: bool = False,
    execute: bool = False,
    max_risk: str = "DESTRUCTIVE",
    max_actions: int = 0,
    max_chains: int = 0,
    run_mode: str = "fresh",
    assessment_id: str | None = None,
    from_assessment: str | None = None,
    agent: bool = False,
) -> list[str]:
    """Build orchestrator argv for a GUI run.

    Kept as a pure function so tests can assert every console control reaches
    the CLI. `-c` is always passed because Settings writes config.yaml at a
    path the orchestrator would otherwise never read (it resolves a relative
    default against the process CWD, which is the repo root we also pin in
    ``_start_process``).
    """
    args = [
        str(ORCHESTRATOR),
        "-t", target,
        "-o", str(output_dir),
        "-c", str(config_path),
    ]
    args.extend(["--run-mode", run_mode])
    if assessment_id:
        args.extend(["--assessment", assessment_id])
    if from_assessment:
        args.extend(["--from-assessment", from_assessment])
    # Autonomous engagement (r10xM-mode): one supervisor drives the whole
    # recon -> exploit -> verify -> report lifecycle, so the per-module/mode
    # selectors do not apply. --execute + --max-risk hand it the exploitation
    # mandate; --module and --mode are deliberately omitted.
    if agent:
        args.append("--agent")
        if execute:
            args.append("--execute")
        args.extend(["--max-risk", str(max_risk)])
        if int(max_actions):
            args.extend(["--max-actions", str(int(max_actions))])
        return args
    if active:
        args.append("--active")
    # Independent of `active`: both flags may legitimately apply at once.
    if mode == "LLM":
        args.extend(["--mode", "llm"])
    if module:
        args.extend(["--module", str(module)])
    if pentest:
        args.append("--pentest")
        args.extend(["--max-risk", str(max_risk)])
        args.extend(["--max-actions", str(int(max_actions))])
        args.extend(["--max-chains", str(int(max_chains))])
        if execute:
            args.append("--execute")
    return args


__all__ = [
    'csv',
    'importlib',
    'json',
    'os',
    're',
    'sys',
    'time',
    'html_escape',
    'Path',
    'urlparse',
    'yaml',
    'QEasingCurve',
    'QEvent',
    'QProcess',
    'QPropertyAnimation',
    'QSize',
    'QSettings',
    'Qt',
    'QTimer',
    'QUrl',
    'QAction',
    'QColor',
    'QDesktopServices',
    'QFont',
    'QKeySequence',
    'QPalette',
    'QShortcut',
    'QWebEngineView',
    'QAbstractItemView',
    'QApplication',
    'QButtonGroup',
    'QCheckBox',
    'QComboBox',
    'QDoubleSpinBox',
    'QFileDialog',
    'QFormLayout',
    'QFrame',
    'QGridLayout',
    'QGraphicsOpacityEffect',
    'QGroupBox',
    'QHBoxLayout',
    'QHeaderView',
    'QInputDialog',
    'QLabel',
    'QLineEdit',
    'QMainWindow',
    'QMenu',
    'QMessageBox',
    'QProgressBar',
    'QPushButton',
    'QPlainTextEdit',
    'QScrollArea',
    'QSizePolicy',
    'QSpinBox',
    'QSplitter',
    'QStackedWidget',
    'QStyle',
    'QTableWidget',
    'QTableWidgetItem',
    'QTabWidget',
    'QTextEdit',
    'QToolButton',
    'QVBoxLayout',
    'QWidget',
    'analyze_display_graph',
    'build_display_graph',
    'count_relations',
    'filter_display_graph',
    'render_attack_html',
    'render_gravis_html',
    'ActionRegistry',
    'get_llm_config',
    'KEY_SPECS',
    'KeyVault',
    'AssessmentStore',
    'new_assessment_id',
    'MODULE_REGISTRY',
    'get_all_module_ids',
    'DOCKER_TOOLS',
    'configure_tool_backend',
    'tool_available',
    'schemathesis_available',
    'TOOL_DEFINITIONS',
    'EXTRA_CONTAINER_TOOLS',
    'ROOT_DIR',
    'ORCHESTRATOR',
    'TOOLS_REQUIREMENTS',
    'STATUS_COLORS',
    'SEVERITY_RANK',
    'SEVERITY_COLORS',
    'CONFIDENCE_RANK',
    'EMPTY_GRAPH_HTML',
    'VERDICT_LABELS',
    'VERDICT_COLORS',
    'SCHEMA_TIERS',
    'SCHEMA_TIER_RANK',
    'SCHEMA_TIER_COLORS',
    'SCHEMA_TIER_MEANING',
    'SCHEMA_EVIDENCE_TYPES',
    'SCHEMA_METHODS',
    'SCHEMA_OPS',
    'AUTHZ_EVIDENCE_TYPE',
    'AUTHZ_TIERS',
    'AUTHZ_TIER_RANK',
    'AUTHZ_TIER_COLORS',
    'AUTHZ_TIER_MEANING',
    'AUTHZ_OUTCOME_TIER',
    'AUTHZ_MODULES',
    'AUTHZ_FINDING_CATEGORIES',
    'CSPT_MODULE_ID',
    'CSPT_EVIDENCE_TYPE',
    'CSPT_IMPACT_TYPE',
    'CSPT_TIERS',
    'CSPT_TIER_RANK',
    'CSPT_TIER_COLORS',
    'CSPT_TIER_MEANING',
    'CSPT_STATE_TIER',
    'CSPT_STATES',
    'CSPT_INJECT_POINTS',
    'CSPT_FINDING_CATEGORY',
    'ORM_MODULE_ID',
    'ORM_EVIDENCE_TYPE',
    'ORM_CANARY_EVIDENCE_TYPE',
    'ORM_TIERS',
    'ORM_TIER_RANK',
    'ORM_TIER_COLORS',
    'ORM_TIER_MEANING',
    'ORM_VECTOR_MEANING',
    'ORM_FINDING_CATEGORY',
    'ORM_CLEANUP_VERIFIED',
    '_browser_driver_present',
    '_describe_expectation',
    '_priority_rank',
    '_bold_font',
    'code_font',
    '_dark_palette',
    'R10XM_CONFIG_NAME',
    '_deep_merge',
    'r10xm_config_overlay',
    'build_scan_args',
]

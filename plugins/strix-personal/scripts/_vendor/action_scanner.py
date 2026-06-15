"""Action-point scanner: inventory all governance-relevant call sites.

A superset of the ``/strix-wire`` skill scanner. The skill scanner is
scoped to *one* irreversible mutation per run (it wraps the candidate
with ``governedAction()``). This module is the audit surface: it walks
the tree and surfaces **every** action point — mutations *and* AI
surfaces — so an operator can see what's already governed, what isn't,
and which capability IDs they need to map.

Two pattern families:

* **Mutation patterns** — irreversible side-effects on the outside
  world (payments, deletes, sends, schema migrations). Same scope as the
  /strix-wire skill scanner; the patterns are duplicated here so the
  installed package does not depend on the ``.claude/`` directory.

* **AI patterns** — call sites where an LLM or agent loop is invoked,
  where a tool/function is registered for model-driven invocation, or
  where retrieval is performed against a vector store. These are the
  high-leverage governance points in AI applications; the side-effects
  *driven* by these calls are caught by the mutation patterns above,
  but the model-call layer itself is governance-relevant for budget,
  prompt-injection, and provenance reasons.

Usage:

    from solo_builder.action_scanner import scan
    candidates = scan(repo_root, include_ai=True)

Standalone CLI form:

    python -m solo_builder.action_scanner --root . --include-ai --json
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Pattern tables
# ---------------------------------------------------------------------------

# Language extension shortcuts.
_PY = frozenset({".py"})
_JS = frozenset({".ts", ".tsx", ".js", ".jsx", ".mjs"})
_JS_PY = _PY | _JS

# Each pattern: (regex, kind, category, capability_id, confidence, languages)
# - kind: "mutation" | "ai"
# - confidence: "high" | "medium"


MUTATION_PATTERNS: list[tuple[str, str, str, str, str, frozenset[str]]] = [
    # ── Payments — Stripe ────────────────────────────────────────────────
    (r"\bstripe\.\w+\.create\s*\(", "mutation", "payments", "payment.charge", "high", _JS_PY),
    (r"\bstripe\.Charge\.create\s*\(", "mutation", "payments", "payment.charge", "high", _PY),
    (r"\bstripe\.charges\.create\s*\(", "mutation", "payments", "payment.charge", "high", _JS),
    (r"\bstripe\.PaymentIntent\.create\s*\(", "mutation", "payments", "payment.charge", "high", _PY),
    (r"\bstripe\.paymentIntents\.create\s*\(", "mutation", "payments", "payment.charge", "high", _JS),
    # ── Database deletes — Prisma / ORMs ─────────────────────────────────
    (r"\bprisma\.\w+\.delete(Many)?\s*\(", "mutation", "db-delete", "database.delete", "high", _JS),
    (r"\bprisma\.\w+\.update(Many)?\s*\(", "mutation", "db-update", "database.update", "medium", _JS),
    (
        r"""(?ix)        # raw SQL DELETE / DROP / TRUNCATE — quoted literal
        ["']\s*
        (?: DELETE\s+FROM | DROP\s+TABLE | TRUNCATE\s+TABLE | TRUNCATE )
        \s+
        """,
        "mutation",
        "db-delete",
        "database.delete",
        "high",
        _JS_PY | frozenset({".go", ".rb"}),
    ),
    (r"\.destroy\s*\(\s*\{\s*where", "mutation", "db-delete", "database.delete", "high", _JS),
    # ── S3 / object storage ──────────────────────────────────────────────
    (r"\.delete_object\s*\(", "mutation", "s3-delete", "storage.delete", "high", _PY),
    (r"\bDeleteObjectCommand\s*\(", "mutation", "s3-delete", "storage.delete", "high", _JS),
    (r"\.deleteObject\s*\(", "mutation", "s3-delete", "storage.delete", "high", _JS),
    (r"\.put_object\s*\(", "mutation", "s3-write", "storage.write", "medium", _PY),
    (r"\bPutObjectCommand\s*\(", "mutation", "s3-write", "storage.write", "medium", _JS),
    # ── Email / SMS sends ────────────────────────────────────────────────
    (r"\bsendgrid\.[A-Za-z_]*[Ss]end[A-Za-z_]*\s*\(", "mutation", "email-send", "email.send", "high", _JS_PY),
    (r"\bSendGridAPIClient\b", "mutation", "email-send", "email.send", "medium", _PY),
    (r"\bnodemailer\b[^\n]{0,80}\.sendMail\s*\(", "mutation", "email-send", "email.send", "high", _JS),
    (r"\btwilio[^\n]{0,80}\.messages\.create\s*\(", "mutation", "sms-send", "sms.send", "high", _JS_PY),
    # ── Filesystem deletes ───────────────────────────────────────────────
    (
        r"\b(os\.remove|os\.unlink|shutil\.rmtree)\s*\(",
        "mutation",
        "file-delete",
        "filesystem.delete",
        "medium",
        _PY,
    ),
    (
        r"\bfs\.(unlink|rm|unlinkSync|rmSync)\s*\(",
        "mutation",
        "file-delete",
        "filesystem.delete",
        "medium",
        _JS,
    ),
    # ── Schema migrations ────────────────────────────────────────────────
    (
        r"(?i)alembic\.op\.(drop_|alter_|create_)",
        "mutation",
        "schema-migration",
        "database.migrate",
        "high",
        _PY,
    ),
    (
        r"(?i)\bprisma migrate (deploy|reset)\b",
        "mutation",
        "schema-migration",
        "database.migrate",
        "high",
        frozenset({".sh", ".ts", ".js"}),
    ),
]


AI_PATTERNS: list[tuple[str, str, str, str, str, frozenset[str]]] = [
    # ── Provider call sites ──────────────────────────────────────────────
    # OpenAI chat completions — unambiguous shape.
    (r"\.chat\.completions\.create\s*\(", "ai", "ai-provider", "ai.completion", "high", _JS_PY),
    # OpenAI Responses API.
    (r"\.responses\.create\s*\(", "ai", "ai-provider", "ai.completion", "high", _JS_PY),
    # Embeddings (OpenAI, Cohere, Voyage all use this shape).
    (r"\.embeddings\.create\s*\(", "ai", "ai-embedding", "ai.embedding", "high", _JS_PY),
    # Anthropic messages — Twilio uses the same suffix; the Twilio
    # pattern above is matched first (it requires `twilio` on the line)
    # so this fires for the remaining cases. Marked medium for safety.
    (r"\.messages\.create\s*\(", "ai", "ai-provider", "ai.completion", "medium", _JS_PY),
    # Bedrock InvokeModel.
    (r"\binvoke_model\s*\(", "ai", "ai-provider", "ai.completion", "high", _PY),
    (r"\bInvokeModelCommand\s*\(", "ai", "ai-provider", "ai.completion", "high", _JS),
    # Vertex / Gemini.
    (r"\bgenerative_models\.GenerativeModel\s*\(", "ai", "ai-provider", "ai.completion", "high", _PY),
    (r"\bgenAI\.getGenerativeModel\s*\(", "ai", "ai-provider", "ai.completion", "high", _JS),
    # LangChain chat-model constructors — high signal of provider use.
    (
        r"\b(ChatAnthropic|ChatOpenAI|ChatBedrock|ChatVertexAI|ChatGoogleGenerativeAI|ChatCohere|ChatMistralAI)\s*\(",
        "ai",
        "ai-provider",
        "ai.completion",
        "high",
        _JS_PY,
    ),
    # Provider SDK imports — medium because import alone isn't a call.
    (r"^\s*(?:from\s+anthropic\b|import\s+anthropic\b)", "ai", "ai-provider", "ai.completion", "medium", _PY),
    (r"^\s*(?:from\s+openai\b|import\s+openai\b)", "ai", "ai-provider", "ai.completion", "medium", _PY),
    (r"from\s+['\"]@anthropic-ai/sdk['\"]", "ai", "ai-provider", "ai.completion", "medium", _JS),
    (r"^\s*import\s+[^;\n]*\bfrom\s+['\"]openai['\"]", "ai", "ai-provider", "ai.completion", "medium", _JS),
    # ── Tool use / function calling ──────────────────────────────────────
    # MCP server tool decorators.
    (r"@\s*(?:mcp|server|app)\.tool\b", "ai", "ai-tool-use", "ai.tool_use", "high", _PY),
    # FastMCP / MCP Server constructor.
    (r"\b(?:FastMCP|McpServer|Server)\s*\(\s*\{?\s*name", "ai", "ai-tool-use", "ai.tool_use", "high", _JS_PY),
    (r"\bFastMCP\s*\(", "ai", "ai-tool-use", "ai.tool_use", "high", _PY),
    # tool_choice argument — strong AI signal.
    (r"\btool_choice\s*[=:]", "ai", "ai-tool-use", "ai.tool_use", "high", _JS_PY),
    # tools= [list] kwarg on call line (Anthropic / OpenAI function calling).
    (r"\btools\s*=\s*\[", "ai", "ai-tool-use", "ai.tool_use", "medium", _PY),
    (r"\btools:\s*\[", "ai", "ai-tool-use", "ai.tool_use", "medium", _JS),
    # @tool decorator (LangChain / smolagents).
    (r"^\s*@tool\b", "ai", "ai-tool-use", "ai.tool_use", "medium", _PY),
    # ── Agent frameworks ─────────────────────────────────────────────────
    # LangGraph.
    (r"\bStateGraph\s*\(", "ai", "ai-agent", "ai.agent_run", "high", _JS_PY),
    (r"\bcreate_react_agent\s*\(", "ai", "ai-agent", "ai.agent_run", "high", _PY),
    (r"^\s*from\s+langgraph\b", "ai", "ai-agent", "ai.agent_run", "high", _PY),
    # CrewAI.
    (r"^\s*from\s+crewai\b", "ai", "ai-agent", "ai.agent_run", "high", _PY),
    (r"\bCrew\s*\(\s*agents", "ai", "ai-agent", "ai.agent_run", "high", _PY),
    # AutoGen.
    (r"^\s*from\s+autogen\b", "ai", "ai-agent", "ai.agent_run", "high", _PY),
    (
        r"\b(?:ConversableAgent|GroupChat|AssistantAgent|UserProxyAgent)\s*\(",
        "ai",
        "ai-agent",
        "ai.agent_run",
        "high",
        _PY,
    ),
    # smolagents.
    (r"^\s*from\s+smolagents\b", "ai", "ai-agent", "ai.agent_run", "high", _PY),
    (r"\b(?:CodeAgent|ToolCallingAgent)\s*\(", "ai", "ai-agent", "ai.agent_run", "high", _PY),
    # LlamaIndex agents.
    (
        r"\b(?:ReActAgent|OpenAIAgent|FunctionCallingAgentWorker)\s*\(",
        "ai",
        "ai-agent",
        "ai.agent_run",
        "high",
        _PY,
    ),
    # LangChain AgentExecutor.
    (r"\bAgentExecutor\s*\(", "ai", "ai-agent", "ai.agent_run", "high", _JS_PY),
    (r"\binitialize_agent\s*\(", "ai", "ai-agent", "ai.agent_run", "high", _PY),
    # Anthropic Agent SDK (managed agents).
    (r"@anthropic-ai/agent-sdk", "ai", "ai-agent", "ai.agent_run", "high", _JS),
    (r"^\s*from\s+claude_agent_sdk\b", "ai", "ai-agent", "ai.agent_run", "high", _PY),
    # ── RAG / retrieval ──────────────────────────────────────────────────
    # Pinecone.
    (r"\bpinecone\.Index\s*\(", "ai", "ai-retrieval", "ai.retrieval", "high", _PY),
    (r"^\s*from\s+pinecone\b", "ai", "ai-retrieval", "ai.retrieval", "medium", _PY),
    (r"\bPinecone\s*\(\s*\{?\s*apiKey", "ai", "ai-retrieval", "ai.retrieval", "high", _JS),
    # Chroma.
    (
        r"\bchromadb\.(?:Client|PersistentClient|HttpClient)",
        "ai",
        "ai-retrieval",
        "ai.retrieval",
        "high",
        _PY,
    ),
    (r"\bChromaClient\s*\(", "ai", "ai-retrieval", "ai.retrieval", "high", _JS),
    # Weaviate.
    (r"\bweaviate\.(?:Client|connect_to_\w+)", "ai", "ai-retrieval", "ai.retrieval", "high", _PY),
    (r"\bweaviate\.client\.Client\s*\(", "ai", "ai-retrieval", "ai.retrieval", "high", _JS),
    # Qdrant.
    (r"\bQdrantClient\s*\(", "ai", "ai-retrieval", "ai.retrieval", "high", _JS_PY),
    # FAISS.
    (r"\bfaiss\.(?:IndexFlat|read_index|write_index)", "ai", "ai-retrieval", "ai.retrieval", "high", _PY),
    # LangChain retriever / vectorstore.
    (r"\.as_retriever\s*\(", "ai", "ai-retrieval", "ai.retrieval", "high", _JS_PY),
    (r"\bVectorStoreRetriever\s*\(", "ai", "ai-retrieval", "ai.retrieval", "high", _JS_PY),
    # LlamaIndex query engine / retriever.
    (r"\.as_query_engine\s*\(", "ai", "ai-retrieval", "ai.retrieval", "high", _PY),
    (r"\bVectorStoreIndex\.from_documents\s*\(", "ai", "ai-retrieval", "ai.retrieval", "high", _PY),
]


# Directories we never descend into.
SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        ".venv",
        "venv",
        "env",
        "dist",
        "build",
        ".next",
        ".nuxt",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        "vendor",
        "target",
        "coverage",
        "htmlcov",
        ".tox",
    }
)

# Path fragments that indicate test code — never wrap these.
TEST_PATH_MARKERS = (
    "/tests/",
    "/test/",
    "/__tests__/",
    "/spec/",
    "/specs/",
    "/fixtures/",
    "/mocks/",
    "/__mocks__/",
)

# Source extensions the scanner reads.
_SOURCE_EXTS = (
    ".py",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".mjs",
    ".go",
    ".rb",
    ".sh",
)

# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------


@dataclass
class Candidate:
    file: str
    line: int
    snippet: str
    kind: str  # "mutation" | "ai"
    category: str
    capability_id: str
    confidence: str  # "high" | "medium"
    governed: bool = False  # True if a governed_action() wrap is detected nearby
    # ── Spine fields (policy + opt-out + SARIF) ────────────────────────
    # SARIF severity decided by the active ``Policy``. The capability_id
    # → severity mapping is the contract every downstream tool (Code
    # Scanning, Sonar, Snyk, Qodana) consumes.
    severity: str = "note"  # "error" | "warning" | "note"
    # True if a ``# strix: allow ...`` directive on the same or previous
    # line opted this candidate out. ``suppressed_reason`` carries the
    # operator's stated justification. Suppressed candidates are kept in
    # the candidate list (so they show up in SARIF as ``suppressions``)
    # but are excluded from ``--fail-on-open`` checks.
    suppressed: bool = False
    suppressed_reason: str | None = None


@dataclass
class ScanSummary:
    candidates: list[Candidate] = field(default_factory=list)
    by_kind: dict[str, int] = field(default_factory=dict)
    by_category: dict[str, int] = field(default_factory=dict)
    by_capability: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    governed_count: int = 0
    ungoverned_count: int = 0
    suppressed_count: int = 0
    # ``governed`` + ``suppressed`` together = "not blocking." Pre-computed
    # so downstream consumers don't reimplement the arithmetic.
    blocking_count: int = 0  # ungoverned, unsuppressed, severity == "error"


# Regex matching a call to the canonical governance wrapper (Python or TS form).
_GOVERNED_CALL_RE = re.compile(r"\bgoverned(?:_action|Action)\s*\(")

# Inline opt-out directive. Matches `# strix: allow capability=<id> reason="..."`
# (or `// strix: allow ...` for JS/TS). Reason is required.
_OPT_OUT_RE = re.compile(
    r"""(?:\#|//)\s*strix:\s*allow\s+
        capability\s*=\s*([^\s"']+)\s+
        reason\s*=\s*"([^"]+)"
    """,
    re.VERBOSE,
)


# ---------------------------------------------------------------------------
# Policy: capability_id glob → SARIF severity
# ---------------------------------------------------------------------------

# Built-in policy used when the operator hasn't set one in ``.solo.toml``.
# Maps capability_id globs to SARIF severity. Most-specific glob (fewest
# wildcards) wins; ties broken by length, then alphabetical. The fallback
# is ``note`` so unknown capabilities are surfaced but never block CI.
DEFAULT_POLICY: dict[str, str] = {
    # Hard blockers — irreversible, externally observable.
    "payment.*": "error",
    "database.delete": "error",
    "database.migrate": "error",
    # Warnings — high impact, sometimes legitimate, sometimes accidental.
    "ai.tool_use": "warning",
    "ai.agent_run": "warning",
    "email.send": "warning",
    "sms.send": "warning",
    "storage.delete": "warning",
    "database.update": "warning",
    # Notes — observability matter, not blockers.
    "ai.completion": "note",
    "ai.embedding": "note",
    "ai.retrieval": "note",
    "filesystem.delete": "note",
    "storage.write": "note",
    "database.create": "note",
    "*": "note",  # catchall
}


@dataclass
class Policy:
    """Capability-glob → SARIF severity mapping with deterministic resolution.

    Resolution: for a given capability_id, all globs that match are
    collected, then sorted by specificity. Most-specific wins. Specificity
    is ``(fewer "*" chars, longer pattern, alphabetical)`` — the rule a
    human would naturally write also wins.

    ``Policy(rules={})`` is allowed and yields ``"note"`` for everything
    (acts as a "report but don't block" policy).
    """

    rules: dict[str, str] = field(default_factory=dict)

    @classmethod
    def default(cls) -> Policy:
        return cls(rules=dict(DEFAULT_POLICY))

    @classmethod
    def from_dict(cls, mapping: dict[str, str], *, merge_defaults: bool = True) -> Policy:
        """Build a Policy from a config-loaded dict. Merges over defaults
        unless ``merge_defaults=False`` (explicit operator override)."""
        if merge_defaults:
            merged = dict(DEFAULT_POLICY)
            merged.update(mapping)
            return cls(rules=merged)
        return cls(rules=dict(mapping))

    def severity_for(self, capability_id: str) -> str:
        """Return ``"error" | "warning" | "note"`` for a capability_id."""
        matches = [g for g in self.rules if fnmatch.fnmatchcase(capability_id, g)]
        if not matches:
            return "note"
        matches.sort(key=lambda g: (g.count("*"), -len(g), g))
        return self.rules[matches[0]]


def _apply_policy(candidates: list[Candidate], policy: Policy) -> None:
    """Mutate each candidate's ``severity`` to match the active policy."""
    for c in candidates:
        c.severity = policy.severity_for(c.capability_id)


def _is_test_path(path: str) -> bool:
    """True if the path looks like test code."""
    normalized = "/" + path.replace("\\", "/").lstrip("/") + "/"
    if any(marker in normalized for marker in TEST_PATH_MARKERS):
        return True
    name = os.path.basename(path)
    if name.startswith("test_") or name.endswith("_test.py"):
        return True
    stem, _, _ext = name.rpartition(".")
    return stem.endswith((".test", ".spec"))


def _iter_source_files(root: Path) -> list[Path]:
    """Yield candidate source files under root, skipping vendored junk."""
    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            if ext not in _SOURCE_EXTS:
                continue
            full = Path(dirpath) / fn
            out.append(full)
    return out


def _compile(patterns: list[tuple[str, str, str, str, str, frozenset[str]]]):
    return [(re.compile(pat), kind, cat, cap, conf, exts) for pat, kind, cat, cap, conf, exts in patterns]


def _governed_line_ranges(text: str) -> list[tuple[int, int]]:
    """Return 1-based ``[(start, end), …]`` line ranges that sit inside a
    ``governed_action(...)`` call.

    Tracks paren depth from the opening ``(`` of ``governed_action`` until
    that call's matching ``)``. The lambda / async body of the wrap is
    nested inside those parens, so any candidate on a line in the range
    is "already governed".

    Limitation: paren counting ignores strings and comments. A call site
    that contains an unbalanced paren in a string literal (rare in
    governance-relevant code) could throw the depth off. This is
    documented and considered acceptable for a heuristic.
    """
    lines = text.splitlines()
    ranges: list[tuple[int, int]] = []
    i = 0
    while i < len(lines):
        match = _GOVERNED_CALL_RE.search(lines[i])
        if not match:
            i += 1
            continue
        start_line_idx = i  # 0-based
        # Begin depth tracking at the opening '(' of the matched call.
        pos = match.end() - 1  # index of '('
        depth = 0
        j = i
        closed = False
        while j < len(lines):
            line_j = lines[j]
            k = pos if j == i else 0
            while k < len(line_j):
                ch = line_j[k]
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        closed = True
                        break
                k += 1
            if closed:
                break
            j += 1
        end_line_idx = j if closed else len(lines) - 1
        ranges.append((start_line_idx + 1, end_line_idx + 1))
        i = (end_line_idx + 1) if closed else len(lines)
    return ranges


def _is_governed(line: int, ranges: list[tuple[int, int]]) -> bool:
    """True if ``line`` falls inside any governed-call range."""
    return any(start <= line <= end for start, end in ranges)


# A line is "skippable" when looking backward from a candidate for an
# opt-out directive: blanks, comments, decorators, and the def/class
# signature line don't break the coverage. This is what makes the
# natural pattern work:
#
#     # strix: allow capability=payment.charge reason="…"
#     def legacy_charge():
#         return stripe.Charge.create(...)
#
# The directive sits two structural lines (decorator-style position +
# the `def` line) above the call, but a developer expects it to cover
# the function body.
_STRUCTURAL_LINE_PREFIXES = (
    "def ",
    "async def ",
    "class ",
    "function ",
    "export ",
    "@",
)


def _line_is_skippable(line: str) -> bool:
    """True if ``line`` is structural and doesn't break opt-out coverage."""
    stripped = line.strip()
    if not stripped:
        return True
    if stripped.startswith(("#", "//")):
        return True
    if stripped.startswith(_STRUCTURAL_LINE_PREFIXES):
        return True
    # Closing brackets / continuation lines.
    return stripped in ("):", "}", "{", "{}", "()")


def _parse_opt_outs(text: str) -> dict[int, tuple[str, str]]:
    """Return ``{line_no: (capability_glob, reason)}`` for opt-out directives.

    Coverage is resolved separately by ``_matching_opt_out`` so a single
    directive can cover the first executable line in a function body,
    not just the line immediately following.
    """
    out: dict[int, tuple[str, str]] = {}
    for lineno, line in enumerate(text.splitlines(), start=1):
        m = _OPT_OUT_RE.search(line)
        if m:
            out[lineno] = (m.group(1), m.group(2))
    return out


def _matching_opt_out(
    line: int,
    capability_id: str,
    opt_outs: dict[int, tuple[str, str]],
    text_lines: list[str],
    *,
    lookback: int = 12,
) -> str | None:
    """Return the suppression reason if an opt-out covers this candidate.

    Coverage rules:
    1. Directive on the *same line* as the candidate (end-of-line comment).
    2. Directive on a previous line, with every line between the directive
       and the candidate being "skippable" (blank, comment, decorator,
       def/class signature, closing brace).

    The closest matching directive wins. The first non-skippable, non-
    directive line breaks the coverage chain.
    """
    if line in opt_outs:
        glob_, reason = opt_outs[line]
        if fnmatch.fnmatchcase(capability_id, glob_):
            return reason

    for offset in range(1, lookback + 1):
        prev = line - offset
        if prev < 1:
            break
        if prev in opt_outs:
            glob_, reason = opt_outs[prev]
            if fnmatch.fnmatchcase(capability_id, glob_):
                return reason
            # Closest directive doesn't match this capability — stop.
            break
        prev_idx = prev - 1
        if prev_idx >= len(text_lines):
            break
        if not _line_is_skippable(text_lines[prev_idx]):
            break
    return None


def _path_is_excluded(rel_path: str, patterns: list[str]) -> bool:
    """True if ``rel_path`` matches any glob in ``patterns``.

    Patterns are fnmatch-style. Patterns ending with ``/`` are treated as
    directory-prefix excludes (``tests/`` excludes everything under
    tests/). Patterns containing ``*`` use fnmatch directly.
    """
    normalized = rel_path.replace("\\", "/")
    for pattern in patterns:
        p = pattern.replace("\\", "/")
        if p.endswith("/") and (normalized.startswith(p) or f"/{p}" in f"/{normalized}"):
            return True
        if fnmatch.fnmatchcase(normalized, p):
            return True
        # Also try matching against any suffix path component (so
        # ``tests/*`` matches ``src/tests/foo.py``).
        if "/" in p and fnmatch.fnmatchcase(normalized, f"*/{p}"):
            return True
    return False


def _scan_text(
    text: str,
    rel_path: str,
    compiled,
    *,
    ext: str | None = None,
) -> list[Candidate]:
    """Run compiled patterns over an in-memory text blob.

    Used by ``scan()`` and ``scan_diff()`` so they share one matcher
    instead of duplicating the inner loop.
    """
    if ext is None:
        ext = os.path.splitext(rel_path)[1].lower()
    out: list[Candidate] = []
    governed_ranges = _governed_line_ranges(text)
    opt_outs = _parse_opt_outs(text)
    text_lines = text.splitlines()
    for lineno, line in enumerate(text_lines, start=1):
        for regex, kind, category, capability_id, confidence, exts in compiled:
            if ext not in exts:
                continue
            if regex.search(line):
                reason = _matching_opt_out(lineno, capability_id, opt_outs, text_lines)
                out.append(
                    Candidate(
                        file=rel_path,
                        line=lineno,
                        snippet=line.rstrip(),
                        kind=kind,
                        category=category,
                        capability_id=capability_id,
                        confidence=confidence,
                        governed=_is_governed(lineno, governed_ranges),
                        suppressed=reason is not None,
                        suppressed_reason=reason,
                    )
                )
                break  # one hit per line is enough
    return out


def _rank_and_limit(candidates: list[Candidate], limit: int) -> list[Candidate]:
    confidence_rank = {"high": 0, "medium": 1}
    kind_rank = {"mutation": 0, "ai": 1}
    candidates.sort(
        key=lambda c: (
            confidence_rank.get(c.confidence, 9),
            kind_rank.get(c.kind, 9),
            c.file,
            c.line,
        )
    )
    return candidates[:limit]


def scan(
    root: Path,
    limit: int = 50,
    *,
    include_mutations: bool = True,
    include_ai: bool = False,
    include_deps: bool = False,
    include_governed: bool = True,
    exclude_paths: list[str] | None = None,
    policy: Policy | None = None,
) -> list[Candidate]:
    """Scan ``root`` and return candidates ranked by confidence then path.

    By default returns only mutation candidates (back-compat with the
    /strix-wire skill behavior). Set ``include_ai=True`` to add AI
    surfaces; set ``include_mutations=False`` for AI-only output.

    Set ``include_deps=True`` to also scan dependency manifests
    (``pyproject.toml``, ``requirements*.txt``, ``package.json``) for
    known AI SDK packages — useful for catching transitive AI usage
    where the imports don't appear in your own source.

    By default candidates whose call site appears already wrapped with
    ``governed_action()`` are still returned but marked
    ``governed=True``. Set ``include_governed=False`` to exclude them.

    ``exclude_paths`` is a list of fnmatch-style globs; matching files
    are skipped. ``policy`` controls capability → severity mapping;
    defaults to ``Policy.default()``.
    """
    if not (include_mutations or include_ai or include_deps):
        return []

    excludes = exclude_paths or []
    active_policy = policy or Policy.default()

    patterns: list[tuple[str, str, str, str, str, frozenset[str]]] = []
    if include_mutations:
        patterns.extend(MUTATION_PATTERNS)
    if include_ai:
        patterns.extend(AI_PATTERNS)
    compiled = _compile(patterns)

    candidates: list[Candidate] = []
    if patterns:
        for src in _iter_source_files(root):
            rel = str(src.relative_to(root))
            if _is_test_path(rel):
                continue
            if excludes and _path_is_excluded(rel, excludes):
                continue
            try:
                text = src.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            candidates.extend(_scan_text(text, rel, compiled, ext=src.suffix.lower()))

    if include_deps:
        for c in scan_dependencies(root):
            if not (excludes and _path_is_excluded(c.file, excludes)):
                candidates.append(c)

    if not include_governed:
        candidates = [c for c in candidates if not c.governed]

    _apply_policy(candidates, active_policy)

    return _rank_and_limit(candidates, limit)


def summarize(candidates: list[Candidate]) -> ScanSummary:
    """Roll up a flat candidate list into kind/category/capability counts."""
    summary = ScanSummary(candidates=candidates)
    for c in candidates:
        summary.by_kind[c.kind] = summary.by_kind.get(c.kind, 0) + 1
        summary.by_category[c.category] = summary.by_category.get(c.category, 0) + 1
        summary.by_capability[c.capability_id] = summary.by_capability.get(c.capability_id, 0) + 1
        summary.by_severity[c.severity] = summary.by_severity.get(c.severity, 0) + 1
        if c.governed:
            summary.governed_count += 1
        else:
            summary.ungoverned_count += 1
        if c.suppressed:
            summary.suppressed_count += 1
        # Blocking = ungoverned + unsuppressed + error-severity. This is
        # what ``--fail-on-open`` keys off of.
        if not c.governed and not c.suppressed and c.severity == "error":
            summary.blocking_count += 1
    return summary


def coverage_ratio(summary: ScanSummary) -> float:
    """Return governance coverage: (governed + suppressed) / total.

    Suppressed candidates count as "accepted" because the operator has
    explicitly justified them; they should not penalize the coverage
    metric. Returns 1.0 when no candidates exist (vacuous truth).
    """
    total = summary.governed_count + summary.ungoverned_count
    if total == 0:
        return 1.0
    suppressed_open = sum(1 for c in summary.candidates if c.suppressed and not c.governed)
    accepted = summary.governed_count + suppressed_open
    return min(1.0, accepted / total)


# ---------------------------------------------------------------------------
# Dependency-manifest scanning
# ---------------------------------------------------------------------------

# Known-AI dependency map. Keys are normalized to lowercase with hyphens
# (the PyPI convention) for matching against pyproject / requirements.
# capability_id is the best-guess governance bucket for the package.
PY_AI_DEPS: dict[str, tuple[str, str]] = {
    # Provider SDKs.
    "anthropic": ("ai-dependency", "ai.completion"),
    "openai": ("ai-dependency", "ai.completion"),
    "cohere": ("ai-dependency", "ai.completion"),
    "mistralai": ("ai-dependency", "ai.completion"),
    "groq": ("ai-dependency", "ai.completion"),
    "ollama": ("ai-dependency", "ai.completion"),
    "replicate": ("ai-dependency", "ai.completion"),
    "google-generativeai": ("ai-dependency", "ai.completion"),
    "google-genai": ("ai-dependency", "ai.completion"),
    "vertexai": ("ai-dependency", "ai.completion"),
    "litellm": ("ai-dependency", "ai.completion"),
    "huggingface-hub": ("ai-dependency", "ai.completion"),
    "transformers": ("ai-dependency", "ai.completion"),
    # LangChain family.
    "langchain": ("ai-dependency", "ai.completion"),
    "langchain-core": ("ai-dependency", "ai.completion"),
    "langchain-community": ("ai-dependency", "ai.completion"),
    "langchain-anthropic": ("ai-dependency", "ai.completion"),
    "langchain-openai": ("ai-dependency", "ai.completion"),
    "langchain-google-genai": ("ai-dependency", "ai.completion"),
    # Agent frameworks.
    "langgraph": ("ai-dependency", "ai.agent_run"),
    "llama-index": ("ai-dependency", "ai.agent_run"),
    "llamaindex": ("ai-dependency", "ai.agent_run"),
    "crewai": ("ai-dependency", "ai.agent_run"),
    "autogen": ("ai-dependency", "ai.agent_run"),
    "pyautogen": ("ai-dependency", "ai.agent_run"),
    "autogen-agentchat": ("ai-dependency", "ai.agent_run"),
    "smolagents": ("ai-dependency", "ai.agent_run"),
    "claude-agent-sdk": ("ai-dependency", "ai.agent_run"),
    "instructor": ("ai-dependency", "ai.completion"),
    "dspy-ai": ("ai-dependency", "ai.completion"),
    "guidance": ("ai-dependency", "ai.completion"),
    "outlines": ("ai-dependency", "ai.completion"),
    # MCP / tool-use.
    "mcp": ("ai-dependency", "ai.tool_use"),
    "fastmcp": ("ai-dependency", "ai.tool_use"),
    # Vector / retrieval.
    "pinecone-client": ("ai-dependency", "ai.retrieval"),
    "pinecone": ("ai-dependency", "ai.retrieval"),
    "chromadb": ("ai-dependency", "ai.retrieval"),
    "weaviate-client": ("ai-dependency", "ai.retrieval"),
    "qdrant-client": ("ai-dependency", "ai.retrieval"),
    "faiss-cpu": ("ai-dependency", "ai.retrieval"),
    "faiss-gpu": ("ai-dependency", "ai.retrieval"),
    "sentence-transformers": ("ai-dependency", "ai.embedding"),
}

JS_AI_DEPS: dict[str, tuple[str, str]] = {
    # Provider SDKs.
    "@anthropic-ai/sdk": ("ai-dependency", "ai.completion"),
    "@anthropic-ai/bedrock-sdk": ("ai-dependency", "ai.completion"),
    "@anthropic-ai/vertex-sdk": ("ai-dependency", "ai.completion"),
    "openai": ("ai-dependency", "ai.completion"),
    "ai": ("ai-dependency", "ai.completion"),
    "@ai-sdk/anthropic": ("ai-dependency", "ai.completion"),
    "@ai-sdk/openai": ("ai-dependency", "ai.completion"),
    "@ai-sdk/google": ("ai-dependency", "ai.completion"),
    "@ai-sdk/mistral": ("ai-dependency", "ai.completion"),
    "cohere-ai": ("ai-dependency", "ai.completion"),
    "@google/generative-ai": ("ai-dependency", "ai.completion"),
    "@google-cloud/vertexai": ("ai-dependency", "ai.completion"),
    "@mistralai/mistralai": ("ai-dependency", "ai.completion"),
    "mistralai": ("ai-dependency", "ai.completion"),
    "groq-sdk": ("ai-dependency", "ai.completion"),
    "ollama": ("ai-dependency", "ai.completion"),
    "replicate": ("ai-dependency", "ai.completion"),
    # LangChain family.
    "langchain": ("ai-dependency", "ai.completion"),
    "@langchain/core": ("ai-dependency", "ai.completion"),
    "@langchain/anthropic": ("ai-dependency", "ai.completion"),
    "@langchain/openai": ("ai-dependency", "ai.completion"),
    "@langchain/community": ("ai-dependency", "ai.completion"),
    # Agent frameworks.
    "@anthropic-ai/agent-sdk": ("ai-dependency", "ai.agent_run"),
    "@langchain/langgraph": ("ai-dependency", "ai.agent_run"),
    "langgraph": ("ai-dependency", "ai.agent_run"),
    "crewai": ("ai-dependency", "ai.agent_run"),
    "llamaindex": ("ai-dependency", "ai.agent_run"),
    # MCP.
    "@modelcontextprotocol/sdk": ("ai-dependency", "ai.tool_use"),
    # Vector / retrieval.
    "@pinecone-database/pinecone": ("ai-dependency", "ai.retrieval"),
    "chromadb": ("ai-dependency", "ai.retrieval"),
    "weaviate-ts-client": ("ai-dependency", "ai.retrieval"),
    "weaviate-client": ("ai-dependency", "ai.retrieval"),
    "@qdrant/js-client-rest": ("ai-dependency", "ai.retrieval"),
    "@qdrant/qdrant-js": ("ai-dependency", "ai.retrieval"),
}


def _normalize_pkg_name(name: str) -> str:
    return name.strip().lower().replace("_", "-")


_PEP508_NAME_RE = re.compile(r"^\s*([A-Za-z0-9_][A-Za-z0-9_\-.]*)")


def _spec_to_name(spec: str) -> str | None:
    """Parse a PEP 508 spec like ``anthropic>=0.40`` to ``anthropic``."""
    if not isinstance(spec, str):
        return None
    m = _PEP508_NAME_RE.match(spec)
    if not m:
        return None
    return _normalize_pkg_name(m.group(1))


def _find_name_line(text_lines: list[str], name: str, *, quoted: bool = False) -> int:
    """Return the 1-based line where ``name`` first appears as a token.

    Both ``_`` and ``-`` variants of the name match (PEP 503 normalization).
    """
    needle = _normalize_pkg_name(name)
    # Match name as a word, optionally inside quotes — case-insensitive,
    # _ and - are interchangeable.
    pattern = re.compile(
        r"['\"]?\b" + re.escape(needle).replace(r"\-", r"[-_]") + r"\b['\"]?",
        re.IGNORECASE,
    )
    for i, line in enumerate(text_lines, start=1):
        normalized = line.replace("_", "-")
        if pattern.search(normalized):
            return i
    return 1


def _parse_pyproject_deps(path: Path) -> list[tuple[str, int]]:
    """Return ``[(normalized_name, line_no), …]`` from a ``pyproject.toml``."""
    try:
        if sys.version_info >= (3, 11):
            import tomllib
        else:
            import tomli as tomllib
    except ImportError:  # pragma: no cover
        return []

    try:
        text = path.read_text(encoding="utf-8")
        data = tomllib.loads(text)
    except (OSError, Exception):
        return []

    names: set[str] = set()

    project = data.get("project", {}) if isinstance(data, dict) else {}
    if isinstance(project, dict):
        for spec in project.get("dependencies", []) or []:
            n = _spec_to_name(spec)
            if n:
                names.add(n)
        opt = project.get("optional-dependencies", {}) or {}
        if isinstance(opt, dict):
            for specs in opt.values():
                for spec in specs or []:
                    n = _spec_to_name(spec)
                    if n:
                        names.add(n)

    # Poetry-style.
    poetry = data.get("tool", {}).get("poetry", {}) if isinstance(data, dict) else {}
    if isinstance(poetry, dict):
        for key in ("dependencies", "dev-dependencies"):
            block = poetry.get(key, {}) or {}
            if isinstance(block, dict):
                for n in block:
                    if n and n.lower() != "python":
                        names.add(_normalize_pkg_name(n))

    lines = text.splitlines()
    return [(n, _find_name_line(lines, n)) for n in sorted(names)]


def _parse_requirements_txt(path: Path) -> list[tuple[str, int]]:
    """Return ``[(normalized_name, line_no), …]`` from a ``requirements*.txt``."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    out: list[tuple[str, int]] = []
    for i, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        n = _spec_to_name(line)
        if n:
            out.append((n, i))
    return out


def _parse_package_json(path: Path) -> list[tuple[str, int]]:
    """Return ``[(name, line_no), …]`` from a ``package.json``."""
    try:
        text = path.read_text(encoding="utf-8")
        data = json.loads(text)
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, dict):
        return []
    names: set[str] = set()
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        block = data.get(key, {})
        if isinstance(block, dict):
            for name in block:
                if isinstance(name, str):
                    names.add(name)
    lines = text.splitlines()
    return [(n, _find_name_line(lines, n)) for n in sorted(names)]


def scan_dependencies(root: Path) -> list[Candidate]:
    """Scan dependency manifests under ``root`` for known AI SDK packages.

    Walks ``pyproject.toml``, ``requirements*.txt``, and ``package.json``
    files (the manifest is in the repo root or a direct subdirectory of
    the root — we don't recurse into vendored junk). Each known AI
    package becomes a ``Candidate`` with ``category="ai-dependency"``.
    """
    out: list[Candidate] = []

    for manifest_name, parser, dep_map in (
        ("pyproject.toml", _parse_pyproject_deps, PY_AI_DEPS),
        ("package.json", _parse_package_json, JS_AI_DEPS),
    ):
        manifest = root / manifest_name
        if not manifest.is_file():
            continue
        rel = manifest_name
        for name, line in parser(manifest):
            if name in dep_map:
                category, capability_id = dep_map[name]
                out.append(
                    Candidate(
                        file=rel,
                        line=line,
                        snippet=name,
                        kind="ai",
                        category=category,
                        capability_id=capability_id,
                        confidence="high",
                    )
                )

    # requirements*.txt — multiple variants may exist.
    for req in sorted(root.glob("requirements*.txt")):
        rel = req.name
        for name, line in _parse_requirements_txt(req):
            if name in PY_AI_DEPS:
                category, capability_id = PY_AI_DEPS[name]
                out.append(
                    Candidate(
                        file=rel,
                        line=line,
                        snippet=name,
                        kind="ai",
                        category=category,
                        capability_id=capability_id,
                        confidence="high",
                    )
                )

    return out


# ---------------------------------------------------------------------------
# Diff-since-baseline (catch newly-introduced action points)
# ---------------------------------------------------------------------------


def _git_changed_files(root: Path, since_ref: str) -> list[str]:
    """Return paths changed (Added/Modified/Renamed) since ``since_ref``."""
    result = subprocess.run(
        [
            "git",
            "diff",
            "--name-only",
            "--diff-filter=AMR",
            f"{since_ref}...HEAD",
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        stderr = result.stderr.strip()
        # Friendly hint for the common pre-commit failure mode: the user
        # is running the hook in a repo that hasn't fetched the base ref.
        if "ambiguous argument" in stderr or "unknown revision" in stderr:
            hint = (
                f"Couldn't resolve git ref {since_ref!r}. "
                f"Try `git fetch origin {since_ref.removeprefix('origin/')}` first, "
                f"or pass a ref that exists locally (e.g. `--since HEAD~1`). "
                f"Underlying error: {stderr}"
            )
            raise RuntimeError(hint)
        raise RuntimeError(f"git diff failed: {stderr}")
    return [ln.strip() for ln in result.stdout.splitlines() if ln.strip()]


def _git_show(root: Path, ref: str, path: str) -> str | None:
    """Return file contents at ``ref:path``, or None if the file didn't exist."""
    result = subprocess.run(
        ["git", "show", f"{ref}:{path}"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    return result.stdout


def scan_diff(
    root: Path,
    since_ref: str,
    *,
    include_mutations: bool = True,
    include_ai: bool = False,
    include_deps: bool = False,
    include_governed: bool = True,
    exclude_paths: list[str] | None = None,
    policy: Policy | None = None,
    limit: int = 100,
) -> list[Candidate]:
    """Return candidates that exist in HEAD but not at ``since_ref``.

    Useful in PRs: ``solo govern scan --since main`` surfaces only
    action points introduced by the current branch.

    Implementation: list files changed since ``since_ref``, scan each
    in both versions, and return the set difference on
    ``(file, capability_id, snippet)``.
    """
    if not (include_mutations or include_ai or include_deps):
        return []

    changed = set(_git_changed_files(root, since_ref))
    if not changed:
        return []

    excludes = exclude_paths or []
    active_policy = policy or Policy.default()

    patterns: list[tuple[str, str, str, str, str, frozenset[str]]] = []
    if include_mutations:
        patterns.extend(MUTATION_PATTERNS)
    if include_ai:
        patterns.extend(AI_PATTERNS)
    compiled = _compile(patterns)

    # Head candidates from the working tree, restricted to changed files
    # (manifests included).
    head_candidates: list[Candidate] = []
    if patterns:
        for src in _iter_source_files(root):
            rel = str(src.relative_to(root))
            if _is_test_path(rel):
                continue
            if rel not in changed:
                continue
            if excludes and _path_is_excluded(rel, excludes):
                continue
            try:
                text = src.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            head_candidates.extend(_scan_text(text, rel, compiled, ext=src.suffix.lower()))

    if include_deps:
        for c in scan_dependencies(root):
            if c.file not in changed:
                continue
            if excludes and _path_is_excluded(c.file, excludes):
                continue
            head_candidates.append(c)

    # Build the REF baseline set: scan the REF version of each changed file.
    ref_signatures: set[tuple[str, str, str]] = set()
    for rel in changed:
        ref_text = _git_show(root, since_ref, rel)
        if ref_text is None:
            continue
        ext = os.path.splitext(rel)[1].lower()
        if rel.endswith(("pyproject.toml", "package.json")) or rel.endswith(".txt"):
            # Dep manifest in REF — scan its dep list.
            ref_deps = _ref_dep_candidates(rel, ref_text)
            for c in ref_deps:
                ref_signatures.add((c.file, c.capability_id, c.snippet))
            continue
        if ext not in _SOURCE_EXTS:
            continue
        for c in _scan_text(ref_text, rel, compiled, ext=ext):
            ref_signatures.add((c.file, c.capability_id, c.snippet.strip()))

    new_only = [
        c for c in head_candidates if (c.file, c.capability_id, c.snippet.strip()) not in ref_signatures
    ]

    if not include_governed:
        new_only = [c for c in new_only if not c.governed]

    _apply_policy(new_only, active_policy)

    return _rank_and_limit(new_only, limit)


def _ref_dep_candidates(rel: str, text: str) -> list[Candidate]:
    """Parse a manifest's text content (from ``git show``) and yield deps."""
    out: list[Candidate] = []

    def _emit(name: str, line: int, dep_map: dict[str, tuple[str, str]]) -> None:
        if name in dep_map:
            category, capability_id = dep_map[name]
            out.append(
                Candidate(
                    file=rel,
                    line=line,
                    snippet=name,
                    kind="ai",
                    category=category,
                    capability_id=capability_id,
                    confidence="high",
                )
            )

    if rel.endswith("pyproject.toml"):
        try:
            if sys.version_info >= (3, 11):
                import tomllib
            else:
                import tomli as tomllib
            data = tomllib.loads(text)
        except Exception:
            return []
        names: set[str] = set()
        project = data.get("project", {}) if isinstance(data, dict) else {}
        for spec in project.get("dependencies", []) or []:
            n = _spec_to_name(spec)
            if n:
                names.add(n)
        for specs in (project.get("optional-dependencies", {}) or {}).values():
            for spec in specs or []:
                n = _spec_to_name(spec)
                if n:
                    names.add(n)
        poetry = data.get("tool", {}).get("poetry", {}) if isinstance(data, dict) else {}
        if isinstance(poetry, dict):
            for key in ("dependencies", "dev-dependencies"):
                block = poetry.get(key, {}) or {}
                if isinstance(block, dict):
                    for n in block:
                        if n and n.lower() != "python":
                            names.add(_normalize_pkg_name(n))
        lines = text.splitlines()
        for n in sorted(names):
            _emit(n, _find_name_line(lines, n), PY_AI_DEPS)
        return out

    if rel.endswith("package.json"):
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return []
        if not isinstance(data, dict):
            return []
        names = set()
        for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            block = data.get(key, {})
            if isinstance(block, dict):
                for name in block:
                    if isinstance(name, str):
                        names.add(name)
        lines = text.splitlines()
        for n in sorted(names):
            _emit(n, _find_name_line(lines, n), JS_AI_DEPS)
        return out

    if rel.endswith(".txt") and "requirements" in os.path.basename(rel):
        for i, raw in enumerate(text.splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            n = _spec_to_name(line)
            if n:
                _emit(n, i, PY_AI_DEPS)
        return out

    return out


# ---------------------------------------------------------------------------
# SARIF v2.1.0 emitter
# ---------------------------------------------------------------------------

# Project metadata embedded in the SARIF driver block. ``version`` is
# best-effort; if importing the package version fails we fall back to a
# sentinel so the SARIF still validates.
_TOOL_NAME = "solo-govern"
_TOOL_INFORMATION_URI = "https://github.com/Tarshann/solo-builder-core"
_SARIF_SCHEMA_URI = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)


def _tool_version() -> str:
    try:
        from solo_builder import __version__

        return str(__version__)
    except Exception:  # pragma: no cover — never crash SARIF on metadata
        return "0.0.0"


def _fingerprint(c: Candidate) -> str:
    """Stable fingerprint for SARIF dedup across re-runs."""
    payload = f"{c.file}|{c.capability_id}|{c.snippet.strip()}".encode()
    return hashlib.sha256(payload).hexdigest()[:16]


def _rule_descriptor(capability_id: str, severity: str, kind: str) -> dict:
    """Build a SARIF reporting-descriptor for a capability_id."""
    return {
        "id": capability_id,
        "name": capability_id.replace(".", "_").replace("-", "_"),
        "shortDescription": {
            "text": f"{capability_id} action point ({kind})",
        },
        "fullDescription": {
            "text": (
                f"Call site matching the Strix governance capability "
                f"'{capability_id}'. Wrap with governed_action(...) to "
                f"produce a verifiable evidence record on every "
                f"invocation."
            ),
        },
        "helpUri": f"{_TOOL_INFORMATION_URI}#capability-{capability_id}",
        "defaultConfiguration": {"level": severity},
    }


def to_sarif(candidates: list[Candidate], *, repo_uri: str | None = None) -> dict:
    """Render a SARIF v2.1.0 document for ``candidates``.

    Each candidate becomes one ``result`` whose ``ruleId`` is its
    ``capability_id``. Suppressed candidates carry a ``suppressions`` array
    per SARIF spec, which GitHub Code Scanning and most other consumers
    use to hide them from the default view.
    """
    # One rule descriptor per unique capability_id seen.
    by_cap: dict[str, Candidate] = {}
    for c in candidates:
        if c.capability_id not in by_cap:
            by_cap[c.capability_id] = c
    rules = [_rule_descriptor(c.capability_id, c.severity, c.kind) for c in by_cap.values()]

    results = []
    for c in candidates:
        result: dict = {
            "ruleId": c.capability_id,
            "level": c.severity,
            "message": {
                "text": (
                    f"Ungoverned {c.capability_id} action point"
                    if not c.governed
                    else f"{c.capability_id} action point (governed)"
                ),
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": c.file},
                        "region": {
                            "startLine": c.line,
                            "snippet": {"text": c.snippet.strip()},
                        },
                    }
                }
            ],
            "partialFingerprints": {"strixActionPoint/v1": _fingerprint(c)},
            "properties": {
                "capability_id": c.capability_id,
                "kind": c.kind,
                "category": c.category,
                "confidence": c.confidence,
                "governed": c.governed,
            },
        }
        if c.suppressed:
            result["suppressions"] = [
                {
                    "kind": "inSource",
                    "justification": c.suppressed_reason or "(no reason given)",
                }
            ]
        results.append(result)

    run: dict = {
        "tool": {
            "driver": {
                "name": _TOOL_NAME,
                "version": _tool_version(),
                "informationUri": _TOOL_INFORMATION_URI,
                "rules": rules,
            }
        },
        "results": results,
    }
    if repo_uri:
        run["versionControlProvenance"] = [{"repositoryUri": repo_uri}]

    return {
        "$schema": _SARIF_SCHEMA_URI,
        "version": "2.1.0",
        "runs": [run],
    }


# ---------------------------------------------------------------------------
# Markdown report (used by `solo govern scan --format markdown` and the
# GitHub Action's sticky PR comment).
# ---------------------------------------------------------------------------

_SEVERITY_BADGE = {
    "error": "🔴 error",
    "warning": "🟡 warning",
    "note": "🔵 note",
}


def _md_escape_pipe(text: str) -> str:
    """Escape `|` characters that would break a markdown table cell."""
    return text.replace("|", "\\|")


def _md_snippet(snippet: str, max_len: int = 80) -> str:
    """Render a code snippet for a markdown table cell."""
    s = snippet.strip()
    if len(s) > max_len:
        s = s[: max_len - 1] + "…"
    return f"`{_md_escape_pipe(s)}`"


def to_markdown(
    candidates: list[Candidate],
    *,
    title: str = "Strix Governance",
    since_ref: str | None = None,
    repo_name: str | None = None,
    sha: str | None = None,
    max_rows_per_table: int = 25,
) -> str:
    """Render a PR-comment-ready markdown report.

    Surfaces three tables: open (ungoverned, unsuppressed), governed,
    and suppressed. Each table caps at ``max_rows_per_table`` rows; the
    SARIF / JSON outputs carry the full list for tools that need it.
    """
    summary = summarize(candidates)
    coverage = coverage_ratio(summary)

    parts: list[str] = []
    repo_label = f" — `{repo_name}`" if repo_name else ""
    parts.append(f"## 🔒 {title}{repo_label}")
    parts.append("")

    if not candidates:
        scope = f" since `{since_ref}`" if since_ref else ""
        parts.append(f"✅ No action points found{scope}.")
        if sha:
            parts.append("")
            parts.append(f"<sub>Scanned at commit `{sha[:7]}`.</sub>")
        return "\n".join(parts) + "\n"

    headline_bits = [
        f"**Total:** {len(candidates)}",
        f"**Coverage:** {coverage:.1%}",
        f"**Blocking:** {summary.blocking_count}",
        f"**Governed:** {summary.governed_count}",
        f"**Suppressed:** {summary.suppressed_count}",
    ]
    if since_ref:
        headline_bits.append(f"_diff since `{since_ref}`_")
    parts.append(" · ".join(headline_bits))
    parts.append("")

    open_rows = [c for c in candidates if not c.governed and not c.suppressed]
    governed_rows = [c for c in candidates if c.governed]
    suppressed_rows = [c for c in candidates if c.suppressed]

    if open_rows:
        # Sort by severity (error first), then file, then line.
        sev_order = {"error": 0, "warning": 1, "note": 2}
        open_rows.sort(key=lambda c: (sev_order.get(c.severity, 9), c.file, c.line))
        parts.append(f"### Open action points ({len(open_rows)})")
        parts.append("")
        parts.append("| Severity | File | Line | Capability | Snippet |")
        parts.append("|---|---|---|---|---|")
        for c in open_rows[:max_rows_per_table]:
            parts.append(
                f"| {_SEVERITY_BADGE.get(c.severity, c.severity)} "
                f"| `{_md_escape_pipe(c.file)}` "
                f"| {c.line} "
                f"| `{c.capability_id}` "
                f"| {_md_snippet(c.snippet)} |"
            )
        if len(open_rows) > max_rows_per_table:
            parts.append("")
            parts.append(
                f"_…and {len(open_rows) - max_rows_per_table} more (see SARIF / JSON for the full list)._"
            )
        parts.append("")

    if governed_rows:
        parts.append(f"<details><summary>Already governed ({len(governed_rows)})</summary>")
        parts.append("")
        parts.append("| File | Line | Capability |")
        parts.append("|---|---|---|")
        for c in governed_rows[:max_rows_per_table]:
            parts.append(f"| `{_md_escape_pipe(c.file)}` | {c.line} | `{c.capability_id}` |")
        if len(governed_rows) > max_rows_per_table:
            parts.append("")
            parts.append(f"_…and {len(governed_rows) - max_rows_per_table} more._")
        parts.append("")
        parts.append("</details>")
        parts.append("")

    if suppressed_rows:
        parts.append(
            f"<details><summary>Suppressed via <code># strix: allow</code> ({len(suppressed_rows)})</summary>"
        )
        parts.append("")
        parts.append("| File | Line | Capability | Reason |")
        parts.append("|---|---|---|---|")
        for c in suppressed_rows[:max_rows_per_table]:
            reason = (c.suppressed_reason or "")[:80]
            parts.append(
                f"| `{_md_escape_pipe(c.file)}` "
                f"| {c.line} "
                f"| `{c.capability_id}` "
                f"| {_md_escape_pipe(reason)} |"
            )
        parts.append("")
        parts.append("</details>")
        parts.append("")

    foot_bits = []
    if sha:
        foot_bits.append(f"commit `{sha[:7]}`")
    foot_bits.append("policy: `.solo.toml [govern.policy]`")
    parts.append(f"<sub>Scanned by `solo govern scan` · {' · '.join(foot_bits)}.</sub>")

    return "\n".join(parts) + "\n"


# ---------------------------------------------------------------------------
# Standalone CLI (also reachable as `python -m solo_builder.action_scanner`)
# ---------------------------------------------------------------------------


def _format_human(candidates: list[Candidate]) -> str:
    if not candidates:
        return (
            "No action-point candidates found.\n"
            "Mutation patterns: payments, db deletes, s3 deletes, email/SMS,\n"
            "filesystem deletes, schema migrations.\n"
            "AI patterns (--include-ai): provider calls, tool-use, agent\n"
            "frameworks, RAG/retrieval.\n"
            "If you have a specific function in mind, point me at it."
        )
    lines = []
    for i, c in enumerate(candidates, start=1):
        if c.suppressed:
            tag = "suppressed"
        elif c.governed:
            tag = "governed"
        else:
            tag = "open"
        lines.append(
            f"{i}. [{c.severity}/{c.kind}/{tag}] {c.file}:{c.line}  ({c.capability_id})\n"
            f"   {c.snippet.strip()}"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=("Scan for governance-relevant action points (irreversible mutations and AI surfaces).")
    )
    parser.add_argument("--root", default=".", help="Repository root to scan (default: cwd).")
    parser.add_argument(
        "--format",
        choices=["text", "json", "sarif", "markdown"],
        default="text",
        help="Output format (default: text).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Shortcut for --format json (preserved for back-compat).",
    )
    parser.add_argument("--limit", type=int, default=50, help="Maximum candidates to return (default: 50).")
    parser.add_argument(
        "--include-ai",
        action="store_true",
        help="Include AI surfaces (provider calls, tool-use, agent frameworks, retrieval).",
    )
    parser.add_argument(
        "--only-ai",
        action="store_true",
        help="Only AI surfaces — exclude mutation patterns.",
    )
    parser.add_argument(
        "--include-deps",
        action="store_true",
        help="Also scan pyproject.toml / requirements*.txt / package.json for AI SDK packages.",
    )
    parser.add_argument(
        "--exclude-governed",
        action="store_true",
        help="Exclude candidates whose call site appears already wrapped with governed_action().",
    )
    parser.add_argument(
        "--exclude-paths",
        nargs="+",
        default=None,
        metavar="GLOB",
        help="One or more fnmatch globs; matching files are skipped.",
    )
    parser.add_argument(
        "--since",
        metavar="REF",
        help="Diff mode: return only candidates introduced since git REF (e.g. 'main').",
    )
    parser.add_argument(
        "--fail-on-open",
        action="store_true",
        help="Exit non-zero (5) if any error-severity ungoverned candidate is in scope.",
    )
    parser.add_argument(
        "--min-governed-ratio",
        type=float,
        default=None,
        metavar="N",
        help="Exit non-zero (6) if (governed+suppressed)/total < N. Range [0.0, 1.0].",
    )
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    if not root.is_dir():
        print(f"error: --root {root} is not a directory", file=sys.stderr)
        return 3

    include_mutations = not args.only_ai
    include_ai = args.include_ai or args.only_ai
    output_format = "json" if args.json else args.format

    if args.since:
        try:
            candidates = scan_diff(
                root,
                args.since,
                limit=args.limit,
                include_mutations=include_mutations,
                include_ai=include_ai,
                include_deps=args.include_deps,
                include_governed=not args.exclude_governed,
                exclude_paths=args.exclude_paths,
            )
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 4
    else:
        candidates = scan(
            root,
            limit=args.limit,
            include_mutations=include_mutations,
            include_ai=include_ai,
            include_deps=args.include_deps,
            include_governed=not args.exclude_governed,
            exclude_paths=args.exclude_paths,
        )

    if output_format == "sarif":
        print(json.dumps(to_sarif(candidates), indent=2))
    elif output_format == "markdown":
        print(to_markdown(candidates, since_ref=args.since))
    elif output_format == "json":
        print(json.dumps([asdict(c) for c in candidates], indent=2))
    else:
        print(_format_human(candidates))

    summary = summarize(candidates)
    if args.fail_on_open and summary.blocking_count > 0:
        return 5
    if args.min_governed_ratio is not None and coverage_ratio(summary) < args.min_governed_ratio:
        return 6
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

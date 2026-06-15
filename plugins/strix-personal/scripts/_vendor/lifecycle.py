"""The Strix Personal action lifecycle: DETECTED → … → VERIFIED.

The load-bearing rule (mirrors the type-disjointness discipline in ADR-009 /
ADR-010): a ``ScanReport`` is **not** evidence. It carries no ``record_hash``,
``chain_seq``, or ``prev_hash``, and it cannot promote a candidate past
``WRAPPED`` from scan data alone. ``TESTED`` / ``ENFORCED`` / ``VERIFIED`` each
require an explicit runtime signal. This is the structural form of "never
convert detected directly into governed."

This module is vendored byte-for-byte into the ``strix-personal`` plugin, so
the scanner import uses a dual path: the installed package when available, the
vendored sibling otherwise. Do not collapse the ``try/except`` — it is what
lets one file serve both locations.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields
from enum import Enum

try:  # installed package
    from solo_builder.action_scanner import Candidate, scan
except ImportError:  # vendored standalone (plugin scripts/_vendor/)
    from action_scanner import Candidate, scan  # type: ignore


class LifecycleError(RuntimeError):
    """Raised on an illegal state transition (e.g. DETECTED → VERIFIED)."""


class ActionState(str, Enum):
    """Where a single action point sits on the road to governance."""

    DETECTED = "detected"
    WRAPPABLE = "wrappable"
    WRAPPED = "wrapped"
    TESTED = "tested"
    ENFORCED = "enforced"
    VERIFIED = "verified"
    SUPPRESSED = "suppressed"


# The main progression. SUPPRESSED is a terminal off-ramp, not on this line.
_PROGRESSION: list[ActionState] = [
    ActionState.DETECTED,
    ActionState.WRAPPABLE,
    ActionState.WRAPPED,
    ActionState.TESTED,
    ActionState.ENFORCED,
    ActionState.VERIFIED,
]
_RANK: dict[ActionState, int] = {s: i for i, s in enumerate(_PROGRESSION)}

# States that may ONLY be entered with a matching runtime signal. This is the
# barrier that stops scan data from manufacturing a "governed" verdict.
_SIGNAL_KIND_FOR: dict[ActionState, str] = {
    ActionState.TESTED: "test",
    ActionState.ENFORCED: "bypass",
    ActionState.VERIFIED: "evidence",
}

# The minimum state a candidate must already hold before it may enter a given
# state. This is what makes "never convert detected directly into governed"
# structural: you cannot reach VERIFIED unless you are already ENFORCED, and a
# signal alone never lets a DETECTED candidate leap the whole chain.
_MIN_PRECURSOR: dict[ActionState, ActionState] = {
    ActionState.TESTED: ActionState.WRAPPED,
    ActionState.ENFORCED: ActionState.WRAPPED,
    ActionState.VERIFIED: ActionState.ENFORCED,
}

# The furthest a candidate can be placed from static scan information alone.
MAX_STATIC_STATE = ActionState.WRAPPED


@dataclass(frozen=True)
class RuntimeSignal:
    """An out-of-band fact that justifies advancing past WRAPPED.

    ``kind`` is one of ``"test"`` (a deny/approval scenario passed),
    ``"bypass"`` (the boundary-routing check passed — no sibling unwrapped
    call), or ``"evidence"`` (a real signed record was produced).
    """

    kind: str
    passed: bool = True
    evidence_id: str | None = None
    detail: str | None = None


def _is_wrappable(candidate: Candidate) -> bool:
    """True if a candidate is a recognized, mechanically-wrappable call site.

    Dependency-manifest candidates (``category == "ai-dependency"``) are
    informational only — there is no call site to wrap — so they stay
    DETECTED.
    """
    return candidate.kind in ("mutation", "ai") and candidate.category != "ai-dependency"


def initial_state(candidate: Candidate) -> ActionState:
    """Resolve a candidate's starting lifecycle state from static scan data.

    Never returns anything past ``WRAPPED`` — runtime promotion is required
    for TESTED / ENFORCED / VERIFIED.
    """
    if candidate.suppressed:
        return ActionState.SUPPRESSED
    if candidate.governed:
        return ActionState.WRAPPED
    if _is_wrappable(candidate):
        return ActionState.WRAPPABLE
    return ActionState.DETECTED


@dataclass
class LifecycleEntry:
    """One action point and its current lifecycle state.

    Intentionally NOT evidence-shaped: no ``record_hash`` / ``chain_seq`` /
    ``prev_hash``. ``dataclasses.asdict()`` on this can never be mistaken for
    an authoritative evidence row.
    """

    candidate: Candidate
    state: ActionState
    evidence_id: str | None = None
    history: list[tuple[str, str]] = field(default_factory=list)

    @classmethod
    def detect(cls, candidate: Candidate) -> LifecycleEntry:
        st = initial_state(candidate)
        return cls(candidate=candidate, state=st, history=[(st.value, "detected by scanner")])

    @property
    def capability_id(self) -> str:
        return self.candidate.capability_id

    @property
    def location(self) -> str:
        return f"{self.candidate.file}:{self.candidate.line}"

    @property
    def is_governed(self) -> bool:
        """True once the candidate is at least WRAPPED, or operator-suppressed."""
        if self.state == ActionState.SUPPRESSED:
            return True
        return _RANK.get(self.state, -1) >= _RANK[ActionState.WRAPPED]


def promote(
    entry: LifecycleEntry,
    target: ActionState,
    *,
    signal: RuntimeSignal | None = None,
    reason: str = "",
) -> LifecycleEntry:
    """Advance ``entry`` to ``target``, enforcing the transition rules.

    Rules:
      * Movement is forward-only along the progression (no silent downgrade).
      * SUPPRESSED may be entered from any non-terminal progression state.
      * TESTED / ENFORCED / VERIFIED require a matching, passing ``signal``;
        VERIFIED additionally requires an ``evidence_id``.

    Raises ``LifecycleError`` on any illegal transition. Mutates and returns
    ``entry`` for convenience.
    """
    current = entry.state

    if target == current:
        return entry

    if target == ActionState.SUPPRESSED:
        if current in (ActionState.VERIFIED, ActionState.SUPPRESSED):
            raise LifecycleError(f"cannot suppress from terminal state {current.value}")
        entry.state = target
        entry.history.append((target.value, reason or "operator suppressed"))
        return entry

    if current == ActionState.SUPPRESSED:
        raise LifecycleError("a suppressed action cannot re-enter the progression")

    if target not in _RANK:
        raise LifecycleError(f"unknown target state {target!r}")

    if _RANK[target] <= _RANK[current]:
        raise LifecycleError(
            f"illegal transition {current.value} → {target.value} (lifecycle is forward-only)"
        )

    precursor = _MIN_PRECURSOR.get(target)
    if precursor is not None and _RANK[current] < _RANK[precursor]:
        raise LifecycleError(
            f"cannot reach {target.value} from {current.value}: "
            f"must be at least {precursor.value} first "
            "(no leaping the lifecycle on a signal alone)"
        )

    required_kind = _SIGNAL_KIND_FOR.get(target)
    if required_kind is not None:
        if signal is None or signal.kind != required_kind or not signal.passed:
            raise LifecycleError(
                f"{target.value} requires a passing {required_kind!r} signal "
                f"(refusing to promote {entry.location} on scan data alone)"
            )
        if target == ActionState.VERIFIED:
            ev = signal.evidence_id
            if not ev:
                raise LifecycleError("VERIFIED requires a non-empty evidence_id")
            entry.evidence_id = ev

    entry.state = target
    detail = reason or (signal.detail if signal else "") or "promoted"
    entry.history.append((target.value, detail))
    return entry


# Severity badges reused from the scanner's vocabulary.
_SEVERITY_BADGE = {"error": "\U0001f534 error", "warning": "\U0001f7e1 warning", "note": "\U0001f535 note"}


@dataclass
class ScanReport:
    """A lifecycle view over a set of scanned action points.

    DELIBERATELY type-disjoint from evidence: this dataclass declares no
    ``record_hash`` / ``chain_seq`` / ``prev_hash`` field. The invariant is
    asserted in ``tests/test_strix_personal_lifecycle.py`` so a future field
    addition that would let a report impersonate evidence fails the build.
    """

    entries: list[LifecycleEntry] = field(default_factory=list)

    # ---- builders -------------------------------------------------------
    @classmethod
    def from_candidates(cls, candidates: list[Candidate]) -> ScanReport:
        return cls(entries=[LifecycleEntry.detect(c) for c in candidates])

    @classmethod
    def from_scan(cls, root, **scan_kwargs) -> ScanReport:
        """Convenience: run the scanner and build a report in one step."""
        return cls.from_candidates(scan(root, **scan_kwargs))

    # ---- rollups --------------------------------------------------------
    @property
    def total(self) -> int:
        return len(self.entries)

    def by_state(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for e in self.entries:
            out[e.state.value] = out.get(e.state.value, 0) + 1
        return out

    def by_severity(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for e in self.entries:
            sev = e.candidate.severity
            out[sev] = out.get(sev, 0) + 1
        return out

    def governed_count(self) -> int:
        return sum(1 for e in self.entries if e.is_governed)

    def coverage(self) -> float:
        """(governed-or-better) / total. 1.0 for an empty report (vacuous)."""
        if not self.entries:
            return 1.0
        return min(1.0, self.governed_count() / self.total)

    def open_blocking(self) -> list[LifecycleEntry]:
        """Ungoverned, error-severity action points — the things to fix first."""
        return [e for e in self.entries if not e.is_governed and e.candidate.severity == "error"]

    def headline(self) -> str:
        return (
            f"Total: {self.total} · "
            f"Coverage: {self.coverage():.1%} · "
            f"Blocking: {len(self.open_blocking())} · "
            f"Governed: {self.governed_count()}"
        )

    # ---- rendering ------------------------------------------------------
    def render(self) -> str:
        """Human-readable consumer report with the lifecycle table."""
        if not self.entries:
            return (
                "\U0001f512 Strix Personal — no consequential action points found.\n"
                "Patterns checked: payments, db deletes, storage, email/SMS, "
                "filesystem deletes, schema migrations, AI surfaces."
            )

        lines: list[str] = ["\U0001f512 Strix Personal — action inventory", ""]
        lines.append(self.headline())
        lines.append("")

        sev = self.by_severity()
        sev_bits = [f"{_SEVERITY_BADGE.get(k, k)} {sev[k]}" for k in ("error", "warning", "note") if k in sev]
        if sev_bits:
            lines.append("By severity:  " + " · ".join(sev_bits))

        state_counts = self.by_state()
        state_bits = [
            f"{s.value} {state_counts[s.value]}"
            for s in (*_PROGRESSION, ActionState.SUPPRESSED)
            if s.value in state_counts
        ]
        if state_bits:
            lines.append("Lifecycle:    " + " · ".join(state_bits))
        lines.append("")

        blocking = self.open_blocking()
        if blocking:
            lines.append(f"Open action points ({len(blocking)} blocking):")
            for e in blocking:
                lines.append(
                    f"  {_SEVERITY_BADGE.get(e.candidate.severity, e.candidate.severity)}"
                    f"  [{e.capability_id}]  {e.location}"
                )
                lines.append(f"      {e.candidate.snippet.strip()}")
            lines.append("")

        lines.append("Next: /strix-plan to map capabilities, then /strix-apply to wrap one.")
        return "\n".join(lines)


def _report_has_no_evidence_fields() -> bool:
    """Self-check used by the disjointness test: a report is not evidence."""
    forbidden = {"record_hash", "chain_seq", "prev_hash", "signature", "signing_key_id"}
    report_fields = {f.name for f in fields(ScanReport)}
    entry_fields = {f.name for f in fields(LifecycleEntry)}
    return not (forbidden & (report_fields | entry_fields))


__all__ = [
    "ActionState",
    "LifecycleEntry",
    "LifecycleError",
    "RuntimeSignal",
    "ScanReport",
    "MAX_STATIC_STATE",
    "initial_state",
    "promote",
]

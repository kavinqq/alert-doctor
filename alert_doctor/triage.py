from __future__ import annotations

from statistics import median

from alert_doctor import auto_texts, replies
from alert_doctor.models import (
    Category,
    CheckSpec,
    Decision,
    Evidence,
    Incident,
    ParsedAlert,
    Reaction,
    RuleMatch,
)

RECOVERY_BUCKETS = 2
SETTLED_BUCKETS = RECOVERY_BUCKETS + 1
MIN_BASELINE_SAMPLES = 4
SPIKE_FLOOR = 5


def is_transient(ev: Evidence | None, max_count: int) -> bool:
    """True only with positive proof of recovery: query succeeded, total <= max_count, exactly known host set
    of <= 1 host, and the two buckets before the final one are empty.

    The final bucket is the current partial minute and ES ingestion may lag, so it is ignored; that needs
    at least 3 buckets unless nothing matched at all. Any missing or failed evidence is False, so a
    require_transient rule can never silence on an ELK outage.
    """
    if ev is None or not ev.query_ok or ev.total is None:
        return False
    if ev.total > max_count:
        return False
    if ev.total == 0:
        return True
    # A hit without any host breakdown means the host field was missing, not that there was one host.
    if not ev.per_host or len(ev.per_host) > 1:
        return False
    if len(ev.histogram) < SETTLED_BUCKETS:
        return False
    return all(count == 0 for _, count in ev.histogram[-SETTLED_BUCKETS:-1])


def detect_spike(current: int, baseline: list[int]) -> bool:
    if len(baseline) < MIN_BASELINE_SAMPLES:
        return False
    return current >= max(SPIKE_FLOOR, 3 * median(baseline) + 1)


def _with_note(text: str, note: str | None) -> str:
    return f"{text}\n{note}" if note else text


def classify(
    alert: ParsedAlert,
    *,
    is_new_incident: bool,
    spike: bool,
    rule: RuleMatch | None,
    check: CheckSpec | None,
    evidence: Evidence | None,
    incident: Incident,
    permalink: str,
    accumulated: bool = False,
    signal=None,
    auto_hit=None,
    auto_link: str = "",
    owners: tuple[str, ...] | None = None,
    elk_failed: bool = False,
    known_hit=None,
) -> Decision:
    """Order: never_silence > datasource > known (link, window) > UNPARSED > ACCUMULATED
    > file KNOWN > auto rule > file noise > DUPLICATE > SPIKE > NEW.

    A never_silence alert whose check also failed on the data source stays CRITICAL; the
    reply adds the data-source line. `known_hit` is a `known_store.LinkHit` (the error is
    linked to a known entry) or a `known.KnownHit` (a maintenance window); only an action
    "known" entry classifies, a "context" one is analyzer background. A known hit never
    hides magnitude: with `spike` or `accumulated` the alert is classified as that and the
    reply names the known entry.

    `auto_hit` is `autorules.match`'s result (blocked fingerprints never get one). An active
    auto rule (noise or known) silences only when nothing above it fired, the alert is not a
    sample, there is no spike, and the check's ELK `signal` exists and succeeded (`elk_failed`
    also vetoes); otherwise the alert falls through to the rest of the order. `owners` are
    ready mention strings for CRITICAL; None falls back to the check's raw owners.
    """
    active = auto_hit is not None and auto_hit.active
    invalidate = "invalidate" if active else None
    datasource = bool(rule and rule.action == "datasource")

    if (check and check.never_silence) or (rule and rule.action == "never_silence"):
        mention = owners if owners is not None else (check.owners if check else ())
        text = replies.critical(incident, mention, spike)
        if datasource:
            text = f"{text}\n{replies.datasource(alert, ())}"
        return Decision(
            Category.CRITICAL,
            text,
            Reaction.CRITICAL,
            is_new_incident or spike,
            rule,
            severity=Reaction.SEV_CRITICAL,
            auto_effect=invalidate,
        )

    # The check never saw the system, so the alert says nothing about it: report the data
    # source failure and keep it out of analysis, baselines and auto rules.
    if datasource:
        mention = owners if owners is not None else ()
        return Decision(Category.DATASOURCE, replies.datasource(alert, mention), Reaction.DATASOURCE,
                        False, rule)

    known_note = None
    if known_hit is not None and known_hit.entry.action == "known":
        if not (spike or accumulated):
            return Decision(Category.KNOWN, known_hit.reply_text(), Reaction.KNOWN, False, rule)
        known_note = known_hit.magnitude_note()

    if not alert.parse_ok:
        return Decision(Category.UNPARSED, replies.unparsed(), Reaction.UNPARSED, False, rule)

    if accumulated:
        signal_dict = signal.to_dict() if signal is not None else {}
        return Decision(
            Category.ACCUMULATED, _with_note(auto_texts.accumulated(incident, signal_dict), known_note),
            Reaction.ACCUMULATED,
            True, rule, severity=Reaction.SEV_HIGH, auto_effect=invalidate,
        )

    if rule and rule.action == "known":
        return Decision(Category.KNOWN, replies.known(rule), Reaction.KNOWN, False, rule)

    sampled = False
    shadow = None
    # A rule learned from quiet periods says nothing about a burst or a moment we cannot measure.
    evidence_ok = not spike and not elk_failed and signal is not None and signal.ok
    if auto_hit is not None:
        if not auto_hit.active:
            shadow = "shadow"
        elif auto_hit.sample:
            sampled = True
        elif not evidence_ok:
            pass
        elif auto_hit.rule.kind == "known":
            return Decision(Category.KNOWN, auto_texts.auto_known(auto_hit.rule, auto_link),
                            Reaction.KNOWN, False, rule, auto_effect="silenced")
        else:
            return Decision(Category.NOISE, auto_texts.auto_noise(auto_hit.rule, False),
                            Reaction.NOISE, False, rule, auto_effect="silenced")

    if not sampled and rule and rule.action == "noise":
        if not rule.require_transient or is_transient(evidence, rule.max_count):
            return Decision(Category.NOISE, replies.noise(rule, evidence), Reaction.NOISE, False, rule,
                            auto_effect=shadow)

    # An incident never queued for analysis (noise/known anchor, expired rule) must not swallow a real outage.
    if not is_new_incident and not spike and incident.analysis_state != "none":
        return Decision(
            Category.DUPLICATE, replies.duplicate(incident, permalink), Reaction.DUPLICATE, False, rule,
            auto_effect=shadow,
        )

    category = Category.SPIKE if spike else Category.NEW
    if sampled:
        text = auto_texts.sampled(auto_hit.rule, incident)
    else:
        text = _with_note(replies.analyzing(incident, spike), known_note)
    return Decision(
        category, text, Reaction.ANALYZING, True, rule,
        severity=Reaction.SEV_HIGH if spike else None,
        auto_effect="sample" if sampled else shadow,
    )

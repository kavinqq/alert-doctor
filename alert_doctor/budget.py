from __future__ import annotations

CLASSES = ("critical", "first", "normal")
_STEP_SECONDS = 60
_EXIT_RATIO = 0.5


class TokenBucket:
    """Continuously refilled bucket with per-class reserves. Starts full. Not thread-safe.

    Capacity splits into one shared pool plus a private pool per reserved class; a class
    spends the shared pool first and its own reserve last. Refill tops reserves up before
    the shared pool, so protected classes recover first after a drain.
    """

    def __init__(self, capacity: int, per_minute: float, reserved: dict[str, int] | None = None):
        self.capacity = capacity
        self.per_minute = per_minute
        self._reserve_cap = {k: v for k, v in (reserved or {}).items() if v > 0}
        self._shared_cap = max(0, capacity - sum(self._reserve_cap.values()))
        self._reserve = {k: float(v) for k, v in self._reserve_cap.items()}
        self._shared = float(self._shared_cap)
        self._updated: float | None = None

    def _refill(self, now: float) -> None:
        if self._updated is not None and now > self._updated:
            gain = (now - self._updated) * self.per_minute / 60
            for k, cap in self._reserve_cap.items():
                add = min(gain, cap - self._reserve[k])
                self._reserve[k] += add
                gain -= add
            self._shared = min(float(self._shared_cap), self._shared + gain)
        if self._updated is None or now > self._updated:
            self._updated = now

    def available(self, cls: str, now: float) -> int:
        self._refill(now)
        return int(self._shared + self._reserve.get(cls, 0.0))

    def take(self, cls: str, now: float, n: int = 1) -> bool:
        if n > self.available(cls, now):
            return False
        from_shared = min(self._shared, float(n))
        self._shared -= from_shared
        if cls in self._reserve:
            self._reserve[cls] -= n - from_shared
        return True


class Budgets:
    def __init__(self, cfg):
        self.elk = TokenBucket(
            cfg.budget_elk_per_min, cfg.budget_elk_per_min,
            {"critical": cfg.budget_elk_reserved_critical})
        self.slack = TokenBucket(
            cfg.budget_slack_per_min, cfg.budget_slack_per_min,
            {"critical": cfg.budget_slack_reserved_critical, "first": cfg.budget_slack_reserved_first})
        self.llm = TokenBucket(cfg.budget_llm_per_min, cfg.budget_llm_per_min)


class ProtectionMonitor:
    """Overload hysteresis: enter at once, leave after N calm observation steps.

    An observation step is a calm `observe` call at least 60s after the previous
    counted step (the first calm call starts the streak and counts as step 1); calm
    calls closer than that are ignored. Any non-calm call resets the streak, however soon.
    Calm = both metrics below 50% of their thresholds.
    """

    def __init__(self, cfg):
        self._intake_limit = cfg.overload_intake_per_min
        self._active_limit = cfg.overload_active_incidents
        self._exit_steps = cfg.overload_exit_minutes
        self._streak = 0
        self._last_step: float | None = None

    def observe(self, now: float, intake_last_min: int, active_incidents: int,
                current: str) -> tuple[str, str] | None:
        over = intake_last_min >= self._intake_limit or active_incidents >= self._active_limit
        if current != "overload":
            self._reset()
            if not over:
                return None
            return "overload", self._enter_reason(intake_last_min, active_incidents)
        calm = (intake_last_min < self._intake_limit * _EXIT_RATIO
                and active_incidents < self._active_limit * _EXIT_RATIO)
        if not calm:
            self._reset()
            return None
        if self._last_step is not None and now - self._last_step < _STEP_SECONDS:
            return None
        self._last_step = now
        self._streak += 1
        if self._streak < self._exit_steps:
            return None
        self._reset()
        return "normal", f"連續 {self._exit_steps} 分鐘低於門檻 50%(最近 1 分鐘 {intake_last_min} 則、活躍 incident {active_incidents} 件)"

    def _reset(self) -> None:
        self._streak = 0
        self._last_step = None

    def _enter_reason(self, intake: int, active: int) -> str:
        parts = []
        if intake >= self._intake_limit:
            parts.append(f"最近 1 分鐘進件 {intake} 則(門檻 {self._intake_limit})")
        if active >= self._active_limit:
            parts.append(f"活躍 incident {active} 件(門檻 {self._active_limit})")
        return "、".join(parts)

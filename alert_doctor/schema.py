"""Tables owned by modules other than Store; every process that touches them calls `ensure_all` once."""
from __future__ import annotations


def ensure_all(store) -> None:
    from alert_doctor import attachments, autorules, feedback, tuner
    for module in (tuner, autorules, feedback, attachments):
        module.ensure_schema(store)

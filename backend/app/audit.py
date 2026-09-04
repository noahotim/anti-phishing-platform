"""Audit logging.

Every important security action is recorded with actor, entity, before/after
values, result, and request metadata so administrators can reconstruct what
happened and why.
"""
from __future__ import annotations

import json
from typing import Any, Optional

from . import database


def audit(
    *,
    action: str,
    entity: str = "",
    entity_id: str | int | None = None,
    org_id: Optional[int] = None,
    actor_id: Optional[int] = None,
    actor_email: str = "",
    prev: Any = None,
    new: Any = None,
    ip: str = "",
    user_agent: str = "",
    result: str = "SUCCESS",
) -> None:
    def _ser(v: Any) -> str:
        if v is None:
            return "{}"
        if isinstance(v, dict):
            return json.dumps(v, default=str)[:4000]
        return json.dumps({"value": str(v)}, default=str)[:4000]

    database.execute(
        """
        INSERT INTO audit_logs
            (org_id, actor_id, actor_email, action, entity, entity_id,
             prev, new, ip, user_agent, result, created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            org_id,
            actor_id,
            actor_email,
            action,
            entity,
            str(entity_id) if entity_id is not None else None,
            _ser(prev),
            _ser(new),
            ip,
            user_agent,
            result,
            database.utcnow_iso(),
        ),
    )
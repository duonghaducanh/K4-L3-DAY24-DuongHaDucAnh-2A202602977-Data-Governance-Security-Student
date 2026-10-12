"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Mọi decision trả về (allow, reason)
và `reason` không bao giờ rỗng (evidence audit — điều kiện trượt nếu thiếu).

Quyền hiệu lực của một tool call = principal.allowed_tools
                                  ∩ agent_scopes
                                  ∩ parent_scopes   (chỉ khi delegation_depth > 0)
Purpose phải nằm trong principal.purposes. Unknown principal, scope thiếu,
purpose sai, hoặc expires_at đã qua đều deny.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

PRINCIPALS_FILE = Path(__file__).resolve().parent.parent / "data" / "principals.json"


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def _load_principals() -> dict:
    return json.loads(PRINCIPALS_FILE.read_text(encoding="utf-8"))


def _expired(expires_at: str) -> bool:
    """True nếu expires_at rỗng hoặc đã qua. Rỗng = không có hạn hợp lệ."""
    if not expires_at:
        return True
    try:
        when = datetime.fromisoformat(expires_at)
    except ValueError:
        return True
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return when <= datetime.now(timezone.utc)


def check(context: PolicyContext) -> tuple[bool, str]:
    # Rule tối thiểu bắt buộc: restricted + egress -> DENY. Kiểm TRƯỚC tiên,
    # kể cả khi principal có đủ mọi quyền (xem test_policy.py).
    if context.data_classification == "restricted" and context.egress_enabled:
        return False, (
            "deny: data_classification=restricted đi kèm egress_enabled=True "
            "— vi phạm rule tối thiểu (không cho restricted rời boundary)"
        )

    # OBO: principal phải tồn tại trong nguồn tin cậy.
    principal = _load_principals().get(context.principal_id)
    if principal is None:
        return False, f"deny: principal không tồn tại trong principals.json ({context.principal_id!r})"

    # Purpose phải được principal cho phép.
    if context.request_purpose not in principal.get("purposes", []):
        return False, (
            f"deny: purpose {context.request_purpose!r} không nằm trong purposes "
            f"của {context.principal_id!r} {principal.get('purposes', [])}"
        )

    # Quyền hiệu lực = allowed_tools ∩ agent_scopes (∩ parent_scopes nếu depth>0).
    effective = set(principal.get("allowed_tools", [])) & set(context.agent_scopes)
    if context.delegation_depth > 0:
        effective &= set(context.parent_scopes)
    if context.requested_tool not in effective:
        detail = (
            f"principal.allowed_tools={principal.get('allowed_tools', [])}, "
            f"agent_scopes={list(context.agent_scopes)}"
        )
        if context.delegation_depth > 0:
            detail += f", parent_scopes={list(context.parent_scopes)}"
        return False, (
            f"deny: tool {context.requested_tool!r} không nằm trong quyền hiệu lực "
            f"của {context.principal_id!r} ({detail})"
        )

    # Run hết hạn -> deny.
    if _expired(context.expires_at):
        return False, (
            f"deny: run đã hết hạn hoặc thiếu expires_at "
            f"({context.expires_at!r})"
        )

    return True, (
        f"allow: {context.principal_id!r} được {context.requested_tool!r} "
        f"cho purpose {context.request_purpose!r} "
        f"(classification={context.data_classification}, egress={context.egress_enabled}, "
        f"depth={context.delegation_depth})"
    )

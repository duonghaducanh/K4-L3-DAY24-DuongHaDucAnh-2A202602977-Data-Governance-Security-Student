"""BƯỚC 3c — trifecta split + egress allowlist. ĐÂY LÀ PHẦN KHÓ NHẤT.

Kiến trúc containment (không phải mitigation bằng filter chuỗi):

    Run A  (untrusted):  search_docs(message) -> CHỈ lấy list[int] ticket_id
                         từ TÊN FILE ("ticket-901.md" -> 901). Chạy
                         llm.find_injection() để ghi nhận, nhưng TUYỆT ĐỐI
                         không dùng customer_id mà nó trả về. Không read,
                         không egress.
    Run B  (private):    nhận list[int] ticket_id đã typed. Suy customer_id
                         từ data/customers.json qua `related_tickets` — KHÔNG
                         từ free text. Rồi read_customer. Thử egress ->
                         PEP deny (restricted + egress).

Mọi lần gọi tool (allow HAY deny) đi qua `agent.policy.check()` TRƯỚC khi tool
chạy và được ghi `agent.ledger.append()` với reason, on_behalf_of, agent_id,
run_id, expires_at.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import ledger, policy, tools

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"
CUSTOMERS_FILE = Path(__file__).resolve().parent.parent / "data" / "customers.json"

AGENT_ID_A = "lab24-agent/run-a"
AGENT_ID_B = "lab24-agent/run-b"
PURPOSE_A = "summarize-tickets"
PURPOSE_B = "support-reply"
TTL_SECONDS = 300

_TICKET_FILE_RE = re.compile(r"ticket-(\d+)\.md$")


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ttl_expiry(seconds: int = TTL_SECONDS) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()


def _args_hash(args: dict) -> str:
    blob = json.dumps(args, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _ticket_ids_from_names(docs: list[dict]) -> list[int]:
    """Chỉ lấy ID SỐ từ TÊN FILE — không bao giờ từ nội dung."""
    ids: list[int] = []
    for doc in docs:
        match = _TICKET_FILE_RE.search(str(doc.get("id", "")))
        if match:
            ids.append(int(match.group(1)))
    return sorted(set(ids))


def _customers_for_tickets(ticket_ids: list[int]) -> list[str]:
    """Nguồn tin cậy: map ticket_id -> customer_id qua related_tickets."""
    records = json.loads(CUSTOMERS_FILE.read_text(encoding="utf-8"))
    wanted = set(ticket_ids)
    return [r["customer_id"] for r in records if wanted & set(r.get("related_tickets", []))]


def _log(entry: dict, *, path: Path, run_id: str, principal_id: str,
         agent_id: str, expires_at: str) -> dict:
    full = {
        "ts": _now_iso(),
        "agent_id": agent_id,
        "run_id": run_id,
        "on_behalf_of": principal_id,
        "expires_at": expires_at,
        "args_hash": "n/a",
        "classification": "internal",
        **entry,
    }
    return ledger.append(full, path)


def _guard(*, tool: str, classification: str, purpose: str, egress: bool,
           agent_scopes: tuple[str, ...], principal_id: str, agent_id: str,
           run_id: str, expires_at: str, args: dict, ledger_path: Path) -> bool:
    """PEP: check policy TRƯỚC khi tool chạy; ghi ledger cả allow lẫn deny.
    Trả True nếu được phép chạy tool."""
    context = policy.PolicyContext(
        data_classification=classification,
        request_purpose=purpose,
        agent_owner=agent_id,
        delegation_depth=0,
        egress_enabled=egress,
        principal_id=principal_id,
        requested_tool=tool,
        agent_scopes=agent_scopes,
        parent_scopes=(),
        expires_at=expires_at,
    )
    allowed, reason = policy.check(context)
    _log(
        {
            "tool": tool,
            "classification": classification,
            "decision": "allow" if allowed else "deny",
            "reason": reason,
            "args_hash": _args_hash(args),
        },
        path=ledger_path, run_id=run_id, principal_id=principal_id,
        agent_id=agent_id, expires_at=expires_at,
    )
    return allowed


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    ledger_path = Path(log_dir) / "ledger.jsonl" if log_dir else DEFAULT_LEDGER_PATH
    run_id = f"run-{uuid.uuid4().hex[:12]}"
    expires_at = _ttl_expiry()

    # ---- Run A: untrusted content, chỉ lấy ticket_id từ TÊN FILE ----------
    if _guard(tool="search_docs", classification="internal", purpose=PURPOSE_A,
              egress=False, agent_scopes=("search_docs",), principal_id=principal_id,
              agent_id=AGENT_ID_A, run_id=run_id, expires_at=expires_at,
              args={"query": message}, ledger_path=ledger_path):
        docs = tools.search_docs(message)
    else:
        docs = []

    combined = "\n\n".join(d.get("text", "") for d in docs)
    injected = llm.find_injection(combined) if combined else None
    ticket_ids = _ticket_ids_from_names(docs)

    # ---- Run B: private data, customer_id suy từ related_tickets ----------
    target_customers = _customers_for_tickets(ticket_ids)
    collected: list[dict] = []
    for customer_id in target_customers:
        allowed = _guard(tool="read_customer", classification="restricted",
                         purpose=PURPOSE_B, egress=False,
                         agent_scopes=("read_customer",), principal_id=principal_id,
                         agent_id=AGENT_ID_B, run_id=run_id, expires_at=expires_at,
                         args={"customer_id": customer_id}, ledger_path=ledger_path)
        if not allowed:
            continue
        try:
            collected.append(tools.read_customer(customer_id))
        except tools.ToolError:
            continue

    # ---- Egress leg: chỉ thử khi có chỉ thị; PEP deny (restricted+egress) --
    if injected is not None and collected:
        target_url = injected.target_url or "http://127.0.0.1:10024/reconcile"
        allowed = _guard(tool="http_post", classification="restricted",
                         purpose=PURPOSE_B, egress=True,
                         agent_scopes=("http_post",), principal_id=principal_id,
                         agent_id=AGENT_ID_B, run_id=run_id, expires_at=expires_at,
                         args={"url": target_url, "record_count": len(collected)},
                         ledger_path=ledger_path)
        if allowed:  # trong lab này luôn False; giữ đối xứng cho đúng PEP
            tools.http_post(target_url, {"records": collected})

    return llm.summarize(docs)

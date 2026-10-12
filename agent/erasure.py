"""BONUS — xoá dữ liệu (right to erasure) theo kiểu append-only.

Xoá hồ sơ khách phải cascade sang private store nhưng **không** được viết lại
ledger: ta ghi thêm một entry `erase_customer` (tombstone, chỉ có `args_hash`
— không PII thô) rồi mới xoá record. Vì lịch sử cũ không bị sửa, hash chain
`verify()` vẫn trả True. Đây là điểm khác biệt giữa "xoá dữ liệu" và "sửa
bằng chứng audit".
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from agent import ledger

ERASURE_AGENT_ID = "lab24-agent/erasure"


def _args_hash(payload: dict) -> str:
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def erase_customer(customer_id: str, *, customers_file: Path, ledger_path: Path,
                   principal_id: str = "dpo", run_id: str = "run-erasure") -> int:
    """Xoá `customer_id` khỏi `customers_file`, ghi tombstone vào ledger.

    Trả về số record đã xoá (0 nếu không tìm thấy). Ledger được append TRƯỚC
    khi xoá dữ liệu để luôn có bằng chứng hành vi.
    """
    customers_file = Path(customers_file)
    records = json.loads(customers_file.read_text(encoding="utf-8"))
    kept = [r for r in records if str(r.get("customer_id")) != str(customer_id)]
    removed = len(records) - len(kept)

    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "agent_id": ERASURE_AGENT_ID,
        "run_id": run_id,
        "on_behalf_of": principal_id,
        "expires_at": "",
        "tool": "erase_customer",
        "args_hash": _args_hash({"customer_id": customer_id}),
        "classification": "restricted",
        "decision": "allow" if removed else "deny",
        "reason": (
            f"erase_customer {customer_id}: đã xoá {removed} record (tombstone "
            f"append-only, không viết lại lịch sử ledger)"
        ),
    }
    ledger.append(entry, Path(ledger_path))

    if removed:
        customers_file.write_text(
            json.dumps(kept, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    return removed

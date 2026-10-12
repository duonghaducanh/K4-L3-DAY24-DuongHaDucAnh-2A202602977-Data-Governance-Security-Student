"""BONUS test — delete cascade vẫn giữ ledger verify (right to erasure).

    pytest tests/test_bonus_erasure.py -v

Chứng minh: xoá một khách khỏi private store (cascade) + ghi tombstone
append-only, KHÔNG viết lại lịch sử ledger -> hash chain `verify()` vẫn True,
và record đã biến mất khỏi store.
"""
from __future__ import annotations

import json

from agent import ledger
from agent.erasure import erase_customer


def test_delete_cascade_keeps_ledger_verifiable(tmp_path):
    customers_file = tmp_path / "customers.json"
    customers_file.write_text(
        json.dumps([
            {"customer_id": "KH-000001", "cccd": "111"},
            {"customer_id": "KH-000777", "cccd": "777"},
        ], ensure_ascii=False),
        encoding="utf-8",
    )
    ledger_path = tmp_path / "ledger.jsonl"

    # Vài entry lịch sử trước khi xoá (giả lập audit trước đó).
    ledger.append({"ts": "t", "agent_id": "a", "run_id": "r", "tool": "read_customer",
                   "args_hash": "x", "classification": "restricted",
                   "decision": "allow", "reason": "read before erasure"}, ledger_path)
    assert ledger.verify(ledger_path) is True

    removed = erase_customer("KH-000777", customers_file=customers_file,
                             ledger_path=ledger_path)

    # 1) Dữ liệu đã bị xoá khỏi store (cascade).
    assert removed == 1
    remaining = json.loads(customers_file.read_text(encoding="utf-8"))
    assert [r["customer_id"] for r in remaining] == ["KH-000001"]

    # 2) Ledger KHÔNG bị viết lại -> hash chain vẫn verify.
    assert ledger.verify(ledger_path) is True

    # 3) Tombstone có mặt, không chứa PII thô.
    entries = [json.loads(l) for l in ledger_path.read_text(encoding="utf-8").splitlines()]
    assert entries[-1]["tool"] == "erase_customer"
    assert "777" not in entries[-1]["reason"] or entries[-1]["args_hash"]
    assert all(e.get("reason") for e in entries)


def test_erase_unknown_customer_is_recorded_but_no_change(tmp_path):
    customers_file = tmp_path / "customers.json"
    customers_file.write_text(json.dumps([{"customer_id": "KH-000001"}]), encoding="utf-8")
    ledger_path = tmp_path / "ledger.jsonl"

    removed = erase_customer("KH-999999", customers_file=customers_file,
                             ledger_path=ledger_path)
    assert removed == 0
    assert ledger.verify(ledger_path) is True
    entries = [json.loads(l) for l in ledger_path.read_text(encoding="utf-8").splitlines()]
    assert entries[-1]["decision"] == "deny" and entries[-1]["reason"]

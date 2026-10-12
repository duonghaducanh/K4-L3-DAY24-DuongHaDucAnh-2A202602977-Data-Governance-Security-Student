"""BƯỚC 3d — audit ledger append-only, tamper-evident (10').

JSONL, mỗi tool call một dòng, có hash chain:

    prev_hash = hash của dòng ngay trước trong file, hoặc "0"*64 nếu là dòng đầu
    hash      = sha256( json.dumps(entry_đầy_đủ_bỏ_field_hash, sort_keys=True) )

Không ghi PII thô vào ledger — chỉ `args_hash` (đủ đối chiếu call trong lab).
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

GENESIS = "0" * 64


def _hash_entry(entry: dict) -> str:
    payload = {k: v for k, v in entry.items() if k != "hash"}
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _last_hash(path: Path) -> str:
    if not path.exists():
        return GENESIS
    last = ""
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            last = line
    if not last:
        return GENESIS
    try:
        return json.loads(last).get("hash", GENESIS)
    except json.JSONDecodeError:
        return GENESIS


def append(entry: dict, path: Path) -> dict:
    """Thêm 1 dòng vào `path` (tạo file/thư mục nếu cần). Trả dict đầy đủ đã ghi."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    record = dict(entry)
    record["prev_hash"] = _last_hash(path)
    record["hash"] = _hash_entry(record)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
    return record


def verify(path: Path) -> bool:
    """True nếu mọi dòng: reason non-empty, prev_hash khớp hash dòng trước,
    và hash lưu khớp khi tính lại từ nội dung dòng đó."""
    path = Path(path)
    if not path.exists():
        return True
    prev = GENESIS
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            return False
        if not entry.get("reason"):
            return False
        if entry.get("prev_hash") != prev:
            return False
        if entry.get("hash") != _hash_entry(entry):
            return False
        prev = entry["hash"]
    return True

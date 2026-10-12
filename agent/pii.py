"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Regex recognizer cho tiếng Việt (Presidio không có recognizer "vi" sẵn):

    VN_CCCD          12 chữ số liên tiếp (thường đứng sau "CCCD"/"căn cước")
    VN_PHONE         0 + 9-10 chữ số, cho phép dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp (thường sau "STK"/"số tài khoản")
    EMAIL            local@domain.tld

Chiến lược: neo theo **từ khoá ngữ cảnh gần nhất** để phân biệt CCCD / STK /
SĐT (vì cùng là dãy số), rồi fallback theo hình dạng khi không có từ khoá.
Đo bằng: pytest tests/test_pii.py -v -s
"""
from __future__ import annotations

import re
import unicodedata

# --- regex cơ bản ---------------------------------------------------------
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

# SĐT VN: bắt đầu bằng 0, tổng 10-11 chữ số, cho phép phân nhóm bằng space/./-.
# (?<!\d) / (?!\d) chặn việc khớp 10 chữ số đầu của một số 12 chữ số (CCCD).
PHONE_RE = re.compile(r"(?<!\d)0\d{2}(?:[ .\-]?\d){7,8}(?!\d)")

# Dãy số liền mạch cho CCCD/STK. 8-16 chữ số, không dính thêm chữ số hai đầu.
DIGITS_RE = re.compile(r"(?<!\d)\d{8,16}(?!\d)")

# Từ khoá ngữ cảnh (so khớp sau khi bỏ dấu + hạ chữ thường).
_KEYWORDS = {
    "VN_BANK_ACCOUNT": ("stk", "so tai khoan", "tai khoan"),
    "VN_CCCD": ("cccd", "can cuoc", "cmnd", "chung minh nhan dan"),
    "VN_PHONE": ("sdt", "so dien thoai", "dien thoai", "lien he"),
}
_CONTEXT_WINDOW = 40  # số ký tự phía trước một số để tìm từ khoá gần nhất


def _strip_diacritics(text: str) -> str:
    text = text.replace("đ", "d").replace("Đ", "D")
    nfkd = unicodedata.normalize("NFKD", text)
    return "".join(c for c in nfkd if not unicodedata.combining(c))


def _classify(text: str, start: int) -> str:
    """Chọn type cho dãy số bắt đầu ở `start`, dựa vào từ khoá gần nhất."""
    window = _strip_diacritics(text[max(0, start - _CONTEXT_WINDOW):start]).lower()
    best_type, best_pos = None, -1
    for etype, keys in _KEYWORDS.items():
        for key in keys:
            pos = window.rfind(key)
            if pos > best_pos:
                best_type, best_pos = etype, pos
    if best_type is not None:
        return best_type
    # Fallback theo hình dạng khi không có từ khoá ngữ cảnh.
    digits = text[start:start + 16]
    run = re.match(r"\d+", digits).group(0)
    if run.startswith("0") and len(run) == 10:
        return "VN_PHONE"
    if len(run) == 12:
        return "VN_CCCD"
    return "VN_BANK_ACCOUNT"


def _overlaps(a: tuple[int, int], b: tuple[int, int]) -> bool:
    return a[0] < b[1] and b[0] < a[1]


def detect(text: str) -> list[dict]:
    """Trả list[{"type", "start", "end"}] — offset như slice Python."""
    found: list[tuple[int, int, str]] = []

    # 1) EMAIL (ưu tiên, để không nhầm chữ số trong domain thành số).
    for m in EMAIL_RE.finditer(text):
        found.append((m.start(), m.end(), "EMAIL"))

    # 2) SĐT có phân nhóm — bỏ qua nếu chồng lên email.
    for m in PHONE_RE.finditer(text):
        span = (m.start(), m.end())
        if any(_overlaps(span, (s, e)) for s, e, _ in found):
            continue
        found.append((m.start(), m.end(), "VN_PHONE"))

    # 3) Dãy số liền mạch (CCCD/STK/SĐT viết liền) — phân loại theo ngữ cảnh.
    for m in DIGITS_RE.finditer(text):
        span = (m.start(), m.end())
        if any(_overlaps(span, (s, e)) for s, e, _ in found):
            continue
        found.append((m.start(), m.end(), _classify(text, m.start())))

    found.sort()
    return [{"type": t, "start": s, "end": e} for s, e, t in found]


def redact(text: str) -> str:
    """Thay mọi entity bằng [REDACTED_<TYPE>]. Thay từ cuối về đầu để
    offset không bị lệch."""
    entities = sorted(detect(text), key=lambda e: e["start"], reverse=True)
    for entity in entities:
        replacement = f"[REDACTED_{entity['type']}]"
        text = text[:entity["start"]] + replacement + text[entity["end"]:]
    return text

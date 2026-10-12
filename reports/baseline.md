# Baseline — Checkpoint 1

Đọc `_naive_loop()` trong `agent/loop.py` (dòng 27–54) và trả lời 3 câu hỏi.

## 1. Agent có identity riêng mỗi run chưa?

**Không.** `_naive_loop(message, llm)` (`agent/loop.py:27`) không tạo và không
nhận bất kỳ định danh nào: không `run_id`, không `agent_id`, không principal,
không scope, không hạn dùng. Mỗi lần chạy là một vòng lặp vô danh — hai lần
chạy khác nhau không thể phân biệt được trong log. Cùng file, hàm `run_once()`
(`agent/loop.py:57`) cũng không sinh identity, chỉ chuyển `message`/`llm` thẳng
vào loop. Vì vậy mọi tool call ở baseline đều **không có "on_behalf_of"**.

## 2. Ai cho phép `http_post`?

**Không ai.** `_naive_loop()` gọi thẳng `tools.http_post(...)`
(`agent/loop.py:44`) ngay khi `llm.find_injection()` trả về một chỉ thị — không
qua bất kỳ PEP/policy nào (`agent/policy.py` thậm chí chưa được import ở
baseline). Thứ duy nhất chặn là allowlist cứng trong
`agent/tools.py::http_post` (dòng 77) — chỉ cho `http://127.0.0.1:10024/*`. Đó
là **rào an toàn của lab** (để không ai vô tình POST ra Internet thật), **không
phải** kiểm soát uỷ quyền: nó không hỏi principal, không hỏi purpose, không
kiểm phân loại dữ liệu.

## 3. Nếu gửi sai PII ra sink, bằng chứng ở đâu?

**Ở `reports/sink.log`.** `sink/sink.py::make_handler` (dòng 40–53) ghi mỗi
request POST thành 1 dòng JSON `{"path": ..., "body": ...}`. Đường đi của dữ
liệu sai: `search_docs` trả toàn văn ticket → `llm.find_injection()` trích
`customer_ids` **từ free text** (KH-000999) → `tools.read_customer` đọc record
chứa CCCD/STK/SĐT → `tools.http_post` POST `{"records": collected}`
(`agent/loop.py:36–44`). Bản chụp lúc chưa contain nằm ở
`reports/attack-before.log` (chứa record synthetic của `KH-000999`).

## Ba lớp bị thiếu (kết luận)

| Lớp | Baseline | Hệ quả |
|---|---|---|
| PEP / policy (Bước 3b) | không có | tool nào cũng chạy, không ai xét quyền |
| Trifecta split (Bước 3c) | không có | 1 run cầm đủ 3 chân: đọc untrusted → đọc private → POST |
| Audit ledger (Bước 3d) | không có | không có bằng chứng allow/deny, không phát hiện sửa đổi |

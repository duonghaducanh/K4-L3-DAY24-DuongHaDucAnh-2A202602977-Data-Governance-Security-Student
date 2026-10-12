# DPIA-lite — Checkpoint 5

## 1. Loại dữ liệu và phân loại

| Dữ liệu | Ví dụ (synthetic) | Phân loại |
|---|---|---|
| Họ tên khách hàng | "Lê Thu Trang" (`KH-000999`) | internal |
| CCCD (12 số) | `811753472374` | **restricted** |
| SĐT | `0861707895` | **restricted** |
| Số tài khoản (STK) | `9103069783` | **restricted** |
| Email | `le.thu.trang666@example.vn` | **restricted** |
| Nội dung ticket (free text) | `corpus/ticket-001..040.md`, `ticket-901..904b.md` | internal (untrusted content) |

Toàn bộ dữ liệu là **tổng hợp** (`scripts/generate_fixtures.py`, seed cố định).
Không có dữ liệu cá nhân thật trong repo, prompt, log hay báo cáo.

## 2. Mục đích xử lý và principal

- **Mục đích:** tổng hợp ticket hỗ trợ (`summarize-tickets`) và trả lời hỗ trợ
  (`support-reply`) — mô phỏng đối soát ticket.
- **Principal (mô phỏng, `data/principals.json`):**
  - `support_l1`: chỉ `search_docs`, **không** `read_customer` → không đọc
    record chứa CCCD/STK.
  - `dpo`: `read_customer` cho purpose `support-reply` → đọc hồ sơ khách gắn
    với ticket hợp lệ.
- `--as` chỉ **mô phỏng quyền** trong lab; **không phải** cơ chế xác thực
  người dùng production.

## 3. Dữ liệu đi qua những run/tool nào, endpoint nào

```
query người dùng
  └─ Run A (untrusted)  : search_docs(message)                 -> chỉ lấy list[int] ticket_id từ TÊN FILE
        (agent/runner.py:132-141)                                KHÔNG đọc private, KHÔNG egress
  └─ Run B (private)    : map ticket_id -> customer_id qua related_tickets (data/customers.json)
        (agent/runner.py:143-155)                                -> read_customer(customer_id)   [PEP: restricted, egress=False]
  └─ egress leg         : http_post(target_url, {records})      [PEP: restricted, egress=True -> DENY]
        (agent/runner.py:158-169)
```

- Endpoint egress: **chỉ** `http://127.0.0.1:10024/*` (allowlist cứng trong
  `agent/tools.py:26-27,77`). Không có endpoint ngoài localhost.
- Free text của attacker **không** đi qua khỏi Run A (chỉ ID số từ tên file
  được truyền tiếp) — đây là containment, không phải mitigation.

## 4. Bằng chứng deny/allow và giới hạn của mock

**Allow (hợp lệ):** dưới `dpo`, ledger ghi `read_customer` `allow` với
`classification=restricted`, `egress=False` — đọc hồ sơ khách gắn với ticket
901–905 (`reports/ledger.jsonl`, các dòng 2–22).

**Deny (chặn egress):** dòng cuối `reports/ledger.jsonl:23`:
`tool=http_post`, `decision=deny`,
`reason="deny: data_classification=restricted đi kèm egress_enabled=True — vi phạm rule tối thiểu (không cho restricted rời boundary)"`,
`on_behalf_of=dpo`. → `reports/attack-after.log` **rỗng**.

**Bằng chứng trước contain:** `reports/attack-before.log` chứa record
synthetic của `KH-000999` (cccd/phone/bank_account) — cùng payload, trước khi
có containment.

**Giới hạn của mock:**
- `--mock` là LLM giả deterministic (`agent/llm.py::MockLLM`); nó **mô
  phỏng** hành vi prompt injection, không phải một model thật. Đổi sang
  `--model` không đổi kết luận nhưng không được dùng để chấm điểm.
- Principal/TTL/scope là **fixture mô phỏng**, không phải IAM production.
- Ledger hash chain phát hiện sửa **trong file**; **không** phát hiện xoá
  dòng cuối hay viết lại toàn bộ chuỗi nếu thiếu mốc tin cậy bên ngoài.
- Regex PII (không dùng Presidio/NER tiếng Việt) có thể bỏ sót biến thể viết
  lạ; đã đo recall=1.000 trên test set synthetic của lab.

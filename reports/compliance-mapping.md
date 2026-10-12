# Compliance mapping — Checkpoint 5

Mỗi dòng trỏ tới **file:dòng evidence thật** trong repo. Cột "Giới hạn" phân
biệt rõ **mô phỏng kỹ thuật trong lab** với **tuân thủ pháp luật thật**: các
control dưới đây là bằng chứng kỹ thuật, không tự chứng minh tuân thủ.

> Trạng thái đối chiếu văn bản pháp luật: môi trường lab chặn truy cập
> nguồn chính thức (xem `reports/verification.md`). Các **điều khoản cụ thể**
> của Luật 91/2025, NĐ 356/2025, Luật AI 134/2025 được ghi **`chưa xác
> minh`** — chỉ ánh xạ tới control tương ứng, không khẳng định số điều.
> Riêng tên ASI01/ASI03/ASI04 đã đối chiếu OWASP Agentic Security Initiative.

| Nguồn / yêu cầu | Control đã làm | Evidence file:dòng | Giới hạn |
|---|---|---|---|
| Luật 91/2025/QH15 (BVDLCN) — bảo vệ dữ liệu cá nhân khi xử lý | PII gate `detect()`/`redact()` (regex VN) redact CCCD/SĐT/STK/email trước boundary; ledger không ghi PII thô, chỉ `args_hash` | `agent/pii.py:69` (`detect`), `agent/pii.py:95` (`redact`); `agent/ledger.py:19` (`_hash_entry`); đo recall=1.000/precision=1.000 trên `tests/vn_pii_testset.jsonl` (118 gold) | Điều khoản cụ thể: `chưa xác minh`. Regex trên dữ liệu **synthetic**; chưa thay thế đánh giá pháp lý. |
| Luật 91/2025/QH15 — hạn chế chuyển dữ liệu ra ngoài | PEP deny `restricted + egress`; OBO giới hạn quyền theo principal | `agent/policy.py:56` (rule tối thiểu); `reports/ledger.jsonl:23` (deny `http_post`) | `chưa xác minh` số điều. `--as` là principal mô phỏng, không phải xác thực người dùng thật. |
| NĐ 356/2025/NĐ-CP — hướng dẫn thi hành BVDLCN | Trifecta split: Run B suy `customer_id` từ `related_tickets` (nguồn tin cậy), không đọc theo free text attacker; `support_l1` bị deny `read_customer` | `agent/runner.py:60` (`_ticket_ids_from_names`), `agent/runner.py:70` (`_customers_for_tickets`), `agent/runner.py:144`; `agent/policy.py:75` (effective scopes); `tests/test_split.py`, `tests/test_obo.py` | `chưa xác minh` số điều. |
| Luật AI 134/2025/QH15 — trách nhiệm giải trình hệ thống AI | Audit ledger append-only, hash chain, mọi dòng có `reason`, `on_behalf_of`, `run_id`; tamper-evident | `agent/ledger.py:40` (`append`), `agent/ledger.py:52` (`verify`); `reports/ledger.jsonl` (23 dòng, `verify=True`); `tests/test_ledger.py` | `chưa xác minh` số điều. Hash chain chỉ phát hiện sửa **trong file**; không phát hiện xoá dòng cuối/viết lại cả chuỗi nếu thiếu mốc ngoài. |
| OWASP ASI01 — Agent Behaviour Hijack (prompt injection) | 4 lure; containment: Run B không đọc free text; PEP chặn egress | `injection-corpus.md`; `corpus/ticket-902.md`..`ticket-904b.md`; `agent/runner.py:140` (chỉ log `find_injection`, không dùng `customer_id`); `tests/test_injection.py` | Đã đối chiếu tên OWASP. Mock LLM là mô hình injection, không phải model thật. |
| OWASP ASI03 — Identity & Privilege Abuse | OBO: quyền hiệu lực = `principal.allowed_tools ∩ agent_scopes (∩ parent_scopes)`; unknown/expired/purpose-sai deny | `agent/policy.py:65,70,75,91`; `data/principals.json`; `tests/test_obo.py`; `reports/ledger.jsonl` (`on_behalf_of`, `expires_at`) | Đã đối chiếu tên OWASP. Principal là fixture mô phỏng. |
| OWASP ASI04 — Agentic Supply Chain Vulnerabilities | Hash-pinned lock; hook Gitleaks pin v8.30.1; quét lịch sử thấy token giả | `.pre-commit-config.yaml`; `requirements.lock`; `reports/secrets-incident.md`; `tests/test_supply_chain.py` | Đã đối chiếu tên OWASP. Finding là token **giả** cài sẵn, không phải secret thật. |
| Deny egress có bằng chứng (rubric) | Dòng ledger `http_post` `decision=deny`, `reason` non-empty | `reports/ledger.jsonl:23` | — |

## Tóm tắt điều kiện trượt

| Điều kiện | Trạng thái | Bằng chứng |
|---|---|---|
| Ledger entry thiếu `reason` | Không vi phạm | `agent/ledger.py:66`; `reports/ledger.jsonl` mọi dòng có reason |
| PII `KH-000999` tới sink sau contain | Không vi phạm | `reports/attack-after.log` rỗng |
| Runner đọc `KH-000777` từ free text | Không vi phạm | `tests/test_split.py` pass; `agent/runner.py:144` |
| `support_l1` đọc restricted / con vượt `parent_scopes` | Không vi phạm | `tests/test_obo.py` pass; `agent/policy.py:75-78` |
| Credential/PII thật trong bài nộp | Không vi phạm | `gitleaks dir` → no leaks; dữ liệu synthetic |

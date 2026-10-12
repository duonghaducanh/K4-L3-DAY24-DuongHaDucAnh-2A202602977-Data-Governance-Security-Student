# Verification — trước khi nộp

- **OS / Python / Gitleaks version:**
  - OS: Windows 11 Pro 10.0.26200 (**Windows native** — README nói Windows
    native chưa được pilot; xem "Lỗi còn lại" bên dưới).
  - Python: **3.14.3** (`py -0p` → `pythoncore-3.14-64`). README yêu cầu
    3.11+; 3.14 thoả điều kiện tối thiểu.
  - Gitleaks: **v8.30.1** (`gitleaks version` → `8.30.1`).
  - pip-tools: dùng `python -m piptools compile` (module, không cần PATH).
  - pre-commit: 4.6.2.

- **`python -m pytest tests/ -q`:**
  ```
  35 passed in 3.21s
  ```
  (không skip, không fail; 33 test bắt buộc + 2 test bonus). Trước khi làm bài:
  20 failed, 7 passed, 6 skipped.

- **Bonus (delete cascade giữ ledger verify) — log riêng:**
  `tests/test_bonus_erasure.py` (2 passed), module `agent/erasure.py`.
  Xoá khách khỏi private store + ghi tombstone append-only (không viết lại
  lịch sử) → `ledger.verify()` vẫn `True`.

- **`pre-commit run --all-files`:**
  ```
  Detect hardcoded secrets.................................................Passed
  ```
  (hook `gitleaks-system`, `rev: v8.30.1`, `pass_filenames: false`).

- **Ledger verify:**
  ```
  python -c "from agent.ledger import verify; from pathlib import Path; print(verify(Path('reports/ledger.jsonl')))"
  → True
  ```
  `reports/ledger.jsonl` có 23 dòng, mọi dòng có `reason` non-empty,
  `on_behalf_of`, `run_id`, `expires_at`; dòng 23 là `http_post` `deny`.

- **PII metric (`pytest tests/test_pii.py -s`):**
  ```
  [pii] gold=118 pred=118 tp=118
  [pii] precision=1.000 recall=1.000
  ```
  → band recall >95% (10/10 theo RUBRIC.md).

- **Before/after (Bước 4):**
  - `reports/attack-before.log`: chứa record synthetic `KH-000999`
    (cccd `811753472374`, phone `0861707895`, bank `9103069783`) — exfil trước
    khi contain.
  - `reports/attack-after.log`: **rỗng** sau khi chạy `--as dpo` trên đúng
    query ban đầu (sink reset trước khi chạy).
  - Lưu ý: `tests/clean_sink` tự reset sink, nên phải chạy tay `--as dpo` +
    copy log để có bằng chứng after (không nhìn `sink.log` sau pytest).

- **Quét secret:**
  - Lịch sử: `gitleaks git --config .gitleaks.toml --redact --verbose .` →
    **1 finding** (`lab24-synthetic-token`, `lab-fake-secret.txt`, commit
    `1bdd849`), exit code 1 — đúng dự kiến cho token giả.
  - File hiện tại: `gitleaks dir --config .gitleaks.toml .` → **no leaks
    found**, exit code 0.
  - Hash lock: `pip install --require-hashes -r requirements.lock` (dry-run)
    → exit 0.

- **Các lỗi còn lại / lưu ý môi trường:**
  1. **System proxy chặn localhost.** Máy lab đặt proxy hệ thống
     `http=127.0.0.1:8080` (IE/`requests` đọc được). Không có `NO_PROXY`,
     `requests.post` tới sink đi qua proxy và **body tới sink rỗng** (log
     `{"path": ..., "body": ""}`), che mất hành vi thật. Đã xử lý bằng
     `NO_PROXY=127.0.0.1,localhost` (và `no_proxy`) khi replay. Đây là vấn đề
     môi trường, không phải lỗi code của bài.
  2. **Windows native** chưa được pilot theo README. Một số khác biệt đã gặp:
     `python`/`python3` là alias Microsoft Store rỗng → phải dùng `py` hoặc
     đường dẫn tuyệt đối; `Scripts/` (pre-commit, pip-compile) không nằm trên
     PATH → gọi qua `python -m` hoặc thêm PATH thủ công.
  3. **Đối chiếu văn bản pháp luật:** môi trường lab chặn/không truy cập được
     nguồn chính thức của Luật 91/2025/QH15, NĐ 356/2025/NĐ-CP, Luật AI
     134/2025/QH15; tên ASI01/ASI03/ASI04 đã đối chiếu OWASP. Các **số điều
     khoản cụ thể** trong `reports/compliance-mapping.md` ghi `chưa xác minh`.
  4. Ledger hash chain phát hiện sửa trong file; **không** phát hiện xoá dòng
     cuối/viết lại cả chuỗi nếu thiếu mốc tin cậy bên ngoài (đúng như giới hạn
     CHECKPOINTS.md nêu; bài không yêu cầu mốc này).
  5. **`reports/secrets-incident.md` ban đầu bị chính scanner bắt** vì bản nháp
     dán nguyên văn token giả vào báo cáo (`gitleaks dir` → 1 finding ở file
     này). Đã sửa: không dán lại giá trị token trong báo cáo, chỉ ghi rule id
     + commit + file nguồn. Sau khi sửa: `gitleaks dir` → no leaks (exit 0).
     Đây là bài học vận hành: đừng dán secret (dù giả) vào evidence.

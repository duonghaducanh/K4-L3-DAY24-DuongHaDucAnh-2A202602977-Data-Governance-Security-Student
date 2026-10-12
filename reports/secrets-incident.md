# Secret giả trong lịch sử Git — Checkpoint 4

> Đây là **token giả, vô hiệu** do đề bài cài sẵn (`LAB24-DEMO-...`). Đây
> **không phải** sự cố bảo mật thật và **không** phải điều kiện trượt #5.
> Finding của scanner là bằng chứng của checkpoint này.

- **Scanner và phiên bản:** Gitleaks **v8.30.1** (`gitleaks version` →
  `8.30.1`), cấu hình `.gitleaks.toml` với rule tuỳ chỉnh
  `lab24-synthetic-token`.
- **Commit chứa token giả:** `1bdd849` (chore: seed student lab with
  synthetic secret exercise). Đây là commit **gốc** của repo đề bài, nên
  token nằm trong lịch sử dù file đã bị xoá ở commit sau (`ece6ca4`).
- **File, rule và kết quả quét lịch sử:**

  ```
  gitleaks git --config .gitleaks.toml --redact --verbose .
  ```

  Kết quả: **1 finding** —
  `RuleID: lab24-synthetic-token`, `File: lab-fake-secret.txt`, `Line: 1`,
  `Commit: 1bdd849922156c868a5ee9293d68f5b72e242d2c`. Exit code = 1 (đúng
  như CHECKPOINTS.md dự kiến cho token giả). Nội dung file là một biến
  `LAB24_FAKE_TOKEN=LAB24-DEMO-<16 ký tự>` — giá trị đầy đủ đã bị redact
  trong log (`--redact`), không dán lại nguyên văn ở đây (dán lại sẽ làm
  chính file báo cáo bị scanner bắt).

- **Kết quả quét file hiện tại:**

  ```
  gitleaks dir --config .gitleaks.toml .
  ```

  Kết quả: **no leaks found** (exit code 0). `lab-fake-secret.txt` đã bị
  xoá khỏi HEAD nên quét cây làm việc sạch.

- **Nếu đây là credential thật, cần xử lý thế nào:** phải **thu hồi
  (revoke) và rotate** credential ngay tại nhà cung cấp — vì secret đã nằm
  trong lịch sử Git thì coi như đã lộ. Xoá file khỏi HEAD, thêm `.gitignore`,
  hay pin dependency đều **không** thu hồi được credential đã phát tán.
  Nếu đã push lên remote, phải coi toàn bộ lịch sử là đã lộ (force-push
  rewrite lịch sử không đảm bảo mọi bản sao/clone bị xoá).

- **Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ:** xoá file ở
  commit sau chỉ làm cây làm việc hiện tại sạch — `git log -p` / `gitleaks
  git` vẫn đọc lại được blob cũ từ commit `1bdd849`. Pin dependency
  (`requirements.lock` + hash) chỉ chống supply-chain (package bị tráo đổi),
  và hook Gitleaks chỉ **ngăn** secret mới bị commit về sau, chứ không xoá
  secret đã lộ trong quá khứ. Cả ba biện pháp là **phòng ngừa**, không thay
  thế bước **rotate** khi secret đã lộ.

## Bằng chứng trong repo

- `.pre-commit-config.yaml`: hook `gitleaks-system`, `rev: v8.30.1`,
  `pass_filenames: false`; `pre-commit run --all-files` → Passed.
- `requirements.lock`: sinh bằng `pip-compile --generate-hashes`; mọi
  package có `--hash=sha256:`; `pip install --require-hashes -r
  requirements.lock` chạy được (dry-run exit 0).

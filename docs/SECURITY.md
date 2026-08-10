# Security Notes

## Mô hình đe dọa

Honeypot tiếp nhận đầu vào không tin cậy từ SSH client. Rủi ro chính gồm command
injection, escape khỏi môi trường giả, làm đầy ổ đĩa, request quá dài, tấn công
LLM và truy cập trái phép dashboard.

## Kiểm soát hiện có

- Không thực thi command thật.
- Giới hạn độ dài command và response.
- Filesystem ảo trong bộ nhớ.
- HTTP Basic cho dashboard/API.
- Container chạy bằng user không đặc quyền.
- Không lưu password thô.
- Ollama là tùy chọn và có timeout.

## Trước khi đưa ra Internet

- Đặt sau firewall và reverse proxy.
- Bật TLS cho dashboard.
- Dùng secret mạnh và quản lý qua secret store.
- Rate limit SSH/web.
- Giới hạn CPU, RAM và dung lượng log của container.
- Tách VLAN/VM khỏi hệ thống thật.
- Gửi log tới máy chủ khác để tránh mất bằng chứng.
- Thực hiện đánh giá pháp lý và quyền riêng tư.

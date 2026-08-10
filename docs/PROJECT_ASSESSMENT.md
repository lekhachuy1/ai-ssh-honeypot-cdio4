# Đánh giá tính khả thi của đề tài

## Kết luận

Đề tài **AI SSH Honeypot** phù hợp để phát triển thành đồ án CDIO/an ninh mạng.
Mức độ triển khai MVP ở mức trung bình, có kịch bản demo trực quan và không yêu
cầu phần cứng mạnh khi tắt Ollama.

| Tiêu chí | Đánh giá |
| --- | --- |
| Độ khó triển khai MVP | Trung bình (khoảng 6/10) |
| Khả năng demo trực tiếp | Tốt |
| Kiến thức an ninh mạng | Có chiều sâu |
| Yêu cầu phần cứng | Thấp khi không bật AI |
| Mức độ hoàn thiện MVP hiện tại | Khoảng 70–80% |
| Khả năng mở rộng | Tốt |
| Rủi ro khi demo | Thấp khi chạy trong Docker hoặc mạng lab |

## Phạm vi chức năng đề xuất

Nhóm nên xem năm chức năng sau là phần bắt buộc:

1. Tiếp nhận và ghi nhận kết nối SSH.
2. Mô phỏng terminal an toàn, không thực thi lệnh trên hệ điều hành thật.
3. Phát hiện và chấm điểm rủi ro của câu lệnh.
4. Ánh xạ hành vi sang MITRE ATT&CK.
5. Hiển thị phiên truy cập, timeline và cảnh báo trên dashboard.

Nên chọn thêm hai hoặc ba chức năng mở rộng để thể hiện đóng góp của nhóm:

- Gửi cảnh báo qua Telegram hoặc email.
- GeoIP và bản đồ nguồn kết nối.
- Biểu đồ theo thời gian, địa chỉ IP, severity và kỹ thuật MITRE.
- Xuất báo cáo PDF hoặc CSV.
- Whitelist và blacklist địa chỉ IP.
- So sánh phát hiện dựa trên luật với phân tích có hỗ trợ LLM.
- Phát hiện chuỗi hành vi thay vì chỉ đánh giá từng lệnh riêng lẻ.

## Định vị thành phần AI

Phiên bản hiện tại sử dụng rule engine làm cơ chế phát hiện chính. Ollama là thành
phần tùy chọn, hỗ trợ tạo phản hồi terminal và tóm tắt phiên. Vì vậy, tên đề tài
phù hợp là:

> Xây dựng SSH Honeypot kết hợp luật phát hiện và mô hình ngôn ngữ để phân tích
> hành vi tấn công.

Nếu nhóm muốn khẳng định AI là cơ chế phát hiện, cần bổ sung tập dữ liệu, phương
pháp đánh giá, độ chính xác, recall, precision và so sánh với baseline rule-based.

## Kịch bản trình diễn

1. Khởi động hệ thống bằng Docker Compose và kiểm tra health check.
2. Kết nối từ máy Kali hoặc một SSH client vào cổng `2222`.
3. Thực hiện các lệnh lành tính như `pwd`, `ls`, `cat notes.txt`.
4. Nhập các lệnh discovery và credential access trong môi trường giả lập.
5. Nhập chuỗi tải payload hoặc reverse shell mẫu; hệ thống tuyệt đối không thực thi.
6. Mở dashboard để trình bày timeline, điểm rủi ro, cảnh báo và MITRE ATT&CK.
7. Chứng minh filesystem thật không bị thay đổi.
8. Khởi động lại container và kiểm tra dữ liệu SQLite vẫn được giữ lại.

## Công việc cần hoàn thiện trước khi bảo vệ

- Bổ sung kiểm thử tích hợp SSH từ đầu đến cuối.
- Xây dựng bộ dữ liệu lệnh benign/malicious và đo false positive, false negative.
- Thêm rate limiting cho SSH và dashboard.
- Đổi thông tin đăng nhập mặc định và bảo vệ dashboard bằng TLS khi triển khai.
- Chuẩn bị chế độ demo không phụ thuộc Ollama để tránh sự cố tài nguyên.
- Không công khai honeypot ra Internet khi chưa có firewall, cách ly mạng và giám sát.


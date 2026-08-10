# Kiến trúc hệ thống

## Thành phần

1. **AsyncSSH listener** tiếp nhận kết nối và xác thực tài khoản giả.
2. **VirtualShell** mô phỏng terminal và filesystem trong bộ nhớ, tách biệt theo phiên.
3. **RiskAnalyzer** kiểm tra command bằng regex, chấm điểm và ánh xạ MITRE ATT&CK.
4. **OllamaClient** là thành phần tùy chọn cho lệnh không có handler và tóm tắt phiên.
5. **HoneypotRepository** lưu session, command event và alert qua SQLAlchemy.
6. **FastAPI Dashboard** hiển thị trạng thái vận hành và cung cấp REST API.

## Luồng dữ liệu

```text
SSH Client
  -> AsyncSSH authentication
  -> create session
  -> receive command
  -> risk analysis
  -> VirtualShell handler
      -> optional Ollama fallback
  -> save command event
  -> create HIGH/CRITICAL alert
  -> close and summarize session
  -> dashboard/API query
```

## Quyết định an toàn

- Không dùng `os.system`, `subprocess`, `eval` hoặc `exec`.
- Lệnh chỉ tác động lên dictionary filesystem của phiên.
- Lệnh ghép bằng pipe, `&&`, `||`, backtick hoặc `$()` không được phân tích để chạy.
- Không lưu mật khẩu do người kết nối nhập.
- LLM chỉ sinh chuỗi văn bản; đầu ra không được thực thi.

# NT204.R11.ANTN_LeVanQuy_24521492

## Sử Dụng Công Cụ AI

### 1. Công cụ sử dụng
- Google Antigravity (Mô hình ngôn ngữ Gemini).

### 2. Mục đích sử dụng
- Tra cứu kỹ thuật các giao thức mạng theo chuẩn RFC.
- Đề xuất kiến trúc hệ thống và cấu trúc chuẩn hóa dữ liệu.
- Hỗ trợ viết code trong mã nguồn và sinh dữ liệu cho 12 test cases.

### 3. Phần mã nguồn có sử dụng AI
- `src/models/event.py`: Cấu trúc dữ liệu `NormalizedEvent` và các dataclass lưu trữ thông tin giao thức.
- `src/capture/`: Khung thu thập gói tin từ card mạng trực tiếp (`live.py`) và file PCAP (`pcap.py`).
- `src/parsers/`: Các bộ bóc tách giao thức IPv4 (`network.py`), TCP/UDP (`transport.py`), DPI detector (`app_detector.py`), HTTP (`http_parser.py`), DNS (`dns_parser.py`), SMTP (`smtp_parser.py`).
- `src/pipeline.py`: Chuỗi xử lý bóc tách và khối bắt lỗi ngoại lệ tập trung.
- `src/logger.py`: Cơ chế xuất luồng dữ liệu định dạng JSON Lines.
- `main.py`: Giao diện dòng lệnh (CLI).
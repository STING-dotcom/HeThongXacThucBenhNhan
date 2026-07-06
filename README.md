# Gửi bệnh án với xác thực kép

## Cần làm trước khi chạy

Nếu chưa có thư viện, mở terminal gõ:
```
pip install pycryptodome
```
Nếu báo lỗi vàng ở dòng `import` hoặc `from`, bấm `Ctrl+Shift+P` → chọn `Python: Select Interpreter` → chọn đúng Python đang dùng.

**Riêng lần chạy đầu tiên** (nếu muốn tự đặt mật khẩu, không dùng mật khẩu mặc định):
```powershell
$env:PASSWORD_SERVER = "MatKhauBaoMat123"
```
Nếu bỏ qua bước này, Server tự động dùng mật khẩu `MatKhauBaoMat123` và báo cảnh báo.

## Cách chạy

1. Chạy **Server trước**: `python phong_luu_tru_server.py`
2. Chạy **Client sau**: `python bac_si_client.py`
3. Trên Client, gõ mật khẩu vào ô → bấm **"MÃ HÓA VÀ GỬI BỆNH ÁN"**

**Mật khẩu mặc định:** `MatKhauBaoMat123`

## Tổng quan

Gồm 2 phần mềm chạy cùng lúc:
- **Bác sĩ (Client):** Soạn bệnh án, gửi đi có mã hóa
- **Phòng lưu trữ (Server):** Nhận, kiểm tra, giải mã và hiển thị bệnh án

## Các lớp bảo vệ

Bệnh án được bảo vệ 4 lớp, tự động chạy khi bấm gửi:

| Lớp | Làm gì? |
|-----|---------|
| **Mã hóa nội dung** | Xào trộn nội dung, ai xem được mới đọc |
| **Chữ ký bác sĩ** | Server biết chắc bệnh án này do đúng bác sĩ gửi |
| **Mật khẩu** | Server đối chiếu thử thách + mật khẩu mới cho qua |
| **Vân tay dữ liệu** | Phát hiện nếu dữ liệu bị sửa trên đường truyền |

## Luồng chạy từng bước (kể chuyện)

1. Client chào Server: "Hello!"
2. Server đáp: "Ready!"
3. Client xin khóa: "YEU CAU KHOA"
4. Server gửi khóa công khai → Client gửi khóa công khai của mình
5. Server gửi một mã thử thách (nonce) cho Client
6. Client băm mật khẩu với mã thử thách đó, ký tên, mã hóa bệnh án → gửi hết lên Server
7. Server kiểm tra lần lượt: vân tay dữ liệu → chữ ký bác sĩ → mật khẩu
8. Nếu OK → giải mã, hiển thị nội dung, báo ACK
9. Nếu sai → báo NACK kèm lý do

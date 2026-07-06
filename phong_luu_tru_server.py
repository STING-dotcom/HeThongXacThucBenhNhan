import socket
import json
import base64
import os
import secrets
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256, SHA512
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import unpad

class PhongLuuTruServer:
    def __init__(self, root):
        self.root = root
        self.root.title("HỆ THỐNG PHÒNG LƯU TRỮ - TIẾP NHẬN BỆNH ÁN")
        self.root.geometry("650x550")
        
        # Cấu hình các tham số bảo mật ban đầu
        self.PASSWORD_GOC = os.environ.get("PASSWORD_SERVER")
        if not self.PASSWORD_GOC:
            self.PASSWORD_GOC = "MatKhauBaoMat123"  # fallback tạm thời cho demo
        
        # Khởi tạo khóa RSA
        self.cap_khoa = RSA.generate(2048)
        self.khoa_rieng = self.cap_khoa
        self.khoa_cong_khai = self.cap_khoa.publickey()
        self.khoa_cong_khai_bytes = self.khoa_cong_khai.export_key(format='PEM')
        
        self.tao_giao_dien()
        
        # Cảnh báo nếu dùng mật khẩu mặc định (sau khi GUI đã sẵn sàng)
        if not os.environ.get("PASSWORD_SERVER"):
            self.ghi_log("[CẢNH BÁO] Biến môi trường PASSWORD_SERVER chưa được thiết lập! Đang dùng mật khẩu mặc định. Vui lòng đặt biến môi trường PASSWORD_SERVER để bảo mật tốt hơn.")
        
        # Chạy Socket Server trên một luồng riêng biệt để tránh treo giao diện
        self.server_thread = threading.Thread(target=self.chay_server, daemon=True)
        self.server_thread.start()

    def tao_giao_dien(self):
        # Tiêu đề chính
        lbl_title = tk.Label(self.root, text="HỆ THỐNG XÁC THỰC KÉP & GIẢI MÃ BỆNH ÁN", font=("Arial", 14, "bold"), fg="blue")
        lbl_title.pack(pady=10)

        # Khu vực cấu hình mật khẩu hệ thống
        frame_pwd = tk.LabelFrame(self.root, text=" Cấu hình xác thực hệ thống ", font=("Arial", 10, "bold"), padx=10, pady=10)
        frame_pwd.pack(fill="x", padx=15, pady=5)
        
        lbl_pwd_info = tk.Label(frame_pwd, text="Mật khẩu hệ thống đã được cấu hình (xem biến môi trường PASSWORD_SERVER)", fg="green", font=("Arial", 10, "italic"))
        lbl_pwd_info.pack(anchor="w")

        # Khu vực hiển thị tiến trình nhật ký (Log)
        frame_log = tk.LabelFrame(self.root, text=" Nhật ký hệ thống (Tiến trình bảo mật) ", font=("Arial", 10, "bold"), padx=10, pady=10)
        frame_log.pack(fill="both", expand=True, padx=15, pady=5)
        
        self.txt_log = scrolledtext.ScrolledText(frame_log, height=12, font=("Courier New", 10))
        self.txt_log.pack(fill="both", expand=True)
        self.ghi_log("[HỆ THỐNG] Đã khởi tạo xong cặp khóa RSA 2048-bit.")
        self.ghi_log("[HỆ THỐNG] Đang sẵn sàng tiếp nhận kết nối...")

        # Khu vực hiển thị kết quả giải mã bệnh án
        frame_kq = tk.LabelFrame(self.root, text=" Nội dung bệnh án sau khi giải mã ", font=("Arial", 10, "bold"), padx=10, pady=10, fg="red")
        frame_kq.pack(fill="x", padx=15, pady=10)
        
        self.txt_benh_an = tk.Text(frame_kq, height=4, font=("Arial", 11), bg="#f0f0f0")
        self.txt_benh_an.pack(fill="x")

    def ghi_log(self, thong_diep):
        self.txt_log.insert(tk.END, thong_diep + "\n")
        self.txt_log.see(tk.END)

    def chay_server(self):
        HOST = '127.0.0.1'
        PORT = 65432
        
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((HOST, PORT))
        self.server_socket.listen(1)
        
        while True:
            try:
                conn, addr = self.server_socket.accept()
                self.ghi_log(f"\n[KẾT NỐI] Đã kết nối với máy Bác sĩ tại địa chỉ: {addr}")
                
                # 1. Bắt tay (Handshake)
                msg1 = conn.recv(1024).decode('utf-8')
                if msg1 == "Hello!":
                    self.ghi_log("[BẮT TAY] Nhận 'Hello!' từ Bác sĩ. Phản hồi 'Ready!'")
                    conn.sendall("Ready!".encode('utf-8'))
                
                # 2. Nhận yêu cầu từ Client và gửi khóa công khai RSA
                msg2 = conn.recv(1024).decode('utf-8')
                if msg2 == "YEU CAU KHOA":
                    conn.sendall(self.khoa_cong_khai_bytes)
                    self.ghi_log("[RSA] Đã gửi khóa công khai RSA cho Bác sĩ.")
                
                # 3. Nhận khóa công khai RSA của Client
                khoa_cong_khai_client_bytes = conn.recv(2048)
                khoa_cong_khai_client = RSA.import_key(khoa_cong_khai_client_bytes)
                self.ghi_log("[RSA] Đã nhận khóa công khai RSA của Bác sĩ.")
                
                # Xác nhận đã sẵn sàng nhận dữ liệu, kèm Nonce chống Replay Attack
                nonce = secrets.token_hex(16)
                self.nonce = nonce
                conn.sendall(f"SAN_SANG|{nonce}".encode('utf-8'))
                self.ghi_log("[NONCE] Đã gửi thử thách (nonce) cho Bác sĩ để xác thực Challenge-Response.")
                
                # 4. Nhận độ dài gói tin trước, rồi nhận dữ liệu
                data_len_bytes = conn.recv(4)
                data_len = int.from_bytes(data_len_bytes, byteorder='big')
                
                du_lieu_nhan = b""
                while len(du_lieu_nhan) < data_len:
                    packet = conn.recv(min(4096, data_len - len(du_lieu_nhan)))
                    if not packet:
                        break
                    du_lieu_nhan += packet
                
                if not du_lieu_nhan:
                    conn.close()
                    continue

                payload = json.loads(du_lieu_nhan.decode('utf-8'))
                
                # Tách các thành phần từ gói tin
                iv = base64.b64decode(payload["iv"])
                ciphertext = base64.b64decode(payload["cipher"])
                received_hash = payload["hash"]
                received_sig = base64.b64decode(payload["sig"])
                received_pwd_hash = payload["pwd"]
                encrypted_session_key = base64.b64decode(payload["enc_key"])
                metadata = payload["metadata"]
                
                self.ghi_log("\n--- BẮT ĐẦU QUY TRÌNH XÁC THỰC KÉP ---")
                
                # Kiểm tra 1: Tính toàn vẹn dữ liệu (SHA-512)
                h_toan_ven = SHA512.new(iv + ciphertext)
                hash_tu_tinh = h_toan_ven.hexdigest()
                if hash_tu_tinh != received_hash:
                    self.ghi_log("[X] THẤT BẠI: Dữ liệu bị thay đổi trên đường truyền (Sai SHA-512 Hash)!")
                    conn.sendall("NACK: Lỗi integrity".encode('utf-8'))
                    conn.close()
                    continue
                self.ghi_log("[✓] Kiểm tra toàn vẹn đạt: Dữ liệu trùng khớp (SHA-512).")
                
                # Kiểm tra 2: Chữ ký số RSA (Xác thực danh tính Bác sĩ)
                try:
                    h_metadata = SHA512.new(metadata.encode('utf-8'))
                    pkcs1_15.new(khoa_cong_khai_client).verify(h_metadata, received_sig)
                    self.ghi_log("[✓] Xác thực chữ ký số đạt: Chữ ký RSA hợp lệ.")
                except (ValueError, TypeError):
                    self.ghi_log("[X] THẤT BẠI: Chữ ký số không hợp lệ (Giả mạo Bác sĩ)!")
                    conn.sendall("NACK: Lỗi chữ ký".encode('utf-8'))
                    conn.close()
                    continue
                
                # Kiểm tra 3: Mật khẩu xác thực (Challenge-Response với Nonce)
                expected_hash = SHA256.new((self.nonce + self.PASSWORD_GOC).encode('utf-8')).hexdigest()
                if received_pwd_hash != expected_hash:
                    self.ghi_log("[X] THẤT BẠI: Sai mật khẩu xác thực truy cập phòng lưu trữ!")
                    conn.sendall("NACK: Lỗi mật khẩu".encode('utf-8'))
                    conn.close()
                    continue
                self.ghi_log("[✓] Xác thực mật khẩu Challenge-Response chính xác (nonce đã được kiểm tra).")
                
                # Giải mã khóa phiên AES bằng khóa riêng RSA (OAEP)
                try:
                    cipher_rsa = PKCS1_OAEP.new(self.khoa_rieng)
                    session_key = cipher_rsa.decrypt(encrypted_session_key)
                    self.ghi_log("[✓] Giải mã khóa phiên AES bằng RSA-OAEP thành công.")
                except Exception:
                    self.ghi_log("[X] THẤT BẠI: Không thể giải mã khóa phiên (Lỗi khóa RSA)!")
                    conn.sendall("NACK: Lỗi解码 khóa".encode('utf-8'))
                    conn.close()
                    continue
                
                # Giải mã dữ liệu bệnh án bằng AES-CBC
                cipher_aes = AES.new(session_key, AES.MODE_CBC, iv)
                plaintext_padded = cipher_aes.decrypt(ciphertext)
                plaintext = unpad(plaintext_padded, AES.block_size)
                
                noi_dung_goc = plaintext.decode('utf-8')
                id_benh_an = metadata.split("|")[2] if "|" in metadata and len(metadata.split("|")) > 2 else "N/A"
                self.ghi_log(f"[THÀNH CÔNG] Hồ sơ bệnh án (ID: {id_benh_an}) đã được giải mã thành công.")
                
                # Hiển thị nội dung lên giao diện
                self.txt_benh_an.delete("1.0", tk.END)
                self.txt_benh_an.insert(tk.END, noi_dung_goc)
                
                # Lưu file với tên từ metadata
                ten_file_goc = metadata.split("|")[0] if "|" in metadata else "medical_record.txt"
                with open(ten_file_goc, "w", encoding="utf-8") as f:
                    f.write(noi_dung_goc)
                
                # Gửi ACK về Client
                conn.sendall("ACK".encode('utf-8'))
                self.ghi_log("[ACK] Đã gửi xác nhận thành công về Bác sĩ.")
                
                messagebox.showinfo("Thành Công", "Hệ thống đã xác thực và tiếp nhận bệnh án an toàn!")
                conn.close()
                
            except Exception as e:
                self.ghi_log(f"[LỖI HỆ THỐNG] Có lỗi phát sinh: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = PhongLuuTruServer(root)
    root.mainloop()
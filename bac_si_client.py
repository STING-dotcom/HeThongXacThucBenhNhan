import socket
import json
import base64
import os
import time
import tkinter as tk
from tkinter import messagebox
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256, SHA512
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad

class BacSiClient:
    def __init__(self, root):
        self.root = root
        self.root.title("HỆ THỐNG BÁC SĨ - GỬI BỆNH ÁN BẢO MẬT")
        self.root.geometry("600x450")
        self.tao_giao_dien()

    def tao_giao_dien(self):
        # Tiêu đề
        lbl_title = tk.Label(self.root, text="CỔNG GỬI HỒ SƠ BỆNH ÁN AN TOÀN", font=("Arial", 14, "bold"), fg="darkgreen")
        lbl_title.pack(pady=15)

        # Ô nhập metadata
        frame_meta = tk.LabelFrame(self.root, text=" Metadata bệnh án ", font=("Arial", 10, "bold"), padx=10, pady=10)
        frame_meta.pack(fill="x", padx=15, pady=5)
        
        lbl_file = tk.Label(frame_meta, text="Tên file:")
        lbl_file.grid(row=0, column=0, sticky="w", pady=2)
        self.ent_file = tk.Entry(frame_meta, font=("Arial", 11), width=30)
        self.ent_file.grid(row=0, column=1, padx=5, pady=2)
        self.ent_file.insert(0, "medical_record.txt")
        
        lbl_id = tk.Label(frame_meta, text="ID bệnh án:")
        lbl_id.grid(row=1, column=0, sticky="w", pady=2)
        self.ent_id = tk.Entry(frame_meta, font=("Arial", 11), width=30)
        self.ent_id.grid(row=1, column=1, padx=5, pady=2)
        self.ent_id.insert(0, "BA-2026-001")

        # Ô nhập nội dung bệnh án
        frame_input = tk.LabelFrame(self.root, text=" Nhập nội dung bệnh án mật ", font=("Arial", 10, "bold"), padx=10, pady=10)
        frame_input.pack(fill="x", padx=15, pady=5)
        
        self.txt_input = tk.Text(frame_input, height=6, font=("Arial", 11))
        self.txt_input.pack(fill="x")
        self.txt_input.insert(tk.END, "HỒ SƠ BỆNH ÁN\n\nHọ tên: Hoàng Việt Anh\nTuổi: 20 tuổi\nGiới tính: Nam\nSố CMND/CCCD: 024201012345\nĐiện thoại: 0912345678\nĐịa chỉ: 123 Đường Lê Lợi, Quận 1, TP.HCM\n\nChẩn đoán: Viêm phổi nặng do khuẩn Streptococcus pneumoniae\nTình trạng: Sốt cao 39.5°C, ho nhiều, khó thở, X-quang phổi có infiltrate lan rộng\nXét nghiệm: WBC 15.200/mm³, CRP 85 mg/L, Procalcitonin 2.5 ng/mL\nPhác đồ điều trị: Truyền kháng sinh Ceftriaxone 2g/ngày + Azithromycin 500mg/ngày, truyền dịch ODS, theo dõi SpO2 liên tục\nGhi chú: Bệnh nhân có tiền sử hen phế quản nhẹ, cần theo dõi sát diễn biến hô hấp.")

        # Ô nhập mật khẩu xác thực kép
        frame_pwd = tk.LabelFrame(self.root, text=" Xác thực kép (Mật khẩu truy cập phòng nhận) ", font=("Arial", 10, "bold"), padx=10, pady=10)
        frame_pwd.pack(fill="x", padx=15, pady=10)
        
        lbl_pwd_hint = tk.Label(frame_pwd, text="Nhập mật khẩu:")
        lbl_pwd_hint.pack(side="left", padx=5)
        
        self.ent_pwd = tk.Entry(frame_pwd, show="*", font=("Arial", 11), width=30)
        self.ent_pwd.pack(side="left", padx=5)
        # Người dùng tự nhập mật khẩu - không hardcode

        # Nút bấm hành động Gửi dữ liệu
        self.btn_gui = tk.Button(self.root, text=" MÃ HÓA VÀ GỬI BỆNH ÁN ", font=("Arial", 12, "bold"), bg="green", fg="white", pady=8, command=self.xu_ly_gui_data)
        self.btn_gui.pack(pady=15)

    def xu_ly_gui_data(self):
        noi_dung_ba = self.txt_input.get("1.0", tk.END).strip()
        mat_khau_nhap = self.ent_pwd.get().strip()
        ten_file = self.ent_file.get().strip()
        id_benh_an = self.ent_id.get().strip()

        if not noi_dung_ba:
            messagebox.showwarning("Cảnh báo", "Vui lòng nhập nội dung bệnh án trước khi gửi!")
            return
        if not mat_khau_nhap:
            messagebox.showwarning("Cảnh báo", "Vui lòng nhập mật khẩu xác thực!")
            return

        HOST = '127.0.0.1'
        PORT = 65432

        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((HOST, PORT))
            
            # --- Bước 1: Bắt tay (Handshake) ---
            client_socket.sendall("Hello!".encode('utf-8'))
            phan_hoi = client_socket.recv(1024).decode('utf-8')
            
            if phan_hoi == "Ready!":
                # --- Bước 2: Yêu cầu khóa công khai RSA từ Server ---
                client_socket.sendall("YEU CAU KHOA".encode('utf-8'))
                khoa_cong_khai_bytes = client_socket.recv(2048)
                khoa_cong_khai_server = RSA.import_key(khoa_cong_khai_bytes)
                
                # Sinh khóa riêng RSA cho Client để ký số
                cap_khoa_client = RSA.generate(2048)
                khoa_rieng_client = cap_khoa_client
                khoa_cong_khai_client = cap_khoa_client.publickey()
                khoa_cong_khai_client_bytes = khoa_cong_khai_client.export_key(format='PEM')
                
                # Gửi khóa công khai RSA của Client cho Server
                client_socket.sendall(khoa_cong_khai_client_bytes)
                
                # Đợi Server xác nhận sẵn sàng, kèm Nonce chống Replay Attack
                xac_nhan = client_socket.recv(1024).decode('utf-8')
                parts = xac_nhan.split("|")
                if parts[0] != "SAN_SANG":
                    messagebox.showerror("Lỗi", "Server chưa sẵn sàng!")
                    client_socket.close()
                    return
                nonce = parts[1] if len(parts) > 1 else ""
                
                # --- Bước 3: Ký số metadata (tên file + timestamp + ID bệnh án) ---
                timestamp = str(int(time.time()))
                metadata = f"{ten_file}|{timestamp}|{id_benh_an}"
                h_metadata = SHA512.new(metadata.encode('utf-8'))
                signature = pkcs1_15.new(khoa_rieng_client).sign(h_metadata)
                
                # --- Bước 4: Mã hóa dữ liệu ---
                khoa_phien_aes = os.urandom(32)
                iv = os.urandom(16)
                cipher_aes = AES.new(khoa_phien_aes, AES.MODE_CBC, iv)
                du_lieu_ma_hoa = cipher_aes.encrypt(pad(noi_dung_ba.encode('utf-8'), AES.block_size))
                
                # Tính hash toàn vẹn SHA-512(IV || ciphertext)
                h_toan_ven = SHA512.new(iv + du_lieu_ma_hoa)
                hash_toan_ven_str = h_toan_ven.hexdigest()
                
                # Mã hóa khóa phiên bằng RSA-OAEP (khóa công khai Server)
                cipher_rsa = PKCS1_OAEP.new(khoa_cong_khai_server)
                khoa_phien_ma_hoa_rsa = cipher_rsa.encrypt(khoa_phien_aes)
                
                # Băm mật khẩu SHA-256 với Nonce (Challenge-Response chống Replay Attack)
                hash_mat_khau_sha256 = SHA256.new((nonce + mat_khau_nhap).encode('utf-8')).hexdigest()
                
                # Đóng gói JSON theo yêu cầu đề bài
                goi_tin_json = {
                    "iv": base64.b64encode(iv).decode('utf-8'),
                    "cipher": base64.b64encode(du_lieu_ma_hoa).decode('utf-8'),
                    "hash": hash_toan_ven_str,
                    "sig": base64.b64encode(signature).decode('utf-8'),
                    "pwd": hash_mat_khau_sha256,
                    "enc_key": base64.b64encode(khoa_phien_ma_hoa_rsa).decode('utf-8'),
                    "metadata": metadata
                }
                
                # Gửi độ dài gói tin trước, rồi gửi dữ liệu
                json_data = json.dumps(goi_tin_json).encode('utf-8')
                data_len = len(json_data)
                client_socket.sendall(data_len.to_bytes(4, byteorder='big'))
                client_socket.sendall(json_data)
                
                # Đợi phản hồi ACK/NACK từ Server
                phan_hoi_server = client_socket.recv(1024).decode('utf-8')
                if phan_hoi_server == "ACK":
                    messagebox.showinfo("Thành Công", "Bệnh án đã được xác thực và truyền đi thành công!")
                else:
                    messagebox.showerror("Lỗi", f"Server từ chối: {phan_hoi_server}")
                
            client_socket.close()
            
        except ConnectionRefusedError:
            messagebox.showerror("Lỗi Kết Nối", "Không thể kết nối tới phòng lưu trữ! Hãy đảm bảo ứng dụng Server đang chạy.")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Có lỗi xảy ra: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = BacSiClient(root)
    root.mainloop()
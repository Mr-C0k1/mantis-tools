# 🛡️ Mantis-Tools v1.0
**Mantis-Tools** adalah *Hybrid Offensive Security Framework* yang menggabungkan kecepatan **Golang** untuk pemindaian jaringan massal dengan kecerdasan **Python** untuk analisis eksploitasi tingkat lanjut.

## 🚀 Fitur Utama
- **⚡ High-Speed Recon:** Pemindaian port berbasis *Goroutines* yang mampu menangani ribuan port dalam hitungan detik.
- **🔍 Expert Banner Grabbing:** Identifikasi layanan dan versi secara real-time.
- **💀 Advanced Exploit Engine:** Otomatisasi pencarian miskonfigurasi kritis seperti `.env` exposure, `.git` leaks, dan S3 Bucket misconfigs.
- **📊 Aesthetic Dashboard:** Terminal User Interface (TUI) yang informatif dan elegan menggunakan library *Rich*.
- **📝 Auto-Reporting:** Hasil pemindaian disimpan secara otomatis dalam format JSON untuk kebutuhan audit.

---

## 🛠️ Teknologi yang Digunakan
| Komponen | Bahasa | Fungsi |
| :--- | :--- | :--- |
| **Engine** | Golang | Performa tinggi, Networking, Concurrency |
| **Orchestrator** | Python 3 | Logika Eksploitasi, API Integration, TUI |
| **Intel** | Shodan API | Pengayaan data kerentanan global |

---

## 📦 Instalasi
Cukup jalankan satu perintah untuk menyiapkan seluruh lingkungan:

# Clone repository
git clone [https://github.com/username-anda/mantis-tools.git](https://github.com/username-anda/mantis-tools.git)
cd mantis-tools
# jalankan installer ( membutuhkan akses sudo untuk setuo global command )
chmod +x installer.sh
./installer.sh

# 📖 Cara Penggunaan
Gunakan perintah mantis-tools dari terminal mana saja
# Menampilkan bantuan
mantis-tools -h

# Pemindaian standar (Hanya Recon)
mantis-tools -t 192.168.1.1

# Mode Expert (Recon + Exploitation)
mantis-tools -t target.com -e -w 500

Argumen:
-t : Target IP atau Domain.
-e : Mengaktifkan modul eksploitasi otomatis.
-w : Jumlah worker/thread (default: 100).
📸 Tampilan Dashboard
⚠️ Disclaimer
Penggunaan Mantis-Tools untuk menyerang target tanpa izin tertulis sebelumnya adalah ilegal. Penulis tidak bertanggung jawab atas penyalahgunaan atau kerusakan yang disebabkan oleh program ini. Gunakan hanya untuk tujuan edukasi dan ethical hacking.
📜 Lisensi
Didistribusikan di bawah MIT License. Lihat file LICENSE untuk informasi lebih lanjut.
Developed with ❤️ by Mr-C0k1
chmod +x installer.sh
./installer.sh

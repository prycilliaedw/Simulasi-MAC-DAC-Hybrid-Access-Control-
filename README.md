# Simulasi-MAC-DAC-Hybrid-Access-Control-
Menyimulasikan bagaimana keputusan akses dibuat berdasarkan aturan MAC dan DAC secara berurutan.

# ------------------------------------------
# Sistem Keamanan Hibrida MAC + DAC
# ------------------------------------------

# MAC: aturan wajib (Level Keamanan: Semakin tinggi angka, semakin sensitif)
security_levels = {
    "Publik": 1,
    "Internal": 2,
    "Rahasia": 3,
    "Sangat Rahasia": 4
}

# MAC: klasifikasi objek
object_classification = {
    "laporan_audit_2025": {
        "level": "Rahasia",
        "department": "Keuangan"
    },
    "memo_internal_2024": {
        "level": "Internal",
        "department": "Keuangan"
    },
    "data_marketing_publik": {
        "level": "Publik",
        "department": "Marketing"
    }
}

# Informasi pengguna (level keamanan dan departemen)
users = {
    "budi": {
        "level": "Internal",
        "department": "Keuangan"
    },
    "susi": {
        "level": "Rahasia",
        "department": "Keuangan"
    },
    "andre": {
        "level": "Rahasia",
        "department": "Risk Management"
    },
    "dina": {
        "level": "Publik",
        "department": "Marketing"
    }
}

# DAC: Access Control List (ACL)
acls = {
    "laporan_audit_2025": {
        "allowed_users": ["susi", "andre"]  # Pemilik file memberi izin ke susi & andre
    },
    "memo_internal_2024": {
        "allowed_users": ["budi", "susi"]
    },
    "data_marketing_publik": {
        "allowed_users": ["dina"]
    }
}

# ---------------------------------------------------------
# Fungsi keputusan akses (MAC diperiksa dulu, lalu DAC)
# ---------------------------------------------------------
def check_access(username, obj):
    """
    Memeriksa izin akses berdasarkan aturan MAC dan DAC.
    Urutan: MAC (Level) -> MAC (Kategori/Departemen) -> DAC (ACL).
    """
    # 0. Periksa ketersediaan data
    user = users.get(username)
    if not user:
        return f"DITOLAK: Pengguna '{username}' tidak ditemukan."

    obj_info = object_classification.get(obj)
    if not obj_info:
        return f"DITOLAK: Objek '{obj}' tidak ditemukan."

    # --- 1. MAC CHECK: Level Keamanan (Prinsip: No Read Up) ---
    # Level pengguna harus SAMA atau LEBIH TINGGI dari level objek
    user_level = security_levels[user["level"]]
    obj_level = security_levels[obj_info["level"]]

    if user_level < obj_level:
        print(f"-> GAGAL MAC (Level): Pengguna level {user['level']} (Level {user_level}) < Objek level {obj_info['level']} (Level {obj_level})")
        return "DITOLAK oleh MAC: level keamanan tidak cukup (No Read Up)"

    # --- 2. MAC CHECK: Kategori Departemen ---
    # Pengguna harus berada di departemen yang SAMA dengan objek (asumsi kategori wajib)
    if user["department"] != obj_info["department"]:
        print(f"-> GAGAL MAC (Departemen): Pengguna departemen '{user['department']}' != Objek departemen '{obj_info['department']}'")
        return "DITOLAK oleh MAC: departemen tidak sesuai"

    # --- 3. DAC CHECK: Access Control List (ACL) ---
    # Pengguna harus terdaftar secara eksplisit di daftar yang diizinkan (allowed_users)
    allowed_list = acls.get(obj, {}).get("allowed_users", [])

    if username not in allowed_list:
        print(f"-> GAGAL DAC (ACL): Pengguna '{username}' tidak ada dalam ACL: {allowed_list}")
        return "DITOLAK oleh DAC: tidak ada izin ACL"

    # --- 4. Jika semua lulus ---
    return "DIIZINKAN: Akses diberikan"

# ---------------------------------------------------------
# Interaksi Pengguna
# ---------------------------------------------------------
def run_simulation():
    """Menjalankan loop interaktif untuk input pengguna."""
    print("\n## SIMULASI AKSES HIBRIDA MAC + DAC ##")
    print(f"Pengguna tersedia: {', '.join(users.keys())}")
    print(f"Objek tersedia: {', '.join(object_classification.keys())}\n")

    while True:
        try:
            # Input Nama Pengguna
            user_input = input("Masukkan Nama Pengguna (atau 'exit' untuk keluar): ").strip().lower()
            if user_input == 'exit':
                break

            if user_input not in users:
                print("Pengguna tidak valid. Coba lagi.")
                continue

            # Input Nama Objek
            obj_input = input("Masukkan Nama Objek yang ingin diakses: ").strip().lower()

            if obj_input not in object_classification:
                print("Objek tidak valid. Coba lagi.")
                continue

            # Cek Akses
            print("\n>>> Memeriksa Akses...")
            result = check_access(user_input, obj_input)
            print(f"HASIL AKHIR: {user_input.upper()} ingin mengakses {obj_input.upper()} --> {result}\n")

        except Exception as e:
            print(f"\n[ERROR] Terjadi kesalahan: {e}. Silakan coba lagi.\n")

if __name__ == "__main__":
    run_simulation()

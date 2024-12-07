from scapy.all import sniff, IP, ICMP, TCP, UDP
import socket

# Cihazın gerçek IP adresini almak
def get_local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        return local_ip
    except Exception as e:
        print(f"Hata: {e}")
        return "127.0.0.1"

# Tespit edilen IP adreslerini kaydetmek için bir liste
detected_ips = []

def detect_attack(packet):
    target_ip = get_local_ip()  # Hedef IP adresi (Cihazın kendi IP'si)

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Cihaza yapılan trafiği kontrol et
        if dst_ip == target_ip:
            if packet.haslayer(ICMP):
                # Ping tespiti
                if src_ip not in detected_ips:
                    detected_ips.append(src_ip)
                    print(f"Tespit (Ping) --> {src_ip}")

            elif packet.haslayer(TCP):
                # TCP Connect taraması tespiti
                if src_ip not in detected_ips:
                    detected_ips.append(src_ip)
                    print(f"Tespit (TCP Connect) --> {src_ip}")

            elif packet.haslayer(UDP):
                # UDP taraması tespiti
                if src_ip not in detected_ips:
                    detected_ips.append(src_ip)
                    print(f"Tespit (UDP) --> {src_ip}")

# Trafiği dinleme fonksiyonu
def start_firewall():
    local_ip = get_local_ip()
    print("Firewall başlatıldı. Ağ trafiği dinleniyor...")
    print(f"Cihaz IP: {local_ip}")
    sniff(prn=detect_attack, store=False)

if __name__ == "__main__":
    start_firewall()

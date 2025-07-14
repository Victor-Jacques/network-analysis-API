import datetime
import threading
from scapy.layers.inet import IP, TCP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw
from scapy.sendrecv import sniff
from scapy.all import get_if_list
from backend.database import HTTPRequest

def save_packet_to_db(packet_data: HTTPRequest, body: str):
    print("-" * 50)
    print("Pacote Capturado:\n")
    print(packet_data.model_dump_json(indent=4))
    print("Corpo da requisição HTTP:")
    print(body)
    print("-" * 50)

def process_packet(packet):

    if packet.haslayer(ICMP):
        print("Pacote ICMP (ping) capturado:", packet.summary())

    if not (packet.haslayer(TCP) and (packet.haslayer(IP) or packet.haslayer(IPv6)) and packet.haslayer(Raw)):
        return

    if packet[TCP].dport == 80:
        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            lines = payload.splitlines()
            if lines and "HTTP" in lines[0]:
                request_line = lines[0]
                method, path, _ = request_line.split(' ')
                host = ""
                for line in lines:
                    if line.lower().startswith("host:"):
                        host = line.split(':', 1)[1].strip()
                        break
                # Captura o corpo da requisição (após a linha em branco)
                if "" in lines:
                    idx = lines.index("")
                    body = "\n".join(lines[idx+1:])
                else:
                    body = ""
                src = packet[IP].src if packet.haslayer(IP) else packet[IPv6].src
                dst = packet[IP].dst if packet.haslayer(IP) else packet[IPv6].dst
                packet_data = HTTPRequest(
                    timestamp=datetime.datetime.now(),
                    source_ip=src,
                    destination_ip=dst,
                    destination_port=packet[TCP].dport,
                    http_method=method,
                    host=host,
                    path=path
                )
                save_packet_to_db(packet_data, body)
        except Exception as e:
            print(f"Erro ao processar pacote: {e}")

def main():
    print("Iniciando o sniffer em todas as interfaces (sem filtro)...")
    interfaces = get_if_list()
    threads = []
    for iface in interfaces:
        t = threading.Thread(target=sniff, kwargs={
            "prn": process_packet,
            "store": 0,
            "iface": iface
        })
        t.daemon = True
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

if __name__ == "__main__":
    main()
"""
netlab - analisador de tráfego de rede

Camadas feitas:
  1. IPs mais "falados" (mais pacotes)
  2. Domínios contactados (consultas DNS)
  3. Sinais de port scan (um IP a tentar muitas portas/destinos diferentes)

Uso: py src/analyze.py caminho/para/ficheiro.pcap
"""

import sys
from collections import Counter, defaultdict

from scapy.all import rdpcap, IP, TCP, DNS, DNSQR


def top_ips(pacotes, top_n=10):
    contagem = Counter()
    for pacote in pacotes:
        if IP in pacote:
            contagem[pacote[IP].src] += 1
            contagem[pacote[IP].dst] += 1

    print(f"Top {top_n} IPs mais falados:")
    for ip, n in contagem.most_common(top_n):
        print(f"  {ip:<20} {n} pacotes")


def dominios_contactados(pacotes, top_n=15):
    dominios = Counter()
    for pacote in pacotes:
        if pacote.haslayer(DNS) and pacote.haslayer(DNSQR) and pacote[DNS].qr == 0:  # qr=0 -> é um pedido
            nome = pacote[DNSQR].qname.decode(errors="ignore").rstrip(".")
            dominios[nome] += 1

    print(f"\nDomínios contactados (top {top_n}):")
    if not dominios:
        print("  (nenhuma consulta DNS encontrada)")
    for dominio, n in dominios.most_common(top_n):
        print(f"  {dominio:<40} {n} pedidos")


def possivel_port_scan(pacotes, limite_portas=15):
    """
    Um IP a INICIAR ligações (pacotes SYN, sem ACK) para muitas portas de
    destino diferentes é o padrão clássico de port scan.

    Nota: só contamos SYN puro (pedido de ligação), não SYN-ACK nem ACK.
    Contar todos os pacotes TCP/UDP dava falsos positivos: um servidor DNS
    a responder a muitos clientes em portas efémeras diferentes parecia
    "portas diferentes", mas é só ele a responder, não a tentar ligar-se.
    """
    portas_por_origem = defaultdict(set)

    for pacote in pacotes:
        if IP in pacote and TCP in pacote:
            flags = pacote[TCP].flags
            eh_syn_puro = "S" in flags and "A" not in flags
            if eh_syn_puro:
                origem = pacote[IP].src
                portas_por_origem[origem].add(pacote[TCP].dport)

    suspeitos = {ip: portas for ip, portas in portas_por_origem.items() if len(portas) >= limite_portas}

    print(f"\nPossível port scan (>= {limite_portas} portas destino distintas):")
    if not suspeitos:
        print("  (nada encontrado com este limite)")
    for ip, portas in sorted(suspeitos.items(), key=lambda x: -len(x[1])):
        print(f"  {ip:<20} tentou {len(portas)} portas diferentes")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: py src/analyze.py caminho/para/ficheiro.pcap")
        sys.exit(1)

    pacotes = rdpcap(sys.argv[1])
    print(f"Total de pacotes: {len(pacotes)}\n")

    top_ips(pacotes)
    dominios_contactados(pacotes)
    possivel_port_scan(pacotes)

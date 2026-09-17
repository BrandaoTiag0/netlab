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

from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR


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
        if pacote.haslayer(DNSQR) and pacote[DNS].qr == 0:  # qr=0 -> é um pedido
            nome = pacote[DNSQR].qname.decode(errors="ignore").rstrip(".")
            dominios[nome] += 1

    print(f"\nDomínios contactados (top {top_n}):")
    if not dominios:
        print("  (nenhuma consulta DNS encontrada)")
    for dominio, n in dominios.most_common(top_n):
        print(f"  {dominio:<40} {n} pedidos")


def possivel_port_scan(pacotes, limite_portas=15):
    """
    Um IP a falar com muitas portas de destino diferentes (no mesmo ou em
    poucos destinos) é o padrão clássico de port scan.
    """
    portas_por_origem = defaultdict(set)

    for pacote in pacotes:
        if IP in pacote and (TCP in pacote or UDP in pacote):
            origem = pacote[IP].src
            porta_destino = pacote[TCP].dport if TCP in pacote else pacote[UDP].dport
            portas_por_origem[origem].add(porta_destino)

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

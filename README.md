# netlab

Analisador de tráfego de rede em Python. Recebe um ficheiro `.pcap` e diz o que se passou: que máquinas falaram com quê, que domínios foram contactados, e sinais de atividade suspeita (port scan, DNS tunneling, beaconing).

Alimentado com capturas reais de infeções de malware (fonte: [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/)).

## Estado atual

- [x] Ler um `.pcap` e listar os 10 IPs mais falados
- [x] Listar domínios contactados (DNS)
- [x] Detetor de port scan
- [ ] Detetor de beaconing (desvio-padrão dos intervalos entre pacotes)
- [ ] Detetor de DNS tunneling

## Uso

```bash
py -m pip install -r requirements.txt
py src/analyze.py captures/exemplo.pcap
```

Coloca os ficheiros `.pcap` descarregados em `captures/` (pasta ignorada pelo git — ver `.gitignore`).

## Análises

### 2026-02-28 — "Easy As 123" (NetSupport Manager RAT)
Fonte: [malware-traffic-analysis.net, 2026-02-28](https://www.malware-traffic-analysis.net/2026/02/28/index.html)

- Host infetado: `10.2.28.88` (o mais falado da captura, 14673 pacotes)
- IP malicioso confirmado pelo exercício: `45.131.214.85` — aparece na lista de top IPs (550 pacotes), consistente com C2 do NetSupport RAT
- Domínios DNS revelam o ambiente: `wpad.easyas123.tech` e o registo LDAP em `easyas123.tech` mostram o domínio Windows da empresa; o resto é tráfego normal do Windows/Office (Microsoft, MSN, Bing)
- Port scan: nada encontrado — correto, este exercício não é sobre scanning

**Bug/lição encontrada:** a 1ª versão do detetor de port scan contava todos os pacotes TCP/UDP, e apanhava o servidor DNS (`10.2.28.2`) como "suspeito" (379 portas diferentes) — mas isso era só ele a RESPONDER a pedidos de clientes em portas efémeras, não a tentar ligar-se a ninguém. Corrigido para só contar pacotes SYN puro (pedido de ligação real, sem ACK). Boa lição de como um detetor ingénuo dá falsos positivos.

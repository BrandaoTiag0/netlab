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

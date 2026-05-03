# Arquitetura do PulseNOC AI

```text
Usuário no navegador
        ↓
Dashboard HTML/CSS/JS + Chart.js
        ↓
Backend FastAPI
        ↓
Coleta de métricas:
- Ping / ICMP
- HTTP / HTTPS
- Portas TCP
- Conexões TCP 80/443
- Hosts recentes
- CPU e RAM via psutil
        ↓
Histerese anti-flapping
        ↓
API Gemini
        ↓
Diagnóstico inteligente no dashboard
```

## Camadas

1. **Frontend**: dashboard moderno, tabelas, cards e gráficos.
2. **Backend**: FastAPI fornece endpoints `/api/metrics`, `/api/history` e `/api/analyze`.
3. **Coleta local**: psutil, ping, requests e sockets.
4. **IA**: Gemini API para análise e classificação.
5. **Histerese**: evita alarmes falsos quando CPU ou RAM oscilam perto do limite.

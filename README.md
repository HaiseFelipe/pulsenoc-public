# PulseNOC AI

Ferramenta local de monitoramento de redes com dashboard web moderno, coleta de tráfego recente, CPU, memória RAM, histerese anti-flapping e integração real com IA via Gemini API.

## Funcionalidades

- Ping periódico para medir disponibilidade e latência.
- Monitoramento HTTP/HTTPS.
- Verificação de portas TCP.
- Identificação de conexões TCP nas portas 80/443.
- Hosts acessados recentemente.
- DNS queries estimadas por resolução reversa.
- Monitoramento de CPU e memória RAM.
- Histerese para reduzir alertas falsos por oscilação.
- Diagnóstico automático com IA.

## Como rodar

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Acesse:

```text
http://127.0.0.1:8000
```

## Configuração

Copie `.env.example` para `.env` e coloque sua chave da Gemini:

```env
GEMINI_API_KEY=sua_chave_aqui
GEMINI_MODEL=gemini-2.5-flash-lite
PING_TARGETS=127.0.0.1,google.com
HTTP_TARGETS=https://google.com
PORT_TARGETS=google.com:443
CPU_WARNING=70
CPU_CRITICAL=85
MEM_WARNING=75
MEM_CRITICAL=90
HYSTERESIS_RECOVERY_GAP=10
```



## Explicação rápida

O PulseNOC AI coleta métricas reais de rede e do host local. A histerese evita flapping: o alerta só volta para normal quando CPU ou RAM caem abaixo do limite de warning menos uma margem de recuperação. A IA recebe os dados e gera classificação, causa provável, insight de tráfego e ações recomendadas.

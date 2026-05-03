import asyncio
import json
import os
import platform
import socket
import statistics
import subprocess
import time
from collections import Counter, deque
from datetime import datetime
from pathlib import Path
from typing import Any

import psutil
import requests
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

APP_NAME = "PulseNOC AI"

app = FastAPI(title=APP_NAME, version="3.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

STATIC_DIR = BASE_DIR / "app" / "static"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

PING_TARGETS = [x.strip() for x in os.getenv("PING_TARGETS", "127.0.0.1,google.com").split(",") if x.strip()]
HTTP_TARGETS = [x.strip() for x in os.getenv("HTTP_TARGETS", "https://google.com").split(",") if x.strip()]
PORT_TARGETS_RAW = [x.strip() for x in os.getenv("PORT_TARGETS", "google.com:443").split(",") if x.strip()]
PORT_TARGETS: list[tuple[str, int]] = []
for item in PORT_TARGETS_RAW:
    if ":" in item:
        host, port = item.rsplit(":", 1)
        try:
            PORT_TARGETS.append((host, int(port)))
        except ValueError:
            pass

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash-lite")

CPU_WARNING = float(os.getenv("CPU_WARNING", "70"))
CPU_CRITICAL = float(os.getenv("CPU_CRITICAL", "85"))
MEM_WARNING = float(os.getenv("MEM_WARNING", "75"))
MEM_CRITICAL = float(os.getenv("MEM_CRITICAL", "90"))
HYSTERESIS_RECOVERY_GAP = float(os.getenv("HYSTERESIS_RECOVERY_GAP", "10"))

history: deque[dict[str, Any]] = deque(maxlen=60)
hysteresis_state = {"cpu": "normal", "memory": "normal"}


class AnalyzeRequest(BaseModel):
    data: dict[str, Any]


def _decode_ping_output(raw_bytes: bytes) -> str:
    for encoding in ("cp850", "cp1252", "utf-8", "latin-1"):
        try:
            return raw_bytes.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw_bytes.decode("utf-8", errors="replace")


def _ping_reachable_from_output(output: str, returncode: int) -> bool:
    if returncode == 0:
        return True

    output_lower = output.lower()
    success_markers = ("tempo=", "ttl=", "bytes=", "time=")
    return any(marker in output_lower for marker in success_markers)


def _run_ping_sync(host: str) -> dict[str, Any]:
    system = platform.system().lower()

    cmd = (
        ["ping", "-n", "1", "-w", "1000", host]
        if "windows" in system
        else ["ping", "-c", "1", "-W", "1", host]
    )

    started = time.perf_counter()

    try:
        result = subprocess.run(cmd, capture_output=True, timeout=3)
        elapsed_ms = round((time.perf_counter() - started) * 1000, 2)

        raw_bytes = (result.stdout or b"") + (result.stderr or b"")
        output = _decode_ping_output(raw_bytes)

        reachable = _ping_reachable_from_output(output, result.returncode)

        return {
            "target": host,
            "reachable": reachable,
            "latency_ms": elapsed_ms if reachable else None,
            "packet_loss_percent": 0 if reachable else 100,
            "raw": output[:300],
        }

    except subprocess.TimeoutExpired:
        return {
            "target": host,
            "reachable": False,
            "latency_ms": None,
            "packet_loss_percent": 100,
            "raw": "Timeout ao aguardar resposta do ping",
        }

    except Exception as exc:
        return {
            "target": host,
            "reachable": False,
            "latency_ms": None,
            "packet_loss_percent": 100,
            "raw": str(exc),
        }


async def ping_host(host: str) -> dict[str, Any]:
    return await asyncio.to_thread(_run_ping_sync, host)


async def check_http(url: str) -> dict[str, Any]:
    def _do_request() -> dict[str, Any]:
        started = time.perf_counter()

        try:
            response = requests.get(url, timeout=4)
            elapsed_ms = round((time.perf_counter() - started) * 1000, 2)

            return {
                "target": url,
                "ok": response.ok,
                "status_code": response.status_code,
                "response_ms": elapsed_ms,
            }

        except Exception as exc:
            return {
                "target": url,
                "ok": False,
                "status_code": None,
                "response_ms": None,
                "error": str(exc),
            }

    return await asyncio.to_thread(_do_request)


async def check_port(host: str, port: int) -> dict[str, Any]:
    started = time.perf_counter()

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=2
        )

        elapsed_ms = round((time.perf_counter() - started) * 1000, 2)

        writer.close()
        await writer.wait_closed()

        return {
            "target": f"{host}:{port}",
            "open": True,
            "connect_ms": elapsed_ms,
        }

    except Exception as exc:
        return {
            "target": f"{host}:{port}",
            "open": False,
            "connect_ms": None,
            "error": str(exc),
        }


def reverse_dns(ip: str) -> str | None:
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return None


def process_name_from_pid(pid: int | None) -> str:
    if not pid:
        return "desconhecido"

    try:
        return psutil.Process(pid).name()
    except Exception:
        return "desconhecido"


def collect_recent_hosts() -> dict[str, Any]:
    tcp_connections: list[dict[str, Any]] = []
    hosts: list[str] = []

    try:
        for conn in psutil.net_connections(kind="inet"):
            if not conn.raddr:
                continue

            remote_ip = getattr(conn.raddr, "ip", None)
            remote_port = getattr(conn.raddr, "port", None)

            if not remote_ip or remote_port not in (80, 443):
                continue

            local_ip = getattr(conn.laddr, "ip", None) if conn.laddr else None
            local_port = getattr(conn.laddr, "port", None) if conn.laddr else None

            host_name = reverse_dns(remote_ip) or remote_ip

            item = {
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "host": host_name,
                "status": conn.status,
                "pid": conn.pid,
                "process": process_name_from_pid(conn.pid),
            }

            tcp_connections.append(item)
            hosts.append(host_name)

    except Exception:
        pass

    counts = Counter(hosts)

    recent_hosts = [
        {
            "host": host,
            "count": count,
        }
        for host, count in counts.most_common(10)
    ]

    dns_queries = [
        {
            "query": item["host"],
            "type": "A/AAAA (estimado)",
        }
        for item in recent_hosts
    ]

    return {
        "tcp_80_443": tcp_connections[:30],
        "recent_hosts": recent_hosts,
        "dns_queries": dns_queries,
        "stats": {
            "tcp_web_connections": len(tcp_connections),
            "https_connections": sum(1 for item in tcp_connections if item["remote_port"] == 443),
            "http_connections": sum(1 for item in tcp_connections if item["remote_port"] == 80),
            "unique_hosts": len(counts),
        },
    }


def get_system_metrics() -> dict[str, Any]:
    cpu_percent = psutil.cpu_percent(interval=0.25)
    memory = psutil.virtual_memory()

    return {
        "cpu_percent": round(cpu_percent, 2),
        "memory_percent": round(memory.percent, 2),
        "memory_total_gb": round(memory.total / (1024 ** 3), 2),
        "memory_used_gb": round(memory.used / (1024 ** 3), 2),
    }


def apply_hysteresis(
    metric_name: str,
    value: float,
    warning: float,
    critical: float,
    recovery_gap: float
) -> str:
    previous = hysteresis_state.get(metric_name, "normal")

    if value >= critical:
        current = "critical"
    elif value >= warning:
        current = "warning"
    elif previous in ("warning", "critical") and value >= (warning - recovery_gap):
        current = previous
    else:
        current = "normal"

    hysteresis_state[metric_name] = current
    return current


def status_rank(status: str) -> int:
    return {
        "normal": 0,
        "warning": 1,
        "critical": 2,
    }.get(status, 1)


def classify_status(summary: dict[str, Any]) -> str:
    statuses: list[str] = []

    if summary["ping_failures"] >= max(1, summary["ping_targets_count"]):
        statuses.append("critical")

    if summary["http_failures"] > 0 or summary["closed_ports"] > 0:
        statuses.append("warning")

    if summary["avg_latency_ms"] is not None and summary["avg_latency_ms"] > 180:
        statuses.append("warning")

    statuses.extend([
        summary.get("cpu_status", "normal"),
        summary.get("memory_status", "normal"),
    ])

    return max(statuses or ["normal"], key=status_rank)


async def collect_metrics() -> dict[str, Any]:
    ping_results = await asyncio.gather(
        *(ping_host(host) for host in PING_TARGETS)
    )

    http_results = await asyncio.gather(
        *(check_http(url) for url in HTTP_TARGETS)
    )

    port_results = await asyncio.gather(
        *(check_port(host, port) for host, port in PORT_TARGETS)
    )

    traffic = await asyncio.to_thread(collect_recent_hosts)
    system_metrics = await asyncio.to_thread(get_system_metrics)

    cpu_status = apply_hysteresis(
        "cpu",
        system_metrics["cpu_percent"],
        CPU_WARNING,
        CPU_CRITICAL,
        HYSTERESIS_RECOVERY_GAP,
    )

    memory_status = apply_hysteresis(
        "memory",
        system_metrics["memory_percent"],
        MEM_WARNING,
        MEM_CRITICAL,
        HYSTERESIS_RECOVERY_GAP,
    )

    latencies = [
        item["latency_ms"]
        for item in ping_results
        if item["latency_ms"] is not None
    ]

    avg_latency = round(statistics.mean(latencies), 2) if latencies else None

    summary = {
        "avg_latency_ms": avg_latency,
        "ping_failures": sum(1 for item in ping_results if not item["reachable"]),
        "http_failures": sum(1 for item in http_results if not item["ok"]),
        "closed_ports": sum(1 for item in port_results if not item["open"]),
        "ping_targets_count": len(ping_results),
        "http_targets_count": len(http_results),
        "port_targets_count": len(port_results),
        "web_connections": traffic["stats"]["tcp_web_connections"],
        "unique_hosts": traffic["stats"]["unique_hosts"],
        "cpu_percent": system_metrics["cpu_percent"],
        "memory_percent": system_metrics["memory_percent"],
        "cpu_status": cpu_status,
        "memory_status": memory_status,
    }

    summary["overall_status"] = classify_status(summary)

    snapshot = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "app_name": APP_NAME,
        "summary": summary,
        "ping": ping_results,
        "http": http_results,
        "ports": port_results,
        "traffic": traffic,
        "system": {
            **system_metrics,
            "cpu_status": cpu_status,
            "memory_status": memory_status,
            "hysteresis": {
                "cpu_warning": CPU_WARNING,
                "cpu_critical": CPU_CRITICAL,
                "memory_warning": MEM_WARNING,
                "memory_critical": MEM_CRITICAL,
                "recovery_gap": HYSTERESIS_RECOVERY_GAP,
                "description": "Recupera para normal apenas quando a métrica cai abaixo do limite de warning menos a margem de recuperação.",
            },
        },
    }

    history.append(snapshot)
    return snapshot


def build_ai_prompt(data: dict[str, Any]) -> str:
    compact = json.dumps(data, ensure_ascii=False, indent=2)

    return f"""
Você é um analista de NOC e observabilidade.
Analise os dados abaixo e responda em JSON válido.

Campos obrigatórios:
- classification: normal | alerta | critico
- title: um título curto do incidente
- summary: resumo curto em português
- probable_cause: causa provável curta
- recommended_actions: lista com 3 ações curtas
- traffic_insight: leitura curta sobre hosts acessados e conexões TCP 80/443
- system_insight: leitura curta sobre CPU, memória RAM e histerese

Dados:
{compact}
""".strip()


def call_gemini(data: dict[str, Any]) -> dict[str, Any]:
    if not GEMINI_API_KEY:
        return {
            "classification": "alerta",
            "title": "IA não configurada",
            "summary": "Configure a GEMINI_API_KEY no arquivo .env para ativar a análise por IA.",
            "probable_cause": "Chave da API ausente.",
            "recommended_actions": [
                "Criar chave no Google AI Studio",
                "Adicionar a chave no arquivo .env",
                "Reiniciar a aplicação",
            ],
            "traffic_insight": "Sem análise avançada de tráfego porque a IA ainda não está ativa.",
            "system_insight": "Métricas locais coletadas sem análise externa.",
            "source": "fallback-local",
        }

    try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent?key={GEMINI_API_KEY}"

        payload = {
            "contents": [
                {
                    "parts": [
                        {
                            "text": build_ai_prompt(data)
                        }
                    ]
                }
            ],
            "generationConfig": {
                "temperature": 0.2,
                "maxOutputTokens": 350,
                "responseMimeType": "application/json",
            },
        }

        response = requests.post(url, json=payload, timeout=8)
        response.raise_for_status()

        body = response.json()
        text = body["candidates"][0]["content"]["parts"][0]["text"]

        parsed = json.loads(text)
        parsed["source"] = "gemini"

        return parsed

    except requests.Timeout:
        return {
            "classification": "alerta",
            "title": "IA demorou para responder",
            "summary": "A API externa de IA demorou mais que o limite configurado.",
            "probable_cause": "Alta demanda ou limite da camada gratuita da Gemini.",
            "recommended_actions": [
                "Aguardar alguns segundos",
                "Evitar clicar várias vezes",
                "Tentar novamente antes da gravação",
            ],
            "traffic_insight": "Os dados de tráfego continuam disponíveis localmente.",
            "system_insight": "CPU, memória RAM e histerese continuam sendo monitorados.",
            "source": "fallback-timeout",
        }

    except Exception as exc:
        return {
            "classification": "alerta",
            "title": "Falha temporária na IA",
            "summary": "Não foi possível concluir a análise externa neste momento.",
            "probable_cause": str(exc),
            "recommended_actions": [
                "Verificar a chave da API",
                "Confirmar o modelo Gemini no .env",
                "Tentar novamente em alguns segundos",
            ],
            "traffic_insight": "A coleta local de tráfego permanece funcionando.",
            "system_insight": "As métricas locais continuam disponíveis no dashboard.",
            "source": "fallback-error",
        }


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "app": APP_NAME,
    }


@app.get("/api/metrics")
async def api_metrics() -> dict[str, Any]:
    return await collect_metrics()


@app.get("/api/history")
def api_history() -> list[dict[str, Any]]:
    return list(history)


@app.post("/api/analyze")
def api_analyze(payload: AnalyzeRequest) -> dict[str, Any]:
    return call_gemini(payload.data)
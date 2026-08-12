#!/usr/bin/env python3
"""
F5 BIG-IP TLS Configuration Validator
Valida configurações de TLS em dispositivos F5 BIG-IP e gera relatório HTML de pré e pós validação.

Requisitos:
    pip install requests urllib3 jinja2

Uso:
    python f5_tls_validator.py --host 192.168.1.1 --user admin --password secret
    python f5_tls_validator.py --host 192.168.1.1 --user admin --password secret --partition Common
    python f5_tls_validator.py --host 192.168.1.1 --user admin --password secret --phase post --baseline baseline.json
"""

import argparse
import json
import os
import sys
import ssl
import datetime
import socket
import urllib3
from dataclasses import dataclass, field, asdict
from typing import Optional
from pathlib import Path

try:
    import requests
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("[ERRO] Instale as dependências: pip install requests urllib3")
    sys.exit(1)

try:
    from jinja2 import Template
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False


# ─── Boas práticas TLS F5 (referência: F5 Security Advisory + NIST SP 800-52r2) ───

DEPRECATED_PROTOCOLS = {"TLSv1", "TLSv1_1", "SSLv2", "SSLv3"}
ALLOWED_PROTOCOLS    = {"TLSv1_2", "TLSv1_3"}

WEAK_CIPHERS = {
    "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon",
    "ADH", "AECDH", "aNULL", "eNULL", "RC2", "IDEA",
}

RECOMMENDED_CIPHERS = {
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "DHE-RSA-AES256-GCM-SHA384",
    "DHE-RSA-AES128-GCM-SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
}

SECURE_KEY_SIZES = {"RSA": 2048, "ECDSA": 256}

SECURE_RENEGOTIATION_OPTIONS = {"secure-renegotiation", "require-strict"}

SEVERITY_ORDER = {"CRITICO": 0, "ALTO": 1, "MEDIO": 2, "INFO": 3, "OK": 4}


# ─── Data classes ───────────────────────────────────────────────────────────────

@dataclass
class Finding:
    severity: str          # CRITICO | ALTO | MEDIO | INFO | OK
    category: str
    object_name: str
    description: str
    recommendation: str
    detail: str = ""


@dataclass
class ProfileResult:
    name: str
    partition: str
    profile_type: str      # client-ssl | server-ssl
    protocols_allowed: list = field(default_factory=list)
    protocols_blocked: list = field(default_factory=list)
    cipher_string: str = ""
    weak_ciphers_found: list = field(default_factory=list)
    cert_name: str = ""
    cert_key_type: str = ""
    cert_key_bits: int = 0
    cert_expiry: str = ""
    cert_days_remaining: int = -1
    ocsp_stapling: str = ""
    sni_enabled: bool = False
    renegotiation: str = ""
    secure_renegotiation: str = ""
    session_ticket: str = ""
    findings: list = field(default_factory=list)


@dataclass
class VirtualServerResult:
    name: str
    partition: str
    destination: str
    client_ssl_profiles: list = field(default_factory=list)
    server_ssl_profiles: list = field(default_factory=list)
    findings: list = field(default_factory=list)


@dataclass
class ValidationReport:
    host: str
    partition: str
    phase: str
    timestamp: str
    software_version: str = ""
    profiles: list = field(default_factory=list)
    virtual_servers: list = field(default_factory=list)
    summary: dict = field(default_factory=dict)


# ─── F5 API Client ──────────────────────────────────────────────────────────────

class F5Client:
    def __init__(self, host: str, username: str, password: str, port: int = 443):
        self.base_url = f"https://{host}:{port}/mgmt/tm"
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({"Content-Type": "application/json"})
        self._authenticate(username, password)

    def _authenticate(self, username: str, password: str):
        url = f"{self.base_url.replace('/tm', '')}/shared/authn/login"
        payload = {"username": username, "password": password, "loginProviderName": "tmos"}
        try:
            resp = self.session.post(url, json=payload, timeout=15)
            resp.raise_for_status()
            token = resp.json().get("token", {}).get("token")
            if not token:
                raise ValueError("Token não retornado pela API.")
            self.session.headers.update({"X-F5-Auth-Token": token})
            print(f"[OK] Autenticado com sucesso em {self.base_url}")
        except requests.exceptions.ConnectionError:
            print(f"[ERRO] Não foi possível conectar a {self.base_url}. Verifique host/porta.")
            sys.exit(1)
        except requests.exceptions.HTTPError as e:
            print(f"[ERRO] Falha de autenticação: {e}")
            sys.exit(1)

    def get(self, path: str, params: dict = None) -> dict:
        url = f"{self.base_url}/{path}"
        resp = self.session.get(url, params=params or {}, timeout=20)
        resp.raise_for_status()
        return resp.json()

    def get_version(self) -> str:
        try:
            data = self.get("sys/version")
            entries = data.get("entries", {})
            for k, v in entries.items():
                nested = v.get("nestedStats", {}).get("entries", {})
                version = nested.get("Version", {}).get("description", "")
                if version:
                    return version
        except Exception:
            pass
        return "Desconhecida"

    def get_client_ssl_profiles(self, partition: str = "Common") -> list:
        try:
            data = self.get("ltm/profile/client-ssl", params={"$filter": f"partition eq {partition}"})
            return data.get("items", [])
        except Exception as e:
            print(f"[AVISO] Erro ao buscar client-ssl profiles: {e}")
            return []

    def get_server_ssl_profiles(self, partition: str = "Common") -> list:
        try:
            data = self.get("ltm/profile/server-ssl", params={"$filter": f"partition eq {partition}"})
            return data.get("items", [])
        except Exception as e:
            print(f"[AVISO] Erro ao buscar server-ssl profiles: {e}")
            return []

    def get_virtual_servers(self, partition: str = "Common") -> list:
        try:
            data = self.get("ltm/virtual", params={
                "$filter": f"partition eq {partition}",
                "expandSubcollections": "true"
            })
            return data.get("items", [])
        except Exception as e:
            print(f"[AVISO] Erro ao buscar virtual servers: {e}")
            return []

    def get_cert_info(self, cert_name: str) -> dict:
        try:
            safe = cert_name.replace("/", "~").lstrip("~")
            data = self.get(f"sys/crypto/cert/{safe}")
            return data
        except Exception:
            return {}


# ─── Analyzer ───────────────────────────────────────────────────────────────────

class TLSAnalyzer:
    def __init__(self, client: F5Client):
        self.client = client

    def _parse_protocols(self, options_list: list) -> tuple:
        """Retorna (allowed, blocked) a partir da lista de options do perfil."""
        allowed, blocked = [], []
        for opt in options_list:
            if opt.startswith("no-"):
                proto = opt[3:]
                blocked.append(proto)
            else:
                allowed.append(opt)
        return allowed, blocked

    def _check_weak_ciphers(self, cipher_string: str) -> list:
        found = []
        upper = cipher_string.upper()
        for weak in WEAK_CIPHERS:
            if weak.upper() in upper:
                found.append(weak)
        return found

    def _cert_days_remaining(self, expiry_str: str) -> int:
        """Converte string de expiração F5 (Jan  1 00:00:00 2025 GMT) para dias restantes."""
        if not expiry_str:
            return -1
        try:
            dt = datetime.datetime.strptime(expiry_str.strip(), "%b %d %H:%M:%S %Y %Z")
            delta = dt - datetime.datetime.utcnow()
            return delta.days
        except Exception:
            return -1

    def analyze_client_ssl(self, raw: dict) -> ProfileResult:
        name = raw.get("name", "")
        partition = raw.get("partition", "Common")
        options = raw.get("options", [])
        if isinstance(options, str):
            options = options.split()

        allowed, blocked = self._parse_protocols(options)
        cipher_string = raw.get("ciphers", raw.get("cipherGroup", ""))
        weak = self._check_weak_ciphers(cipher_string)

        cert_name = raw.get("certKeyChain", [{}])[0].get("cert", "") if raw.get("certKeyChain") else raw.get("cert", "")
        cert_info = self.client.get_cert_info(cert_name) if cert_name else {}

        expiry = cert_info.get("expirationString", "")
        days = self._cert_days_remaining(expiry)
        key_type = cert_info.get("keyType", "")
        key_bits = int(cert_info.get("keySize", 0) or 0)

        pr = ProfileResult(
            name=name,
            partition=partition,
            profile_type="client-ssl",
            protocols_allowed=allowed,
            protocols_blocked=blocked,
            cipher_string=cipher_string,
            weak_ciphers_found=weak,
            cert_name=cert_name,
            cert_key_type=key_type,
            cert_key_bits=key_bits,
            cert_expiry=expiry,
            cert_days_remaining=days,
            ocsp_stapling=raw.get("ocspStapling", "disabled"),
            sni_enabled=bool(raw.get("sniDefault", False) or raw.get("sniRequire", False)),
            renegotiation=raw.get("renegotiation", "enabled"),
            secure_renegotiation=raw.get("secureRenegotiation", ""),
            session_ticket=raw.get("sessionTicket", "enabled"),
        )

        pr.findings = self._evaluate_profile(pr)
        return pr

    def analyze_server_ssl(self, raw: dict) -> ProfileResult:
        name = raw.get("name", "")
        partition = raw.get("partition", "Common")
        options = raw.get("options", [])
        if isinstance(options, str):
            options = options.split()

        allowed, blocked = self._parse_protocols(options)
        cipher_string = raw.get("ciphers", raw.get("cipherGroup", ""))
        weak = self._check_weak_ciphers(cipher_string)

        pr = ProfileResult(
            name=name,
            partition=partition,
            profile_type="server-ssl",
            protocols_allowed=allowed,
            protocols_blocked=blocked,
            cipher_string=cipher_string,
            weak_ciphers_found=weak,
            renegotiation=raw.get("renegotiation", "enabled"),
            secure_renegotiation=raw.get("secureRenegotiation", ""),
        )
        pr.findings = self._evaluate_profile(pr)
        return pr

    def _evaluate_profile(self, pr: ProfileResult) -> list:
        findings = []
        full_name = f"/{pr.partition}/{pr.name}"

        # ── Protocolos deprecated ativos ──
        active_deprecated = [p for p in pr.protocols_allowed if p in DEPRECATED_PROTOCOLS]
        blocked_deprecated = [p for p in pr.protocols_blocked if p in DEPRECATED_PROTOCOLS]
        missing_block = list(DEPRECATED_PROTOCOLS - set(blocked_deprecated) - set(active_deprecated))

        if active_deprecated:
            findings.append(Finding(
                severity="CRITICO",
                category="Protocolo",
                object_name=full_name,
                description=f"Protocolos inseguros ativos: {', '.join(active_deprecated)}",
                recommendation="Desative TLSv1.0 e TLSv1.1 via opção 'no-tlsv1 no-tlsv1.1'.",
                detail=f"Permitidos: {pr.protocols_allowed} | Bloqueados: {pr.protocols_blocked}"
            ))
        elif missing_block:
            findings.append(Finding(
                severity="MEDIO",
                category="Protocolo",
                object_name=full_name,
                description=f"Protocolos legados não explicitamente bloqueados: {', '.join(missing_block)}",
                recommendation="Adicione bloqueio explícito para todos os protocolos legados.",
                detail=f"Bloqueados atualmente: {pr.protocols_blocked}"
            ))
        else:
            findings.append(Finding(
                severity="OK",
                category="Protocolo",
                object_name=full_name,
                description="Todos os protocolos inseguros estão bloqueados.",
                recommendation="",
            ))

        # ── TLS 1.3 ──
        if "TLSv1_3" not in pr.protocols_allowed and "no-tlsv1.3" not in [b.lower() for b in pr.protocols_blocked]:
            findings.append(Finding(
                severity="MEDIO",
                category="Protocolo",
                object_name=full_name,
                description="TLS 1.3 não está explicitamente habilitado.",
                recommendation="Habilite TLS 1.3 para melhor segurança e desempenho.",
            ))

        # ── Ciphers fracos ──
        if pr.weak_ciphers_found:
            findings.append(Finding(
                severity="ALTO",
                category="Cipher",
                object_name=full_name,
                description=f"Ciphers fracos detectados na string: {', '.join(pr.weak_ciphers_found)}",
                recommendation="Remova ciphers fracos. Use apenas ciphers ECDHE/DHE com AES-GCM.",
                detail=f"Cipher string atual: {pr.cipher_string}"
            ))
        elif pr.cipher_string:
            findings.append(Finding(
                severity="OK",
                category="Cipher",
                object_name=full_name,
                description="Nenhum cipher fraco identificado na string de ciphers.",
                recommendation="",
                detail=f"Cipher string: {pr.cipher_string}"
            ))

        # ── Certificado (apenas client-ssl) ──
        if pr.profile_type == "client-ssl":
            if pr.cert_days_remaining < 0:
                findings.append(Finding(
                    severity="INFO",
                    category="Certificado",
                    object_name=full_name,
                    description="Não foi possível determinar expiração do certificado.",
                    recommendation="Verifique manualmente o certificado associado.",
                ))
            elif pr.cert_days_remaining <= 30:
                findings.append(Finding(
                    severity="CRITICO",
                    category="Certificado",
                    object_name=full_name,
                    description=f"Certificado expira em {pr.cert_days_remaining} dia(s)!",
                    recommendation="Renove o certificado imediatamente.",
                    detail=f"Expiração: {pr.cert_expiry}"
                ))
            elif pr.cert_days_remaining <= 90:
                findings.append(Finding(
                    severity="ALTO",
                    category="Certificado",
                    object_name=full_name,
                    description=f"Certificado expira em {pr.cert_days_remaining} dias.",
                    recommendation="Planeje a renovação do certificado.",
                    detail=f"Expiração: {pr.cert_expiry}"
                ))
            else:
                findings.append(Finding(
                    severity="OK",
                    category="Certificado",
                    object_name=full_name,
                    description=f"Certificado válido por {pr.cert_days_remaining} dias.",
                    recommendation="",
                    detail=f"Expiração: {pr.cert_expiry}"
                ))

            # Tamanho da chave
            min_bits = SECURE_KEY_SIZES.get(pr.cert_key_type.upper(), 2048)
            if pr.cert_key_bits and pr.cert_key_bits < min_bits:
                findings.append(Finding(
                    severity="ALTO",
                    category="Certificado",
                    object_name=full_name,
                    description=f"Chave {pr.cert_key_type} com {pr.cert_key_bits} bits é insuficiente (mínimo {min_bits}).",
                    recommendation=f"Use chaves {pr.cert_key_type} de pelo menos {min_bits} bits.",
                ))

        # ── Renegociação ──
        if pr.renegotiation == "enabled":
            findings.append(Finding(
                severity="ALTO",
                category="Renegociação",
                object_name=full_name,
                description="Renegociação TLS habilitada — risco de DoS e ataques MITM.",
                recommendation="Desabilite renegociação ou configure 'secure-renegotiation require-strict'.",
            ))
        if pr.secure_renegotiation and pr.secure_renegotiation not in SECURE_RENEGOTIATION_OPTIONS:
            findings.append(Finding(
                severity="MEDIO",
                category="Renegociação",
                object_name=full_name,
                description=f"Renegociação segura configurada como '{pr.secure_renegotiation}'.",
                recommendation="Use 'require-strict' para forçar RFC 5746.",
            ))

        return findings

    def analyze_virtual_servers(self, raw_list: list, partition: str) -> list:
        results = []
        for vs in raw_list:
            name = vs.get("name", "")
            dest = vs.get("destination", "")
            profiles_ref = vs.get("profilesReference", {}).get("items", [])

            client_ssl = []
            server_ssl = []
            for p in profiles_ref:
                context = p.get("context", "")
                pname = p.get("name", "")
                if context == "clientside":
                    client_ssl.append(pname)
                elif context == "serverside":
                    server_ssl.append(pname)

            vsr = VirtualServerResult(
                name=name,
                partition=partition,
                destination=dest,
                client_ssl_profiles=client_ssl,
                server_ssl_profiles=server_ssl,
            )

            if not client_ssl and not server_ssl:
                vsr.findings.append(Finding(
                    severity="INFO",
                    category="Virtual Server",
                    object_name=f"/{partition}/{name}",
                    description="Virtual Server sem perfil SSL/TLS associado (pode ser tráfego HTTP puro).",
                    recommendation="Confirme se TLS é necessário para este VS.",
                ))
            else:
                vsr.findings.append(Finding(
                    severity="OK",
                    category="Virtual Server",
                    object_name=f"/{partition}/{name}",
                    description=f"SSL profiles encontrados — Client: {client_ssl or 'nenhum'} | Server: {server_ssl or 'nenhum'}",
                    recommendation="",
                ))

            results.append(vsr)
        return results


# ─── Report Generator ────────────────────────────────────────────────────────────

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>F5 TLS Validation Report — {{ report.phase|upper }}</title>
<style>
  :root {
    --c-bg: #f5f6fa; --c-card: #ffffff; --c-border: #e2e5ec;
    --c-text: #1a1d23; --c-muted: #6b7280;
    --c-critico: #dc2626; --c-critico-bg: #fef2f2;
    --c-alto: #ea580c; --c-alto-bg: #fff7ed;
    --c-medio: #ca8a04; --c-medio-bg: #fefce8;
    --c-info: #2563eb; --c-info-bg: #eff6ff;
    --c-ok: #16a34a; --c-ok-bg: #f0fdf4;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: var(--c-bg); color: var(--c-text); font-size: 14px; line-height: 1.6; }
  .container { max-width: 1100px; margin: 0 auto; padding: 2rem 1.5rem; }
  header { background: #1e293b; color: white; padding: 2rem 0; margin-bottom: 2rem; }
  header .container { padding-top: 0; padding-bottom: 0; }
  header h1 { font-size: 1.5rem; font-weight: 600; margin-bottom: 0.25rem; }
  header p { color: #94a3b8; font-size: 0.875rem; }
  .badge { display: inline-block; font-size: 11px; font-weight: 600; padding: 2px 8px; border-radius: 4px; text-transform: uppercase; letter-spacing: 0.04em; }
  .badge-CRITICO { background: var(--c-critico-bg); color: var(--c-critico); }
  .badge-ALTO    { background: var(--c-alto-bg);    color: var(--c-alto); }
  .badge-MEDIO   { background: var(--c-medio-bg);   color: var(--c-medio); }
  .badge-INFO    { background: var(--c-info-bg);    color: var(--c-info); }
  .badge-OK      { background: var(--c-ok-bg);      color: var(--c-ok); }
  .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 2rem; }
  .stat-card { background: var(--c-card); border: 1px solid var(--c-border); border-radius: 8px; padding: 1rem 1.25rem; }
  .stat-card .label { font-size: 11px; color: var(--c-muted); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 6px; }
  .stat-card .value { font-size: 1.75rem; font-weight: 700; }
  .stat-card.critico .value { color: var(--c-critico); }
  .stat-card.alto    .value { color: var(--c-alto); }
  .stat-card.medio   .value { color: var(--c-medio); }
  .stat-card.ok      .value { color: var(--c-ok); }
  .section { margin-bottom: 2.5rem; }
  .section h2 { font-size: 1rem; font-weight: 600; color: var(--c-muted); text-transform: uppercase; letter-spacing: 0.06em; border-bottom: 1px solid var(--c-border); padding-bottom: 0.5rem; margin-bottom: 1rem; }
  .profile-card { background: var(--c-card); border: 1px solid var(--c-border); border-radius: 10px; margin-bottom: 1rem; overflow: hidden; }
  .profile-header { padding: 0.875rem 1.25rem; background: #f8fafc; border-bottom: 1px solid var(--c-border); display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px; }
  .profile-header .name { font-weight: 600; font-size: 0.9rem; }
  .profile-header .meta { font-size: 0.8rem; color: var(--c-muted); }
  .findings-table { width: 100%; border-collapse: collapse; }
  .findings-table th { text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--c-muted); padding: 0.5rem 1rem; background: #f8fafc; border-bottom: 1px solid var(--c-border); }
  .findings-table td { padding: 0.625rem 1rem; border-bottom: 1px solid #f1f5f9; vertical-align: top; }
  .findings-table tr:last-child td { border-bottom: none; }
  .finding-desc { font-weight: 500; margin-bottom: 2px; }
  .finding-rec { font-size: 12px; color: var(--c-muted); }
  .finding-detail { font-size: 11px; color: #9ca3af; font-family: monospace; margin-top: 2px; word-break: break-all; }
  .diff-table { width: 100%; border-collapse: collapse; font-size: 13px; }
  .diff-table th { background: #1e293b; color: white; padding: 0.6rem 1rem; text-align: left; font-weight: 500; }
  .diff-table td { padding: 0.5rem 1rem; border-bottom: 1px solid var(--c-border); vertical-align: top; }
  .diff-table tr:nth-child(even) td { background: #f8fafc; }
  .diff-added   { color: var(--c-ok);      background: var(--c-ok-bg) !important; }
  .diff-removed { color: var(--c-critico); background: var(--c-critico-bg) !important; }
  .diff-changed { color: var(--c-alto);    background: var(--c-alto-bg) !important; }
  .no-diff { font-size: 0.875rem; color: var(--c-muted); padding: 1rem; background: var(--c-card); border: 1px solid var(--c-border); border-radius: 8px; }
  footer { text-align: center; font-size: 12px; color: var(--c-muted); padding: 2rem 0; border-top: 1px solid var(--c-border); margin-top: 3rem; }
</style>
</head>
<body>
<header>
  <div class="container">
    <h1>F5 BIG-IP — Relatório de Validação TLS</h1>
    <p>Host: {{ report.host }} &nbsp;|&nbsp; Partição: {{ report.partition }} &nbsp;|&nbsp; Fase: <strong>{{ report.phase|upper }}</strong> &nbsp;|&nbsp; {{ report.timestamp }} &nbsp;|&nbsp; Versão BIG-IP: {{ report.software_version }}</p>
  </div>
</header>

<div class="container">

  <!-- Summary -->
  <div class="section">
    <h2>Resumo Executivo</h2>
    <div class="summary-grid">
      <div class="stat-card critico">
        <div class="label">Críticos</div>
        <div class="value">{{ report.summary.CRITICO }}</div>
      </div>
      <div class="stat-card alto">
        <div class="label">Altos</div>
        <div class="value">{{ report.summary.ALTO }}</div>
      </div>
      <div class="stat-card medio">
        <div class="label">Médios</div>
        <div class="value">{{ report.summary.MEDIO }}</div>
      </div>
      <div class="stat-card">
        <div class="label">Informativo</div>
        <div class="value" style="color:var(--c-info)">{{ report.summary.INFO }}</div>
      </div>
      <div class="stat-card ok">
        <div class="label">OK</div>
        <div class="value">{{ report.summary.OK }}</div>
      </div>
      <div class="stat-card">
        <div class="label">Perfis SSL</div>
        <div class="value">{{ report.profiles|length }}</div>
      </div>
      <div class="stat-card">
        <div class="label">Virtual Servers</div>
        <div class="value">{{ report.virtual_servers|length }}</div>
      </div>
    </div>
  </div>

  <!-- SSL Profiles -->
  <div class="section">
    <h2>Perfis SSL/TLS</h2>
    {% for profile in report.profiles %}
    <div class="profile-card">
      <div class="profile-header">
        <div>
          <span class="name">/{{ profile.partition }}/{{ profile.name }}</span>
          <span class="meta"> &mdash; {{ profile.profile_type }}</span>
        </div>
        <div style="display:flex;gap:6px;flex-wrap:wrap">
          {% if profile.cert_days_remaining >= 0 %}
            <span class="badge badge-{% if profile.cert_days_remaining <= 30 %}CRITICO{% elif profile.cert_days_remaining <= 90 %}ALTO{% else %}OK{% endif %}">
              Cert: {{ profile.cert_days_remaining }}d
            </span>
          {% endif %}
          {% if profile.weak_ciphers_found %}
            <span class="badge badge-ALTO">Cipher fraco</span>
          {% endif %}
        </div>
      </div>
      <table class="findings-table">
        <thead><tr><th style="width:110px">Severidade</th><th style="width:130px">Categoria</th><th>Descrição</th></tr></thead>
        <tbody>
          {% for f in profile.findings %}
          <tr>
            <td><span class="badge badge-{{ f.severity }}">{{ f.severity }}</span></td>
            <td style="color:var(--c-muted)">{{ f.category }}</td>
            <td>
              <div class="finding-desc">{{ f.description }}</div>
              {% if f.recommendation %}<div class="finding-rec">&#128161; {{ f.recommendation }}</div>{% endif %}
              {% if f.detail %}<div class="finding-detail">{{ f.detail }}</div>{% endif %}
            </td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    {% endfor %}
  </div>

  <!-- Virtual Servers -->
  <div class="section">
    <h2>Virtual Servers</h2>
    {% for vs in report.virtual_servers %}
    <div class="profile-card">
      <div class="profile-header">
        <div>
          <span class="name">/{{ vs.partition }}/{{ vs.name }}</span>
          <span class="meta"> &mdash; {{ vs.destination }}</span>
        </div>
      </div>
      <table class="findings-table">
        <thead><tr><th style="width:110px">Severidade</th><th style="width:130px">Categoria</th><th>Descrição</th></tr></thead>
        <tbody>
          {% for f in vs.findings %}
          <tr>
            <td><span class="badge badge-{{ f.severity }}">{{ f.severity }}</span></td>
            <td style="color:var(--c-muted)">{{ f.category }}</td>
            <td>
              <div class="finding-desc">{{ f.description }}</div>
              {% if f.recommendation %}<div class="finding-rec">&#128161; {{ f.recommendation }}</div>{% endif %}
            </td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    {% endfor %}
  </div>

  <!-- Delta (Pré vs Pós) -->
  {% if delta %}
  <div class="section">
    <h2>Comparativo Pré vs Pós Validação</h2>
    {% if delta.changes %}
    <table class="diff-table">
      <thead><tr><th>Perfil</th><th>Campo</th><th>Antes</th><th>Depois</th><th>Status</th></tr></thead>
      <tbody>
        {% for ch in delta.changes %}
        <tr class="diff-{{ ch.status }}">
          <td><strong>{{ ch.profile }}</strong></td>
          <td>{{ ch.field }}</td>
          <td>{{ ch.before }}</td>
          <td>{{ ch.after }}</td>
          <td><span class="badge badge-{% if ch.status == 'added' %}OK{% elif ch.status == 'removed' %}CRITICO{% else %}MEDIO{% endif %}">
            {% if ch.status == 'added' %}Adicionado{% elif ch.status == 'removed' %}Removido{% else %}Alterado{% endif %}
          </span></td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
    {% else %}
    <div class="no-diff">Nenhuma diferença detectada entre o baseline (pré) e a validação atual (pós).</div>
    {% endif %}
  </div>
  {% endif %}

  <footer>Gerado por f5_tls_validator.py &mdash; {{ report.timestamp }}</footer>
</div>
</body>
</html>"""


def compute_delta(baseline: dict, current: ValidationReport) -> dict:
    """Compara baseline JSON com validação atual e retorna lista de mudanças."""
    changes = []
    baseline_profiles = {p["name"]: p for p in baseline.get("profiles", [])}
    current_profiles = {p.name: p for p in current.profiles}

    fields_to_compare = [
        "protocols_allowed", "protocols_blocked", "cipher_string",
        "weak_ciphers_found", "renegotiation", "secure_renegotiation",
        "cert_days_remaining", "ocsp_stapling",
    ]

    for name, cur in current_profiles.items():
        if name not in baseline_profiles:
            changes.append({"profile": name, "field": "-", "before": "não existia", "after": "criado", "status": "added"})
            continue
        base = baseline_profiles[name]
        for f in fields_to_compare:
            bv = str(base.get(f, ""))
            cv = str(getattr(cur, f, ""))
            if bv != cv:
                changes.append({"profile": name, "field": f, "before": bv, "after": cv, "status": "changed"})

    for name in baseline_profiles:
        if name not in current_profiles:
            changes.append({"profile": name, "field": "-", "before": "existia", "after": "removido", "status": "removed"})

    return {"changes": changes}


def build_summary(profiles: list, virtual_servers: list) -> dict:
    counts = {"CRITICO": 0, "ALTO": 0, "MEDIO": 0, "INFO": 0, "OK": 0}
    for p in profiles:
        for f in p.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
    for vs in virtual_servers:
        for f in vs.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def generate_report(report: ValidationReport, delta: Optional[dict], output_path: str):
    if JINJA2_AVAILABLE:
        tmpl = Template(HTML_TEMPLATE)
        # Serializar dataclasses para dicts para o template
        report_dict = {
            "host": report.host,
            "partition": report.partition,
            "phase": report.phase,
            "timestamp": report.timestamp,
            "software_version": report.software_version,
            "summary": report.summary,
            "profiles": [asdict(p) for p in report.profiles],
            "virtual_servers": [asdict(vs) for vs in report.virtual_servers],
        }
        # Converter findings de volta para objetos com atributos para o template
        class DictObj:
            def __init__(self, d):
                self.__dict__.update(d)
        for p in report_dict["profiles"]:
            p["findings"] = [DictObj(f) for f in p["findings"]]
        for vs in report_dict["virtual_servers"]:
            vs["findings"] = [DictObj(f) for f in vs["findings"]]

        class ReportObj:
            def __init__(self, d):
                self.__dict__.update(d)
                self.profiles = [type('P', (), p)() for p in d["profiles"]]
                self.virtual_servers = [type('VS', (), vs)() for vs in d["virtual_servers"]]

        rendered = tmpl.render(report=ReportObj(report_dict), delta=delta)
    else:
        # Fallback simples sem Jinja2
        lines = [f"<h1>F5 TLS Report — {report.phase.upper()}</h1>",
                 f"<p>Host: {report.host} | {report.timestamp}</p>",
                 f"<p>Críticos: {report.summary.get('CRITICO',0)} | Altos: {report.summary.get('ALTO',0)} | Médios: {report.summary.get('MEDIO',0)}</p>"]
        for p in report.profiles:
            lines.append(f"<h2>/{p.partition}/{p.name} ({p.profile_type})</h2><ul>")
            for f in p.findings:
                lines.append(f"<li>[{f.severity}] {f.description}</li>")
            lines.append("</ul>")
        rendered = "\n".join(lines)

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(rendered)
    print(f"[OK] Relatório HTML gerado: {output_path}")


def save_baseline(report: ValidationReport, path: str):
    data = {
        "timestamp": report.timestamp,
        "host": report.host,
        "profiles": [asdict(p) for p in report.profiles],
        "virtual_servers": [asdict(vs) for vs in report.virtual_servers],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
    print(f"[OK] Baseline salvo: {path}")


# ─── Main ────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Valida configurações TLS no F5 BIG-IP e gera relatório HTML."
    )
    parser.add_argument("--host",      required=True,  help="IP ou hostname do BIG-IP")
    parser.add_argument("--user",      required=True,  help="Usuário de administração")
    parser.add_argument("--password",  required=True,  help="Senha")
    parser.add_argument("--port",      type=int, default=443, help="Porta HTTPS (padrão 443)")
    parser.add_argument("--partition", default="Common", help="Partição (padrão: Common)")
    parser.add_argument("--phase",     choices=["pre", "post"], default="pre",
                        help="Fase da validação: pre ou post")
    parser.add_argument("--baseline",  default="f5_tls_baseline.json",
                        help="Arquivo JSON de baseline para comparação pós (padrão: f5_tls_baseline.json)")
    parser.add_argument("--output",    default=None,
                        help="Caminho do relatório HTML de saída (padrão: f5_tls_report_<phase>_<ts>.html)")
    args = parser.parse_args()

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = args.output or f"f5_tls_report_{args.phase}_{ts}.html"

    print(f"\n{'='*55}")
    print(f"  F5 TLS Validator — Fase: {args.phase.upper()}")
    print(f"  Host: {args.host} | Partição: {args.partition}")
    print(f"{'='*55}\n")

    client   = F5Client(args.host, args.user, args.password, args.port)
    analyzer = TLSAnalyzer(client)

    version = client.get_version()
    print(f"[INFO] Versão BIG-IP: {version}")

    print("[INFO] Coletando client-ssl profiles...")
    raw_client = client.get_client_ssl_profiles(args.partition)
    client_profiles = [analyzer.analyze_client_ssl(p) for p in raw_client]

    print("[INFO] Coletando server-ssl profiles...")
    raw_server = client.get_server_ssl_profiles(args.partition)
    server_profiles = [analyzer.analyze_server_ssl(p) for p in raw_server]

    all_profiles = client_profiles + server_profiles

    print("[INFO] Coletando virtual servers...")
    raw_vs = client.get_virtual_servers(args.partition)
    virtual_servers = analyzer.analyze_virtual_servers(raw_vs, args.partition)

    summary = build_summary(all_profiles, virtual_servers)

    report = ValidationReport(
        host=args.host,
        partition=args.partition,
        phase=args.phase,
        timestamp=datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        software_version=version,
        profiles=all_profiles,
        virtual_servers=virtual_servers,
        summary=summary,
    )

    # Delta (apenas fase pós)
    delta = None
    if args.phase == "post":
        if os.path.exists(args.baseline):
            with open(args.baseline, encoding="utf-8") as fh:
                baseline_data = json.load(fh)
            delta = compute_delta(baseline_data, report)
            print(f"[INFO] Comparativo com baseline '{args.baseline}': {len(delta['changes'])} mudança(s) detectada(s).")
        else:
            print(f"[AVISO] Baseline '{args.baseline}' não encontrado. Comparativo ignorado.")

    # Salvar baseline na fase pré
    if args.phase == "pre":
        save_baseline(report, args.baseline)

    generate_report(report, delta, output_path)

    # Resumo no terminal
    print(f"\n{'─'*40}")
    print(f"  RESUMO: Críticos={summary['CRITICO']} | Altos={summary['ALTO']} | Médios={summary['MEDIO']} | OK={summary['OK']}")
    print(f"  Perfis analisados : {len(all_profiles)}")
    print(f"  Virtual Servers   : {len(virtual_servers)}")
    print(f"{'─'*40}\n")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Agente de auditoría de seguridad asistido por LLM.

Arquitectura (orquestación determinista + LLM analista):
  1. Se conecta por SSH al objetivo (.50).
  2. Ejecuta Lynis y OpenSCAP (perfil CIS) de forma determinista en Python.
  3. Recupera y PARSEA los reportes a hallazgos estructurados.
  4. Envía los hallazgos (nunca el XML crudo) a qwen2.5:7b en Ollama (.240)
     para interpretación, priorización y remediación.
  5. Genera un informe consolidado en Markdown.

El LLM SOLO analiza; no decide qué se ejecuta. Esto es mucho más fiable con un modelo 7B.
"""

import os
import re
import sys
import json
import shlex
import time
import datetime as dt
import xml.etree.ElementTree as ET

import paramiko
from openai import OpenAI


# ─────────────────────────── Configuración ───────────────────────────
def env(name, default=""):
    return os.environ.get(name, default).strip()

CFG = {
    "target_host":  env("TARGET_HOST", "192.168.10.50"),
    "target_user":  env("TARGET_USER", "ubuntu"),
    "target_pass":  env("TARGET_PASSWORD"),
    "target_key":   env("TARGET_SSH_KEY"),
    "sudo_pass":    env("TARGET_SUDO_PASSWORD"),
    "datastream":   env("OSCAP_DATASTREAM"),
    "profile":      env("OSCAP_PROFILE"),
    "family":       env("OSCAP_PROFILE_FAMILY", "cis").lower(),  # cis | stig | standard
    "llm_base":     env("LLM_BASE_URL", "http://192.168.10.240:11434/v1"),
    "llm_model":    env("LLM_MODEL", "qwen2.5:7b"),
    "llm_key":      env("LLM_API_KEY", "ollama"),
    "max_oscap":    int(env("MAX_OSCAP_FINDINGS", "40")),
    "oscap_batch":  int(env("OSCAP_BATCH", "12")),
}

REPORT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")

# Preferencia de perfil por familia (se elige el primer sufijo que exista en el datastream).
FAMILY_PREFS = {
    "cis":      ["cis_level1_server", "cis_level1", "cis_server", "cis"],
    "stig":     ["stig", "stig_gui"],
    "standard": ["standard", "ospp"],
}
FAMILY_LABEL = {"cis": "CIS", "stig": "STIG (DISA)", "standard": "Estándar"}


def profile_label() -> str:
    return FAMILY_LABEL.get(CFG["family"], CFG["family"].upper())


def log(msg):
    print(f"[{dt.datetime.now():%H:%M:%S}] {msg}", flush=True)


# ─────────────────────────── Capa SSH ───────────────────────────
class Target:
    """Conexión SSH al objetivo. Ejecuta comandos (con sudo -S) y captura salida."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.cli = paramiko.SSHClient()
        self.cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def connect(self):
        log(f"SSH → {self.cfg['target_user']}@{self.cfg['target_host']}")
        kwargs = dict(
            hostname=self.cfg["target_host"],
            username=self.cfg["target_user"],
            timeout=20,
            banner_timeout=20,
            auth_timeout=20,
        )
        if self.cfg["target_key"]:
            kwargs["key_filename"] = self.cfg["target_key"]
        if self.cfg["target_pass"]:
            kwargs["password"] = self.cfg["target_pass"]
        self.cli.connect(**kwargs)

    def run(self, cmd, sudo=False, timeout=2400):
        """Ejecuta un comando. Con sudo=True usa 'sudo -S' y alimenta la contraseña por stdin."""
        if sudo:
            wrapped = f"sudo -S -p '' bash -c {shlex.quote(cmd)}"
        else:
            wrapped = f"bash -c {shlex.quote(cmd)}"
        stdin, stdout, stderr = self.cli.exec_command(wrapped, timeout=timeout)
        if sudo and self.cfg["sudo_pass"]:
            stdin.write(self.cfg["sudo_pass"] + "\n")
            stdin.flush()
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        rc = stdout.channel.recv_exit_status()
        return rc, out, err

    def close(self):
        try:
            self.cli.close()
        except Exception:
            pass


# ─────────────────────────── Escáneres ───────────────────────────
def detect_datastream(t: Target) -> str:
    """Autodetecta el datastream SSG según la versión de Ubuntu del objetivo."""
    if CFG["datastream"]:
        return CFG["datastream"]
    rc, out, _ = t.run("ls /usr/share/xml/scap/ssg/content/ssg-ubuntu*-ds.xml 2>/dev/null")
    candidates = [l.strip() for l in out.splitlines() if l.strip()]
    if not candidates:
        raise RuntimeError(
            "No hay contenido SCAP Security Guide en el objetivo. "
            "Instálalo con:  sudo apt-get install -y ssg-debderived"
        )
    # Empareja con la versión del SO si es posible
    rc, ver, _ = t.run(". /etc/os-release; echo $VERSION_ID")
    vid = ver.strip().replace(".", "")
    for c in candidates:
        if vid and vid in c:
            return c
    return candidates[0]


def detect_profile(t: Target, datastream: str) -> str:
    """Elige el perfil de la familia configurada (cis/stig/standard) salvo que se fije por config."""
    if CFG["profile"]:
        return CFG["profile"]
    family = CFG["family"]
    keyword = "stig" if family == "stig" else family
    prefs = FAMILY_PREFS.get(family, [family])
    rc, out, _ = t.run(f"oscap info {shlex.quote(datastream)} 2>/dev/null")
    profiles = re.findall(r"(xccdf_org\.ssgproject\.content_profile_[\w\-.]+)", out)
    matches = [p for p in profiles if keyword in p.lower()]
    # Preferimos el sufijo más específico de la familia; luego cualquier coincidencia.
    for pref in prefs:
        for p in matches:
            if p.lower().endswith(pref):
                return p
    if matches:
        return matches[0]
    raise RuntimeError(
        f"No se encontró perfil '{family}' en {datastream}. Perfiles disponibles: {profiles}"
    )


def run_lynis(t: Target) -> str:
    log("Ejecutando Lynis en el objetivo…")
    t.run("lynis audit system --quiet --no-colors 2>/dev/null; true", sudo=True)
    rc, dat, err = t.run("cat /var/log/lynis-report.dat", sudo=True)
    if rc != 0 or not dat.strip():
        raise RuntimeError(f"No se pudo leer lynis-report.dat: {err.strip()}")
    return dat


def run_openscap(t: Target, datastream: str, profile: str) -> str:
    log(f"Ejecutando OpenSCAP (perfil {profile})…")
    remote_arf = "/tmp/oscap-arf.xml"
    remote_html = "/tmp/oscap-report.html"
    cmd = (
        f"oscap xccdf eval --profile {shlex.quote(profile)} "
        f"--results-arf {remote_arf} --report {remote_html} "
        f"{shlex.quote(datastream)}; echo RC=$?"
    )
    rc, out, err = t.run(cmd, sudo=True)
    # oscap devuelve 0 (todo pass) o 2 (hay reglas 'fail'); ambos son válidos.
    m = re.search(r"RC=(\d+)", out)
    oscap_rc = int(m.group(1)) if m else -1
    if oscap_rc not in (0, 2):
        raise RuntimeError(f"oscap falló (rc={oscap_rc}): {err.strip() or out.strip()}")
    rc, arf, err = t.run(f"cat {remote_arf}", sudo=True)
    if rc != 0 or not arf.strip():
        raise RuntimeError(f"No se pudo leer el ARF: {err.strip()}")
    return arf


# ─────────────────────────── Parsers ───────────────────────────
def parse_lynis(dat: str) -> dict:
    """Extrae índice de endurecimiento, warnings y suggestions del report.dat."""
    def split_entry(val):
        # formato:  TEST-ID|texto|detalle|solución|
        parts = val.split("|")
        return {"test": parts[0] if parts else "",
                "text": parts[1] if len(parts) > 1 else val}

    hardening = None
    warnings, suggestions = [], []
    for line in dat.splitlines():
        if line.startswith("hardening_index="):
            hardening = line.split("=", 1)[1].strip()
        elif line.startswith("warning[]="):
            warnings.append(split_entry(line.split("=", 1)[1]))
        elif line.startswith("suggestion[]="):
            suggestions.append(split_entry(line.split("=", 1)[1]))
    return {"hardening_index": hardening, "warnings": warnings, "suggestions": suggestions}


def _local(tag: str) -> str:
    return tag.split("}")[-1]


def parse_openscap(arf: str) -> list:
    """Parsea el ARF y devuelve la lista de reglas con resultado, severidad y título."""
    root = ET.fromstring(arf)

    # Mapa idref -> (título, severidad) desde las definiciones <Rule>
    titles = {}
    for el in root.iter():
        if _local(el.tag) == "Rule":
            rid = el.get("id")
            sev = el.get("severity")
            title = None
            for ch in el:
                if _local(ch.tag) == "title":
                    title = "".join(ch.itertext()).strip()
                    break
            if rid:
                titles[rid] = (title, sev)

    findings = []
    for rr in root.iter():
        if _local(rr.tag) != "rule-result":
            continue
        idref = rr.get("idref")
        sev = rr.get("severity")
        result = None
        for ch in rr:
            if _local(ch.tag) == "result":
                result = (ch.text or "").strip()
                break
        title, tsev = titles.get(idref, (None, None))
        findings.append({
            "rule": idref,
            "title": title or (idref.split("_rule_")[-1] if idref else idref),
            "severity": (sev or tsev or "unknown").lower(),
            "result": result,
        })
    return findings


# ─────────────────────────── Capa LLM ───────────────────────────
SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "unknown": 3}

def system_prompt() -> str:
    return (
        "Eres un analista senior de seguridad de sistemas Linux. Recibes hallazgos "
        f"reales de Lynis y OpenSCAP (perfil {profile_label()}) de un servidor Ubuntu. "
        "Para cada bloque de hallazgos, redacta en ESPAÑOL un análisis conciso y "
        "accionable: explica el riesgo real, su impacto, y da el comando o cambio de "
        "configuración concreto para remediarlo. No inventes hallazgos que no estén en "
        "la entrada. Prioriza por severidad. Responde en Markdown."
    )


def llm_client():
    return OpenAI(base_url=CFG["llm_base"], api_key=CFG["llm_key"])


def llm_chat(client, user_content, system=None, temperature=0.1):
    if system is None:
        system = system_prompt()
    resp = client.chat.completions.create(
        model=CFG["llm_model"],
        temperature=temperature,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user_content},
        ],
    )
    return resp.choices[0].message.content.strip()


def analyze_lynis(client, lynis: dict) -> str:
    log("LLM: analizando hallazgos de Lynis…")
    payload = {
        "hardening_index": lynis["hardening_index"],
        "warnings": lynis["warnings"],
        "suggestions": lynis["suggestions"][:40],
    }
    prompt = (
        "Analiza estos hallazgos de Lynis. Empieza valorando el hardening_index "
        "(0-100, más alto es mejor). Luego prioriza los warnings sobre las suggestions.\n\n"
        + json.dumps(payload, ensure_ascii=False, indent=2)
    )
    return llm_chat(client, prompt)


def analyze_openscap(client, fails: list) -> str:
    """Analiza los fallos OpenSCAP en lotes para no saturar el contexto del 7B."""
    fails = sorted(fails, key=lambda f: SEV_ORDER.get(f["severity"], 3))[: CFG["max_oscap"]]
    if not fails:
        return "_No hay reglas OpenSCAP en estado FAIL._"
    chunks = [fails[i:i + CFG["oscap_batch"]] for i in range(0, len(fails), CFG["oscap_batch"])]
    parts = []
    for i, chunk in enumerate(chunks, 1):
        log(f"LLM: analizando OpenSCAP lote {i}/{len(chunks)}…")
        slim = [{"regla": f["title"], "severidad": f["severity"]} for f in chunk]
        prompt = (
            f"Reglas {profile_label()} incumplidas (FAIL), lote {i}/{len(chunks)}. Para cada una: "
            "riesgo, impacto y remediación concreta.\n\n"
            + json.dumps(slim, ensure_ascii=False, indent=2)
        )
        parts.append(llm_chat(client, prompt))
    return "\n\n".join(parts)


def executive_summary(client, lynis: dict, oscap_stats: dict) -> str:
    log("LLM: redactando resumen ejecutivo…")
    prompt = (
        "Redacta un RESUMEN EJECUTIVO breve (máx. 8 líneas) para dirección, sin tecnicismos "
        "innecesarios, a partir de estos datos agregados de la auditoría:\n\n"
        + json.dumps({
            "lynis_hardening_index": lynis["hardening_index"],
            "lynis_warnings": len(lynis["warnings"]),
            "lynis_suggestions": len(lynis["suggestions"]),
            "openscap": oscap_stats,
        }, ensure_ascii=False, indent=2)
    )
    return llm_chat(client, prompt)


# ─────────────────────────── Informe ───────────────────────────
def build_report(meta, lynis, oscap_findings, oscap_stats,
                 exec_md, lynis_md, oscap_md) -> str:
    fails = [f for f in oscap_findings if f["result"] == "fail"]
    lines = [
        f"# Informe de auditoría de seguridad — {meta['target']}",
        "",
        f"- **Fecha:** {meta['date']}",
        f"- **Generado por:** agente IA (qwen2.5:7b @ {CFG['llm_base']})",
        f"- **Datastream OpenSCAP:** `{meta['datastream']}`",
        f"- **Perfil {profile_label()}:** `{meta['profile']}`",
        f"- **Índice de endurecimiento (Lynis):** {lynis['hardening_index']}/100",
        "",
        "## 1. Resumen ejecutivo",
        "",
        exec_md,
        "",
        "## 2. Panorama de resultados",
        "",
        f"- Lynis: **{len(lynis['warnings'])}** warnings, **{len(lynis['suggestions'])}** suggestions.",
        f"- OpenSCAP ({profile_label()}): **{len(fails)}** reglas en FAIL de {len(oscap_findings)} evaluadas.",
        "",
        "| Severidad | Reglas FAIL |",
        "|-----------|-------------|",
        f"| Alta      | {oscap_stats.get('high', 0)} |",
        f"| Media     | {oscap_stats.get('medium', 0)} |",
        f"| Baja      | {oscap_stats.get('low', 0)} |",
        f"| Otras     | {oscap_stats.get('unknown', 0)} |",
        "",
        "## 3. Análisis Lynis",
        "",
        lynis_md,
        "",
        f"## 4. Análisis OpenSCAP / {profile_label()}",
        "",
        oscap_md,
        "",
        "---",
        "_Reportes crudos en el objetivo: `/var/log/lynis-report.dat`, "
        "`/tmp/oscap-arf.xml`, `/tmp/oscap-report.html`._",
    ]
    return "\n".join(lines)


# ─────────────────────────── Main ───────────────────────────
def main():
    os.makedirs(REPORT_DIR, exist_ok=True)
    t = Target(CFG)
    try:
        t.connect()
        datastream = detect_datastream(t)
        profile = detect_profile(t, datastream)
        log(f"Datastream: {datastream}")
        log(f"Perfil:     {profile}")

        lynis_dat = run_lynis(t)
        arf = run_openscap(t, datastream, profile)
    finally:
        t.close()

    lynis = parse_lynis(lynis_dat)
    oscap = parse_openscap(arf)
    fails = [f for f in oscap if f["result"] == "fail"]
    stats = {}
    for f in fails:
        stats[f["severity"]] = stats.get(f["severity"], 0) + 1
    log(f"Lynis: {len(lynis['warnings'])} warnings / {len(lynis['suggestions'])} suggestions. "
        f"OpenSCAP: {len(fails)} FAIL.")

    client = llm_client()
    exec_md = executive_summary(client, lynis, stats)
    lynis_md = analyze_lynis(client, lynis)
    oscap_md = analyze_openscap(client, fails)

    meta = {
        "target": CFG["target_host"],
        "date": dt.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "datastream": datastream,
        "profile": profile,
    }
    report = build_report(meta, lynis, oscap, stats, exec_md, lynis_md, oscap_md)

    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    out_path = os.path.join(
        REPORT_DIR, f"auditoria-{CFG['target_host']}-{CFG['family']}-{stamp}.md")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(report)
    log(f"✅ Informe generado: {out_path}")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log(f"❌ ERROR: {e}")
        sys.exit(1)

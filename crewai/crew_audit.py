#!/usr/bin/env python3
"""
Variante con CrewAI del agente de auditoría.

Filosofía distinta a la del agente determinista (../audit_agent.py):
  - Aquí modelamos AGENTES con rol (auditor, analista, revisor) que colaboran.
  - CrewAI orquesta las tareas en secuencia.
  - Los ESCANEOS siguen siendo deterministas: se envuelven las funciones de
    audit_agent.py como 'tools'. Solo el análisis/redacción queda en manos del LLM.
    (Es el punto dulce para un modelo 7B: multi-agente sin apostar 'oscap' a que
     el modelo acierte el formato de tool-calling.)

Reutiliza la MISMA configuración por entorno (agent.env) que el agente principal:
host objetivo, credenciales, OSCAP_PROFILE_FAMILY (cis|stig|standard), LLM, etc.

Uso:
    pip install -r requirements.txt
    set -a; . ../agent.env; set +a
    python crew_audit.py
"""

import os
import sys
import json
import datetime as dt

# audit_agent.py vive en la carpeta padre: lo usamos como librería.
PARENT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PARENT)
import audit_agent as A  # noqa: E402  (Target, CFG, run_lynis, run_openscap, parse_*)

from crewai import Agent, Task, Crew, Process, LLM  # noqa: E402
from crewai.tools import tool  # noqa: E402

REPORT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
os.makedirs(REPORT_DIR, exist_ok=True)


# ─────────────── LLM local (Ollama vía LiteLLM; ojo al prefijo "ollama/") ───────────────
llm = LLM(
    model=f"ollama/{A.CFG['llm_model']}",
    base_url=A.CFG["llm_base"].removesuffix("/v1"),  # LiteLLM quiere la base sin /v1
    temperature=0.1,
)


# ─────────────── Tools: tus escáneres deterministas envueltos ───────────────
@tool("escanear_lynis")
def escanear_lynis(**kwargs) -> str:
    """Ejecuta Lynis por SSH en el objetivo y devuelve los hallazgos parseados en JSON
    (hardening_index, warnings, suggestions).

    NO recibe argumentos: el host objetivo se toma de la configuración (agent.env).
    Se aceptan y descartan kwargs para tolerar que el modelo invente parámetros."""
    t = A.Target(A.CFG)
    t.connect()
    try:
        dat = A.run_lynis(t)
    finally:
        t.close()
    return json.dumps(A.parse_lynis(dat), ensure_ascii=False)


@tool("escanear_openscap")
def escanear_openscap(**kwargs) -> str:
    """Ejecuta OpenSCAP con el perfil configurado (CIS/STIG/estándar) por SSH en el
    objetivo y devuelve la lista de reglas en estado FAIL (regla, título, severidad) en JSON.

    NO recibe argumentos: el objetivo y el perfil se toman de la configuración (agent.env).
    Se aceptan y descartan kwargs para tolerar que el modelo invente parámetros."""
    t = A.Target(A.CFG)
    t.connect()
    try:
        ds = A.detect_datastream(t)
        prof = A.detect_profile(t, ds)
        arf = A.run_openscap(t, ds, prof)
    finally:
        t.close()
    fails = [f for f in A.parse_openscap(arf) if f["result"] == "fail"]
    # Acotamos como en el agente principal, priorizando por severidad, para no saturar el 7B.
    fails.sort(key=lambda f: A.SEV_ORDER.get(f["severity"], 3))
    return json.dumps(fails[: A.CFG["max_oscap"]], ensure_ascii=False)


# ─────────────── Agentes ───────────────
auditor = Agent(
    role="Auditor de sistemas Linux",
    goal="Recopilar hallazgos reales de Lynis y OpenSCAP del servidor objetivo usando las herramientas.",
    backstory=("Especialista en hardening. No inventas datos: te limitas a ejecutar las "
               "herramientas disponibles y a entregar sus resultados tal cual."),
    tools=[escanear_lynis, escanear_openscap],
    llm=llm,
    verbose=True,
    allow_delegation=False,   # clave con un 7B: menos autonomía = más fiabilidad
    max_iter=5,
)

analista = Agent(
    role="Analista de seguridad senior",
    goal=("Interpretar los hallazgos, priorizarlos por severidad y proponer una remediación "
          "concreta (comando o cambio de configuración) para cada uno."),
    backstory=("Consultor que traduce hallazgos técnicos en acciones claras para un equipo de "
               "sistemas. Escribes en español, con rigor y sin relleno."),
    llm=llm,
    verbose=True,
    allow_delegation=False,
)

revisor = Agent(
    role="Revisor técnico de calidad",
    goal=("Depurar el informe del analista: corregir imprecisiones, eliminar relleno, "
          "asegurar que cada hallazgo tiene una remediación accionable y que NO se han "
          "inventado hallazgos ausentes en los datos originales."),
    backstory=("Auditor jefe exigente. Revisas el borrador contra los hallazgos originales, "
               "recortas lo superfluo y entregas la versión final lista para el cliente. "
               "No añades hallazgos nuevos: solo mejoras lo que hay."),
    llm=llm,
    verbose=True,
    allow_delegation=False,
)


# ─────────────── Tareas (encadenadas por 'context') ───────────────
tarea_escaneo = Task(
    description=("Ejecuta AMBAS herramientas de auditoría sobre el objetivo "
                 f"{A.CFG['target_host']} (perfil OpenSCAP: {A.profile_label()}). "
                 "Reúne todos los hallazgos y entrégalos íntegros."),
    expected_output="JSON con: los hallazgos de Lynis y la lista de reglas OpenSCAP en FAIL.",
    agent=auditor,
)

tarea_informe = Task(
    description=("A partir EXCLUSIVAMENTE de los hallazgos recibidos, redacta un BORRADOR de "
                 "informe en Markdown en español con: (1) resumen ejecutivo, (2) valoración del "
                 "hardening_index de Lynis, (3) análisis de los hallazgos priorizados por "
                 "severidad, y (4) remediación concreta por hallazgo. No inventes hallazgos "
                 "que no aparezcan en la entrada."),
    expected_output="Un borrador de informe de auditoría en Markdown.",
    agent=analista,
    context=[tarea_escaneo],
)

tarea_revision = Task(
    description=("Revisa el borrador del analista contra los hallazgos originales de la tarea "
                 "de escaneo. Corrige imprecisiones, elimina relleno, verifica que cada "
                 "hallazgo tiene remediación accionable y que NINGÚN hallazgo ha sido inventado. "
                 "Entrega la versión FINAL, no un listado de comentarios."),
    expected_output="El informe de auditoría FINAL, depurado, en Markdown.",
    agent=revisor,
    context=[tarea_escaneo, tarea_informe],
    # NOTA: no usamos output_file de CrewAI (bloquea rutas absolutas y falla en
    # silencio según versión). Guardamos el resultado nosotros mismos en __main__.
)


crew = Crew(
    agents=[auditor, analista, revisor],
    tasks=[tarea_escaneo, tarea_informe, tarea_revision],
    process=Process.sequential,
    verbose=True,
)


if __name__ == "__main__":
    print(f"[crewai] Objetivo={A.CFG['target_host']}  Perfil={A.profile_label()}  "
          f"LLM={A.CFG['llm_model']}")
    result = crew.kickoff()

    # Guardamos el informe final nosotros mismos (no dependemos del output_file de CrewAI).
    texto = getattr(result, "raw", None) or str(result)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    out_path = os.path.join(REPORT_DIR, f"auditoria-crewai-{A.CFG['family']}-{stamp}.md")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(texto)

    print("\n──────── RESULTADO ────────\n")
    print(texto)
    print(f"\n✅ Informe guardado en: {out_path}")

# Variante CrewAI (multi-agente)

Alternativa al agente determinista de `../audit_agent.py`. Aquí modelamos **agentes
con rol** (Auditor → Analista → Revisor) que CrewAI orquesta en secuencia. Los
**escaneos siguen siendo deterministas**: las funciones de `audit_agent.py` se
reutilizan como *tools*; solo el análisis, la redacción y la revisión quedan en
manos del LLM.

Flujo de las tareas:
1. **Auditor** — ejecuta Lynis y OpenSCAP (tools) y reúne los hallazgos.
2. **Analista** — redacta un *borrador* de informe priorizado por severidad.
3. **Revisor** — depura el borrador contra los hallazgos originales (corrige, recorta
   relleno, verifica que no se inventan hallazgos) y produce el informe **final**.

Convive con el agente principal y **comparte la misma configuración** (`../agent.env`):
mismo objetivo, credenciales, `OSCAP_PROFILE_FAMILY` (cis|stig|standard) y LLM.

## Instalación (en .241)
```bash
cd ~/audit-agent/crewai         # donde hayas copiado esta carpeta
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```
> Nota: CrewAI trae bastantes dependencias (litellm, etc.). Conviene un venv propio,
> separado del venv del agente principal.

## Ejecución
```bash
set -a; . ../agent.env; set +a   # reutiliza tu configuración (host, perfil, credenciales)
python crew_audit.py
```
El informe queda en `reports/auditoria-crewai-<familia>.md` (p. ej. `-stig`).

## Diseño y límites (con qwen2.5:7b)
- `allow_delegation=False` en los agentes: limita la autonomía a propósito. Con un
  modelo 7B, el tool-calling multi-agente autónomo es frágil (formato, reintentos,
  bucles); así lo usamos casi como *pipeline* con roles, que es el punto fiable.
- Los escaneos NO dependen de que el modelo acierte el formato: se ejecutan dentro
  de las tools de forma determinista.
- Es más lento y con más llamadas al LLM que el agente principal, por el overhead de
  orquestación. Para fiabilidad de auditoría, `../audit_agent.py` sigue siendo la
  opción sólida; esta variante es para explorar el patrón multi-agente.

## Detalle técnico
- El LLM se configura vía LiteLLM con prefijo `ollama/` y **base sin `/v1`**
  (`http://192.168.10.240:11434`), a diferencia del cliente OpenAI del agente
  principal, que sí usa `/v1`.

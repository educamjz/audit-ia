# Práctica: Auditoría de seguridad Linux asistida por IA

**Módulo:** Seguridad de sistemas · **Duración estimada:** 2–3 h · **Modalidad:** laboratorio guiado

En esta práctica vas a auditar un servidor Linux con dos herramientas estándar de la
industria —**Lynis** y **OpenSCAP**— pero, en lugar de leerte tú los cientos de líneas
de salida, un **agente de IA** con un modelo de lenguaje local (LLM) interpretará los
hallazgos, los priorizará por severidad y te propondrá remediaciones concretas.

Lo harás de **dos formas**, para que compares dos filosofías de diseño de agentes:

1. **Opción determinista** — el flujo lo controla Python; el LLM solo analiza.
2. **Opción CrewAI** — varios agentes con rol (Auditor → Analista → Revisor) que colaboran.

## Objetivos de aprendizaje

Al terminar serás capaz de:

- Ejecutar una auditoría de cumplimiento con Lynis y OpenSCAP contra perfiles **CIS** y **STIG**.
- Entender la diferencia entre orquestación **determinista** y **multi-agente**.
- Conectar un agente con un **LLM local** (Ollama) sin depender de servicios en la nube.
- Interpretar un informe de seguridad y valorar la calidad del análisis generado por IA.

---

## 1. Arquitectura del laboratorio

```
   .241 (AGENTE)                       .240 (LLM)
   ┌────────────────┐   HTTP :11434    ┌──────────────┐
   │ Tú trabajas    │─────────────────▶│ Ollama       │
   │ aquí           │◀─────────────────│ (modelo LLM) │
   └───────┬────────┘   analiza        └──────────────┘
           │ SSH :22
           ▼
   .50 (OBJETIVO)
   Lynis + OpenSCAP
```

| Host | IP | Rol | Quién lo gestiona |
|------|-----|-----|-------------------|
| Objetivo | `192.168.10.50` | Ubuntu Server con Lynis + OpenSCAP | Preparado por el docente |
| LLM | `192.168.10.240` | Ollama sirviendo el modelo | Preparado por el docente |
| **Agente** | `192.168.10.241` | **Aquí despliegas y ejecutas el agente** | **Tú** |

> El objetivo (`.50`) y el LLM (`.240`) ya están montados. **Tu trabajo es todo en `.241`.**

### Credenciales que te entrega el docente
- Usuario y contraseña (o clave SSH) para entrar en `.241`.
- Usuario/contraseña SSH del objetivo `.50` (y su contraseña de `sudo`).

---

## 2. Requisitos previos (comprobaciones)

Conéctate por SSH a **`.241`** y verifica que ves el resto del laboratorio:

```bash
# ¿Responde el objetivo?
ping -c1 192.168.10.50

# ¿Responde el LLM y qué modelo sirve?
curl -s http://192.168.10.240:11434/api/tags
```

Si el segundo comando devuelve un JSON con un modelo (p. ej. `qwen3:14b`), todo está listo.
Apunta el **nombre exacto del modelo**: lo necesitarás en la configuración.

---

## 3. Obtener el código

En `.241`, clona el repositorio de la práctica:

```bash
git clone https://github.com/<USUARIO>/<REPO>.git
cd <REPO>
ls
# audit_agent.py  requirements.txt  setup_241.sh  agent.env.example
# agent.env.stig.example  crewai/  GUIA-PRACTICA.md
```

---

# PARTE A — Opción determinista

Aquí Python decide **qué** se ejecuta y **en qué orden**; el LLM solo recibe los hallazgos
ya extraídos y redacta el análisis. Es el diseño más fiable, sobre todo con modelos pequeños.

## A.1 · Entorno de Python

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
```

## A.2 · Dar acceso SSH del agente al objetivo

El agente entra por SSH a `.50` para lanzar las herramientas. Genera una clave y autorízala:

```bash
[ -f ~/.ssh/id_ed25519 ] || ssh-keygen -t ed25519 -N '' -f ~/.ssh/id_ed25519
ssh-copy-id -i ~/.ssh/id_ed25519.pub <usuario_objetivo>@192.168.10.50
# Comprueba que entras sin contraseña:
ssh <usuario_objetivo>@192.168.10.50 hostname
```

## A.3 · Verificar el contenido SCAP en el objetivo

OpenSCAP necesita el contenido de la *SCAP Security Guide* en `.50`:

```bash
ssh <usuario_objetivo>@192.168.10.50 \
  'ls /usr/share/xml/scap/ssg/content/ssg-ubuntu*-ds.xml'
```
Si no aparece ningún fichero, instálalo en el objetivo:
```bash
ssh <usuario_objetivo>@192.168.10.50 'sudo apt-get install -y ssg-debderived'
```

## A.4 · Configurar el agente (perfil CIS)

```bash
cp agent.env.example agent.env
nano agent.env
```
Rellena como mínimo:
```ini
TARGET_HOST=192.168.10.50
TARGET_USER=<usuario_objetivo>
TARGET_SSH_KEY=/home/<tu_usuario>/.ssh/id_ed25519
TARGET_SUDO_PASSWORD=<contraseña_sudo_del_objetivo>
OSCAP_PROFILE_FAMILY=cis
LLM_MODEL=<modelo_que_apuntaste_en_el_paso_2>
```

## A.5 · Ejecutar la auditoría CIS

```bash
set -a; . ./agent.env; set +a     # carga la configuración en el entorno
python audit_agent.py
```
Verás en pantalla el progreso (SSH, Lynis, OpenSCAP, llamadas al LLM). Al terminar:
```bash
ls reports/
cat reports/auditoria-192.168.10.50-cis-*.md
```
📸 **Guarda el nombre del fichero generado y ábrelo: lo necesitarás en el cuestionario.**

## A.6 · Repetir con perfil STIG

STIG (DISA) es un endurecimiento más estricto que CIS. Solo cambia la familia:

```bash
cp agent.env.stig.example agent.env
nano agent.env        # ajusta usuario/clave/sudo/modelo igual que antes
set -a; . ./agent.env; set +a
python audit_agent.py
```
Se genera `reports/auditoria-192.168.10.50-stig-*.md`. **Compara** el número de reglas en
FAIL de CIS frente a STIG.

## A.7 · Leer el informe

Cada informe tiene: (1) resumen ejecutivo, (2) índice de endurecimiento de Lynis,
(3) tabla de reglas FAIL por severidad, y (4) análisis con remediación por hallazgo.
Los reportes crudos quedan en el objetivo: `/var/log/lynis-report.dat`,
`/tmp/oscap-arf.xml`, `/tmp/oscap-report.html`.

---

# PARTE B — Opción CrewAI (multi-agente)

Ahora el mismo trabajo, pero modelado como un **equipo de agentes** que colaboran. Los
escaneos siguen siendo deterministas (se reutilizan como *tools*); el LLM aporta el análisis.

Flujo de agentes:
1. **Auditor** → ejecuta Lynis y OpenSCAP y reúne los hallazgos.
2. **Analista** → redacta un *borrador* de informe priorizado por severidad.
3. **Revisor** → coteja el borrador contra los hallazgos originales, depura y entrega el informe **final**.

## B.1 · Entorno propio para CrewAI

CrewAI arrastra bastantes dependencias: usa un entorno virtual **separado**.

```bash
cd crewai
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
```

## B.2 · Reutilizar la configuración

CrewAI usa el **mismo `agent.env`** de la Parte A (host, credenciales, perfil, modelo).
No hay que reconfigurar nada:

```bash
set -a; . ../agent.env; set +a
```

## B.3 · Ejecutar

```bash
python crew_audit.py
```
Observa en la salida cómo cada agente “habla” y se pasa el trabajo al siguiente.
El informe final queda en `crewai/reports/auditoria-crewai-<familia>.md`.

## B.4 · Qué observar

- El **Auditor** invoca las herramientas (verás `escanear_lynis` / `escanear_openscap`).
- El **Revisor** recibe *tanto los datos originales como el borrador* → por eso puede
  detectar si el Analista se ha inventado algún hallazgo.
- Es **más lento** que la Parte A: es el precio de la orquestación multi-agente.

---

## 4. Solución de problemas

| Síntoma | Causa probable | Solución |
|---------|----------------|----------|
| `curl` a `.240:11434` no responde | Ollama solo escucha en localhost | El docente debe arrancarlo con `OLLAMA_HOST=0.0.0.0:11434` |
| `Permission denied (publickey,password)` | Clave SSH no autorizada en `.50` | Repite el `ssh-copy-id` de A.2 |
| `No hay contenido SCAP…` | Falta la SSG en `.50` | `sudo apt-get install -y ssg-debderived` en el objetivo |
| `oscap` termina con código **2** | Hay reglas en FAIL | **Es normal**, no es un error: 0 = todo pasa, 2 = hay fallos |
| CrewAI se “atasca” en bucles | El modelo es pequeño para tanta autonomía | Es esperable; el diseño ya limita la delegación |

---

## 5. Cuestionario de verificación

Responde a estas **7 preguntas**. Algunas requieren valores de **tu propia ejecución**
(demuestran que la práctica se ha ejecutado de verdad) y otras comprueban tu comprensión.

1. **(Lynis)** ¿Qué valor de **índice de endurecimiento** (`hardening_index`, 0–100)
   reportó Lynis sobre el objetivo `192.168.10.50` en tu ejecución? ¿Es un valor bueno o
   mejorable, y por qué?

2. **(OpenSCAP · CIS)** Indica el **nombre exacto del perfil CIS** que autodetectó el
   agente (empieza por `xccdf_org.ssgproject.content_profile_…`) y el **nombre del fichero
   datastream** utilizado en `.50`.

3. **(CIS vs STIG)** ¿Cuántas reglas terminaron en **FAIL** con el perfil **CIS** y cuántas
   con **STIG** en tu objetivo? ¿Cuál de los dos es más estricto y por qué crees que aparece
   esa diferencia?

4. **(Evidencia de ejecución)** Indica la **ruta y el nombre completo** de los ficheros de
   informe que generaste en la Parte A (CIS y STIG) y en la Parte B (CrewAI).

5. **(Diseño determinista)** En la Parte A, ¿qué parte del trabajo hace **Python** y qué
   parte hace el **LLM**? Explica por qué esa separación resulta **más fiable** cuando el
   modelo de lenguaje es pequeño.

6. **(OpenSCAP)** Durante la ejecución, `oscap` devolvió el código de salida **2**.
   ¿Por qué esto **no** significa que la auditoría haya fallado?

7. **(CrewAI)** Describe la función de cada uno de los **tres agentes** (Auditor, Analista,
   Revisor). En concreto: ¿qué información recibe el **Revisor** que le permite detectar si
   el Analista ha inventado hallazgos que no estaban en los datos originales?

---

> **Entrega:** un documento con las 7 respuestas y, adjuntos, los ficheros de informe
> generados en `reports/` (Parte A) y `crewai/reports/` (Parte B).

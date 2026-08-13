# Agente IA de auditoría (Lynis + OpenSCAP)

Agente que se ejecuta en **192.168.10.241**, audita el servidor **192.168.10.50**
con **Lynis** y **OpenSCAP** (perfil **CIS**, **STIG** o **estándar**, configurable),
y usa el LLM **qwen2.5:7b** en **192.168.10.240** para interpretar, priorizar y
proponer remediaciones.

Diseño: **orquestación determinista + LLM analista**. Python decide qué se ejecuta;
el modelo solo razona sobre los hallazgos ya parseados (más fiable con un 7B).

```
 .241 (agente) ──HTTP :11434──► .240 (Ollama / qwen2.5:7b)
      │
      └──SSH :22──► .50 (lynis audit system · oscap xccdf eval --profile CIS)
```

## Requisitos previos
- En **.50**: Lynis, OpenSCAP y el contenido SSG. Comprueba/instala el contenido:
  ```bash
  ls /usr/share/xml/scap/ssg/content/ssg-ubuntu*-ds.xml \
    || sudo apt-get install -y ssg-debderived
  ```
- En **.240**: Ollama sirviendo `qwen2.5:7b` y **escuchando en la red** (no solo en
  localhost). Verifícalo desde .241:
  ```bash
  curl -s http://192.168.10.240:11434/api/tags
  ```
  Si no responde desde fuera, arranca Ollama con `OLLAMA_HOST=0.0.0.0:11434`.

## Instalación (en .241)
```bash
# copia estos ficheros a .241 (p. ej. con scp) y:
bash setup_241.sh
ssh-keygen -t ed25519 -f ~/.ssh/agente_key -C "agente-auditor" -N ""
ssh-copy-id -i ~/.ssh/agente_key.pub <usuario>@192.168.10.50   # autoriza la clave en el objetivo
cd ~/audit-ia
cp agent.env.example agent.env          # perfil CIS (por defecto), o…
cp agent.env.stig.example agent.env     # …perfil STIG
# edita agent.env con tus datos
```

### Elegir el perfil (CIS / STIG / estándar)
Controla la familia con `OSCAP_PROFILE_FAMILY` en `agent.env`:
```bash
OSCAP_PROFILE_FAMILY=cis      # CIS Level 1 Server (por defecto)
OSCAP_PROFILE_FAMILY=stig     # STIG (DISA)
OSCAP_PROFILE_FAMILY=standard # perfil estándar de la SSG
```
El agente autodetecta el perfil concreto dentro del datastream. Si quieres uno
exacto, fíjalo en `OSCAP_PROFILE` (tiene prioridad). Para ver los disponibles en
el objetivo:
```bash
oscap info /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml | grep -i profile
```
El informe incorpora la familia en el nombre (`auditoria-192.168.10.50-stig-<fecha>.md`),
así que CIS y STIG conviven sin pisarse.

## Ejecución
```bash
cd ~/audit-agent
set -a; . ./agent.env; set +a        # carga la configuración
source .venv/bin/activate
python audit_agent.py
```
El informe consolidado queda en `reports/auditoria-192.168.10.50-<fecha>.md`.
Los reportes crudos quedan en el objetivo: `/var/log/lynis-report.dat`,
`/tmp/oscap-arf.xml`, `/tmp/oscap-report.html`.

## Notas
- `OSCAP_DATASTREAM` y `OSCAP_PROFILE` vacíos ⇒ autodetección (versión de Ubuntu y
  primer perfil CIS disponible, preferentemente `cis_level1_server`). Fíjalos si
  quieres otro nivel (p. ej. `..._profile_cis_level2_server`).
- `oscap` devuelve código **2** cuando hay reglas en FAIL: es normal, no es un error.
- El envío al LLM está **acotado** (`MAX_OSCAP_FINDINGS`, `OSCAP_BATCH`) y se
  mandan hallazgos parseados, nunca el XML crudo, para no saturar el contexto del 7B.
- Para programarlo: añade una entrada de `cron` que exporte `agent.env` y ejecute el script.

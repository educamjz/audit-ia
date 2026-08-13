#!/usr/bin/env bash
# ─── Bootstrap del host del agente (.241) ─────────────────────────────────
# Ejecutar EN 192.168.10.241.  Uso:  bash setup_241.sh
set -euo pipefail

APP_DIR="$HOME/audit-agent"
echo "[*] Instalando dependencias del sistema…"
sudo apt-get update -qq
sudo apt-get install -y python3-venv python3-pip openssh-client

echo "[*] Preparando proyecto en $APP_DIR…"
mkdir -p "$APP_DIR"
# Copia aquí audit_agent.py, requirements.txt y agent.env  (scp desde tu equipo)
cp -n audit_agent.py requirements.txt "$APP_DIR"/ 2>/dev/null || true
[ -f agent.env ] && cp -n agent.env "$APP_DIR"/ || true
cd "$APP_DIR"

echo "[*] Entorno virtual + dependencias Python…"
python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
pip install -q -U pip
pip install -q -r requirements.txt

echo "[*] Clave SSH hacia el objetivo…"
if [ ! -f "$HOME/.ssh/id_ed25519" ]; then
  ssh-keygen -t ed25519 -N '' -f "$HOME/.ssh/id_ed25519"
fi

cat <<EOF

[✓] Listo. Faltan 2 pasos manuales:

  1) Autoriza la clave en el objetivo (.50):
       ssh-copy-id -i ~/.ssh/id_ed25519.pub <usuario>@192.168.10.50

  2) Ajusta la configuración y lanza:
       cd $APP_DIR
       cp agent.env.example agent.env   # y edítalo
       set -a; . ./agent.env; set +a
       source .venv/bin/activate
       python audit_agent.py

EOF

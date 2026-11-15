#!/bin/bash
# setup.sh — Setup environment untuk Node + Python (Puppeteer / Camoufox)
# Optimized: tidak stuck, cepat (~3 menit), kompatibel Ubuntu 20.04 / 22.04 / 24.04
# Jalankan: chmod +x setup.sh && ./setup.sh

# JANGAN pakai set -e — handle manual dengan [FATAL]
export DEBIAN_FRONTEND=noninteractive

# =====================================================
# Sudo detection (minimal VPS sering tidak punya sudo)
# =====================================================
if [ "$(id -u)" -eq 0 ]; then
  SUDO=""
else
  SUDO="sudo"
fi

# =====================================================
# Helpers
# =====================================================
pkg_available() { apt-cache show "$1" >/dev/null 2>&1; }
step() { echo ""; echo "========================================="; echo "[STEP] $1"; echo "========================================="; }
ok()   { echo "[OK] $1"; }
warn() { echo "[!] $1"; }
fail() { echo "[FATAL] $1"; exit 1; }

# =====================================================
# STEP 1: Tunggu dpkg lock
# =====================================================
step "1/9 dpkg lock wait"
LOCK_WAIT=0
while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || \
      fuser /var/lib/dpkg/lock >/dev/null 2>&1 || \
      fuser /var/lib/apt/lists/lock >/dev/null 2>&1; do
  if [ $LOCK_WAIT -ge 180 ]; then
    warn "Lock stuck 180s, force kill..."
    fuser -k /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock 2>/dev/null || true
    sleep 2
    rm -f /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock
    dpkg --configure -a || true
    break
  fi
  sleep 2; LOCK_WAIT=$((LOCK_WAIT+2))
done
ok "Lock released"

# =====================================================
# STEP 2: apt update (skip kalau cache < 1 jam)
# =====================================================
step "2/9 apt update"
STAMP=/var/lib/apt/periodic/update-success-stamp
NEED_UPDATE=1
if [ -f "$STAMP" ]; then
  AGE=$(( $(date +%s) - $(stat -c %Y "$STAMP" 2>/dev/null || echo 0) ))
  if [ "$AGE" -lt 3600 ]; then
    echo "[*] apt cache fresh (${AGE}s old), skip update"
    NEED_UPDATE=0
  fi
fi
if [ "$NEED_UPDATE" = "1" ]; then
  $SUDO apt-get -o DPkg::Lock::Timeout=300 update || fail "apt update failed"
fi
ok "apt update done (or skipped)"

# =====================================================
# STEP 3: Install SEMUA paket apt dalam 1× call
# =====================================================
step "3/9 install apt packages (single batch)"

# Kandidat paket wajib — akan difilter otomatis sesuai repo
CANDIDATES="
  git curl wget ca-certificates xz-utils tar unzip
  python3 python3-pip python3-dev python3-venv
  build-essential pkg-config
  screen rsync sysstat
  xvfb
  libatk1.0-0 libatk-bridge2.0-0 libnspr4 libnss3
  libx11-xcb1 libxcomposite1 libxrandr2 libgbm1
  libpangocairo-1.0-0 libpango-1.0-0 libcairo2
  libatspi2.0-0 libxss1 libxtst6 libxdamage1
  libdbus-1-3 libcups2 libdrm2 libgtk-3-0
  fonts-liberation xdg-utils
  libdbus-glib-1-2 libxt6 libxcursor1 libxext6
  libxfixes3 libxi6 libxrender1
"

# Paket dengan nama berbeda antar versi Ubuntu
FALLBACKS="
  libasound2t64:libasound2
  libayatana-appindicator3-1:libappindicator3-1
  libgdk-pixbuf-2.0-0:libgdk-pixbuf2.0-0
"

PKGS=""
for p in $CANDIDATES; do
  if pkg_available "$p"; then PKGS="$PKGS $p"; fi
done
for group in $FALLBACKS; do
  first=$(echo "$group" | cut -d: -f1)
  second=$(echo "$group" | cut -d: -f2)
  if pkg_available "$first"; then
    PKGS="$PKGS $first"
  elif pkg_available "$second"; then
    PKGS="$PKGS $second"
  fi
done

echo "[*] Installing $(echo $PKGS | wc -w) packages..."
$SUDO apt-get -o DPkg::Lock::Timeout=300 install -y $PKGS \
  || fail "apt install failed"
ok "All apt packages installed"

# =====================================================
# STEP 4: Google Chrome (idempotent + retry)
# =====================================================
step "4/9 Google Chrome"
if command -v google-chrome-stable >/dev/null 2>&1; then
  ok "Chrome already installed: $(google-chrome-stable --version 2>/dev/null)"
else
  echo "[*] Downloading Chrome..."
  rm -f /tmp/chrome.deb
  for i in 1 2 3; do
    if wget -q --timeout=60 --tries=2 \
        https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb \
        -O /tmp/chrome.deb; then
      break
    fi
    warn "Retry $i/3..."
    sleep 3
  done
  [ -s /tmp/chrome.deb ] || fail "Chrome download failed"
  $SUDO apt-get install -y /tmp/chrome.deb || fail "Chrome install failed"
  rm -f /tmp/chrome.deb
  ok "Chrome installed"
fi

# =====================================================
# STEP 5: Python packages
# =====================================================
step "5/9 Python packages"

# Deteksi PEP 668 (Ubuntu 23.04+ / Debian 12+)
PIP_FLAGS=""
for f in /usr/lib/python3*/EXTERNALLY-MANAGED; do
  [ -f "$f" ] && PIP_FLAGS="--break-system-packages" && break
done

echo "[*] pip flags: ${PIP_FLAGS:-none}"
$SUDO pip3 install $PIP_FLAGS --no-cache-dir --upgrade pip 2>/dev/null \
  || warn "pip upgrade skipped"

$SUDO pip3 install $PIP_FLAGS --no-cache-dir \
  python-telegram-bot==20.7 \
  py-cpuinfo \
  psutil \
  aiohttp==3.12.15 \
  aiohttp-socks==0.12.0 \
  colorama \
  camoufox \
  || fail "pip install failed"
ok "Python packages installed"

# =====================================================
# STEP 6: Node.js packages (skip Chromium download!)
# =====================================================
step "6/9 Node.js packages"

command -v node >/dev/null 2>&1 || fail "node not found — install Node via nvm first"
command -v npm  >/dev/null 2>&1 || fail "npm not found"

# ⚡ OPTIMASI BESAR: skip download Chromium — pakai Chrome system
export PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
export PUPPETEER_SKIP_DOWNLOAD=true
export PUPPETEER_EXECUTABLE_PATH=/usr/bin/google-chrome-stable

npm cache clean --force >/dev/null 2>&1 || true

npm install --no-audit --no-fund \
  random-useragent \
  set-cookie-parser \
  undici \
  cloudscraper \
  puppeteer-extra \
  puppeteer-extra-plugin-stealth \
  puppeteer-extra-plugin-anonymize-ua \
  puppeteer-real-browser \
  puppeteer \
  axios \
  node-fetch@2 \
  node-fetch-commonjs \
  socks \
  hpack \
  user-agents \
  cheerio \
  colors \
  async \
  resemblejs \
  http-proxy-agent \
  bytenode \
  ssh2 \
  gradient-string \
  randomstring \
  http2-wrapper \
  minimist \
  header-generator \
  || fail "npm install failed"
ok "Node packages installed"

# =====================================================
# STEP 7: Xvfb (persistent via nohup)
# =====================================================
step "7/9 Xvfb virtual display"

if pgrep -f "Xvfb :99" >/dev/null 2>&1; then
  ok "Xvfb :99 already running"
else
  echo "[*] Starting Xvfb :99..."
  # nohup + disown = tetap jalan setelah script/SSH exit
  nohup Xvfb :99 -screen 0 1024x768x16 >/tmp/xvfb.log 2>&1 &
  disown
  sleep 1
  if pgrep -f "Xvfb :99" >/dev/null 2>&1; then
    ok "Xvfb :99 running (PID: $(pgrep -f 'Xvfb :99'))"
  else
    warn "Xvfb gagal start, cek /tmp/xvfb.log"
  fi
fi

# =====================================================
# STEP 8: Persist environment ke bashrc
# =====================================================
step "8/9 persist env"

add_line() {
  local line="$1"
  local file="$2"
  touch "$file" 2>/dev/null || true
  if ! grep -qxF "$line" "$file" 2>/dev/null; then
    echo "$line" >> "$file"
  fi
}

for f in "$HOME/.bashrc" "$HOME/.profile" "$HOME/.bash_profile"; do
  add_line 'export CHROME_PATH=/usr/bin/google-chrome-stable' "$f"
  add_line 'export DISPLAY=:99' "$f"
  add_line 'export PUPPETEER_EXECUTABLE_PATH=/usr/bin/google-chrome-stable' "$f"
  add_line 'export PUPPETEER_SKIP_DOWNLOAD=true' "$f"
done

# Export untuk session ini juga
export CHROME_PATH=/usr/bin/google-chrome-stable
export DISPLAY=:99
export PUPPETEER_EXECUTABLE_PATH=/usr/bin/google-chrome-stable
export PUPPETEER_SKIP_DOWNLOAD=true

ok "env persisted"

# =====================================================
# STEP 9: Summary
# =====================================================
step "9/9 done"
echo ""
echo "======================================="
echo "[✓] Setup selesai."
echo "    Node       : $(node -v 2>/dev/null || echo 'belum terpasang')"
echo "    npm        : $(npm -v 2>/dev/null || echo 'belum terpasang')"
echo "    Python     : $(python3 --version 2>/dev/null)"
echo "    Chrome     : $(which google-chrome-stable 2>/dev/null || echo 'tidak ditemukan')"
echo "    Xvfb       : $(pgrep -f 'Xvfb :99' >/dev/null && echo 'running di :99' || echo 'belum berjalan')"
echo "    CHROME_PATH: ${CHROME_PATH}"
echo "    DISPLAY    : ${DISPLAY}"
echo "======================================="

#!/bin/bash
# setup.sh — Setup environment untuk Node + Python (Puppeteer / Camoufox)
# Jalankan: chmod +x setup.sh && ./setup.sh

set -e

# =====================================================
# 1. Update & Upgrade system
# =====================================================
echo "[+] Updating package list & upgrading system"
sudo apt-get update -y
sudo apt-get upgrade -y

# =====================================================
# 2. Install dependencies untuk Chrome / Puppeteer
# =====================================================
echo "[+] Installing browser / Chromium dependencies"
sudo apt-get install -y \
  libatk1.0-0 \
  libatk-bridge2.0-0 \
  libnspr4 \
  libnss3 \
  libx11-xcb1 \
  libxcomposite1 \
  libxrandr2 \
  libgbm1 \
  libasound2 \
  libpangocairo-1.0-0 \
  libappindicator3-1 \
  libatspi2.0-0 \
  libgdk-pixbuf2.0-0 \
  libxss1 \
  libxtst6 \
  libxdamage1 \
  libdbus-1-3 \
  libcups2 \
  libdrm2 \
  libgtk-3-0 \
  fonts-liberation \
  xdg-utils \
  wget \
  ca-certificates

# =====================================================
# 3. Install Python3 & pip
# =====================================================
echo "[+] Installing Python3 & pip"
sudo apt-get install -y python3 python3-pip

echo "[+] Upgrading pip"
pip3 install --upgrade pip

# =====================================================
# 4. Install Python packages (Telegram bot, Camoufox, dll)
# =====================================================
echo "[+] Installing Python packages"
pip3 install \
  python-telegram-bot==20.7 \
  py-cpuinfo \
  psutil \
  aiohttp==3.12.15 \
  aiohttp-socks==0.12.0 \
  colorama \
  camoufox

# =====================================================
# 5. Install Node.js packages (global project deps)
# =====================================================
echo "[+] Installing Node.js packages"
npm install \
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
  node-fetch@2.0.0 \
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
  header-generator

# =====================================================
# 6. Install dependencies untuk Camoufox / Firefox
# =====================================================
echo "[+] Installing Camoufox / Firefox dependencies"
sudo apt-get install -y \
  libgtk-3-0 \
  libdbus-glib-1-2 \
  libxt6 \
  libx11-xcb1 \
  libxcomposite1 \
  libxcursor1 \
  libxdamage1 \
  libxext6 \
  libxfixes3 \
  libxi6 \
  libxrender1 \
  libxss1 \
  libxtst6 \
  libasound2 \
  libpango-1.0-0 \
  libcairo2 \
  libgdk-pixbuf2.0-0 \
  libatk1.0-0 \
  libatk-bridge2.0-0 \
  libcups2

# =====================================================
# 7. Install Google Chrome (stable)
# =====================================================
echo "[+] Downloading & installing Google Chrome"
wget -q https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb -O /tmp/google-chrome-stable_current_amd64.deb
sudo apt install -y /tmp/google-chrome-stable_current_amd64.deb
rm -f /tmp/google-chrome-stable_current_amd64.deb

# =====================================================
# 8. Install & jalankan Xvfb (virtual display)
# =====================================================
echo "[+] Installing Xvfb"
sudo apt-get install -y xvfb

# Jalankan Xvfb hanya jika belum berjalan di :99
if ! pgrep -f "Xvfb :99" > /dev/null; then
  echo "[+] Starting Xvfb on :99"
  Xvfb :99 -screen 0 1024x768x16 &
  sleep 1
else
  echo "[=] Xvfb :99 already running"
fi

export DISPLAY=:99

# =====================================================
# 9. Export CHROME_PATH ke bashrc (idempotent)
# =====================================================
echo "[+] Setting CHROME_PATH"
if ! grep -q "CHROME_PATH=/usr/bin/google-chrome-stable" ~/.bashrc; then
  echo 'export CHROME_PATH=/usr/bin/google-chrome-stable' >> ~/.bashrc
fi

# Tambahkan DISPLAY juga ke bashrc agar persisten
if ! grep -q "export DISPLAY=:99" ~/.bashrc; then
  echo 'export DISPLAY=:99' >> ~/.bashrc
fi

# Load ulang bashrc di sesi sekarang
source ~/.bashrc

echo "[✓] CHROME_PATH = $CHROME_PATH"
echo "[✓] DISPLAY     = $DISPLAY"

# =====================================================
# 10. Selesai
# =====================================================
echo ""
echo "======================================="
echo "[✓] Setup selesai."
echo "    Node   : $(node -v 2>/dev/null || echo 'belum terpasang')"
echo "    npm    : $(npm -v 2>/dev/null || echo 'belum terpasang')"
echo "    Python : $(python3 --version 2>/dev/null)"
echo "    Chrome : $(which google-chrome-stable 2>/dev/null || echo 'tidak ditemukan')"
echo "    Xvfb   : $(pgrep -f 'Xvfb :99' >/dev/null && echo 'running di :99' || echo 'belum berjalan')"
echo "======================================="
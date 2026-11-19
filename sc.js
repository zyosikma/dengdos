#!/usr/bin/env node
// sc.js — tiered proxy scraper (T1 verified/checked, T2 frequently-updated, T3 API-filtered, T4 bulk)
// Usage: node sc.js [--out proxy.txt] [--tier1-only]

const fs = require('fs');
const https = require('https');
const http = require('http');

const OUT = (() => {
    const i = process.argv.indexOf('--out');
    return i >= 0 && process.argv[i+1] ? process.argv[i+1] : 'proxy.txt';
})();
const TIER1_ONLY = process.argv.includes('--tier1-only');

const SOURCES = [
    // ── TIER 1: verified HTTPS / checked, small volume, high alive (30-50%) ──
    { name: 'roosterkid-https', tier: 1, url: 'https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt' },
    { name: 'monosans-5min',    tier: 1, url: 'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt' },
    { name: 'proxifly-15min',   tier: 1, url: 'https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt' },
    { name: 'jetkai-checked',   tier: 1, url: 'https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt' },

    // ── TIER 2: frequently updated, medium volume, alive 15-30% ──
    { name: 'vakhov-30min',     tier: 2, url: 'https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt' },
    { name: 'mmpx12-checked',   tier: 2, url: 'https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt' },
    { name: 'kangproxy-id',     tier: 2, url: 'https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/http/http.txt' },
    { name: 'sunny9577-multi',  tier: 2, url: 'https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt' },
    { name: 'zloi-hideip',      tier: 2, url: 'https://raw.githubusercontent.com/zloi-user/hideip.me/main/http.txt' },
    { name: 'yemixzy-checked',  tier: 2, url: 'https://raw.githubusercontent.com/yemixzy/proxy-list/main/proxies/http.txt' },
    { name: 'proxy4parsing',    tier: 2, url: 'https://raw.githubusercontent.com/proxy4parsing/proxy-list/main/http.txt' },

    // ── TIER 3: API with server-side filter (uptime/ping) ──
    { name: 'geonode-p1',       tier: 3, url: 'https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc&protocols=http,https', json: 'geonode' },
    { name: 'geonode-p2',       tier: 3, url: 'https://proxylist.geonode.com/api/proxy-list?limit=500&page=2&sort_by=lastChecked&sort_type=desc&protocols=http,https', json: 'geonode' },
    { name: 'geonode-p3',       tier: 3, url: 'https://proxylist.geonode.com/api/proxy-list?limit=500&page=3&sort_by=lastChecked&sort_type=desc&protocols=http,https', json: 'geonode' },
    { name: 'proxyscrape-fast', tier: 3, url: 'https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=5000&country=all&ssl=all&anonymity=all' },
    { name: 'proxy-list.dl',    tier: 3, url: 'https://www.proxy-list.download/api/v1/get?type=http' },

    // ── TIER 4: bulk backup (large, alive 3-8%) ──
    { name: 'thespeedx-bulk',   tier: 4, url: 'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt' },
    { name: 'shiftytr-bulk',    tier: 4, url: 'https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt' },
    { name: 'clarketm-bulk',    tier: 4, url: 'https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt' },
];

function fetchUrl(url, timeout = 20000) {
    return new Promise((resolve) => {
        const client = url.startsWith('https') ? https : http;
        const req = client.get(url, { timeout }, (res) => {
            if (res.statusCode !== 200) { res.resume(); resolve(null); return; }
            let data = '';
            res.on('data', (c) => { data += c.toString(); });
            res.on('end', () => resolve(data));
        });
        req.on('error', () => resolve(null));
        req.on('timeout', () => { req.destroy(); resolve(null); });
    });
}

function isPrivate(a, b) {
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    if (a === 198 && (b === 18 || b === 19)) return true;
    if (a >= 224) return true;
    return false;
}

function parseRaw(raw) {
    if (!raw) return [];
    const out = [];
    const seen = new Set();
    for (const line of raw.split('\n')) {
        let t = line.trim();
        if (!t || t.startsWith('#') || t.startsWith('//')) continue;
        if (t.startsWith('http://')) t = t.slice(7);
        else if (t.startsWith('https://')) t = t.slice(8);
        else if (t.includes('://')) continue;
        t = t.split('/')[0].split(' ')[0].split(',')[0].split('\t')[0].split(';')[0];
        const m = t.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})$/);
        if (!m) continue;
        const parts = m[1].split('.').map(Number);
        if (parts.some(p => p > 255)) continue;
        if (isPrivate(parts[0], parts[1])) continue;
        const port = parseInt(m[2]);
        if (port < 1 || port > 65535) continue;
        const hp = m[1] + ':' + port;
        if (seen.has(hp)) continue;
        seen.add(hp);
        out.push(hp);
    }
    return out;
}

function parseGeonode(raw) {
    if (!raw) return [];
    const out = [];
    const seen = new Set();
    try {
        const j = JSON.parse(raw);
        if (!j || !j.data) return [];
        for (const p of j.data) {
            if (!p.ip || !p.port) continue;
            const ip = String(p.ip).trim();
            const port = String(p.port).trim();
            if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) continue;
            const parts = ip.split('.').map(Number);
            if (parts.some(x => x > 255)) continue;
            if (isPrivate(parts[0], parts[1])) continue;
            const hp = ip + ':' + port;
            if (seen.has(hp)) continue;
            seen.add(hp);
            out.push(hp);
        }
    } catch (e) {}
    return out;
}

(async () => {
    const filtered = TIER1_ONLY ? SOURCES.filter(s => s.tier === 1) : SOURCES;
    console.log('[scrape] ' + filtered.length + ' sources' + (TIER1_ONLY ? ' (tier1-only)' : ''));

    const results = await Promise.all(filtered.map(async (s) => {
        const t0 = Date.now();
        const data = await fetchUrl(s.url);
        const list = s.json === 'geonode' ? parseGeonode(data) : parseRaw(data);
        console.log('  [T' + s.tier + '] ' + s.name.padEnd(20) + ' ' + String(list.length).padStart(6) + ' (' + (Date.now()-t0) + 'ms)');
        return { tier: s.tier, list };
    }));

    const globalSeen = new Set();
    const byTier = { 1: [], 2: [], 3: [], 4: [] };
    for (const r of results) {
        for (const hp of r.list) {
            if (globalSeen.has(hp)) continue;
            globalSeen.add(hp);
            byTier[r.tier].push(hp);
        }
    }
    for (const t of [1, 2, 3, 4]) {
        for (let i = byTier[t].length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [byTier[t][i], byTier[t][j]] = [byTier[t][j], byTier[t][i]];
        }
    }

    const merged = [...byTier[1], ...byTier[2], ...byTier[3], ...byTier[4]];

    console.log('');
    console.log('[scrape] T1=' + byTier[1].length + ' T2=' + byTier[2].length + ' T3=' + byTier[3].length + ' T4=' + byTier[4].length);
    console.log('[scrape] total ' + merged.length + ' unique → ' + OUT);
    fs.writeFileSync(OUT, merged.join('\n') + '\n');
})();

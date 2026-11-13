#!/usr/bin/env node
// sc.js — scrape free HTTP proxies only, no test
// Usage: node sc.js [--out proxy.txt]

const fs = require('fs');
const https = require('https');
const http = require('http');

const OUT = (() => {
    const i = process.argv.indexOf('--out');
    return i >= 0 && process.argv[i+1] ? process.argv[i+1] : 'proxy.txt';
})();

const SOURCES = [
    { name: 'monosans',       url: 'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt' },
    { name: 'proxifly',       url: 'https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt' },
    { name: 'thespeedx',      url: 'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt' },
    { name: 'roosterkid',     url: 'https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt' },
    { name: 'proxyscrape-v2', url: 'https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all' },
    { name: 'vakhov',         url: 'https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt' },
    { name: 'mmpx12',         url: 'https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt' },
    { name: 'shiftytr',       url: 'https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt' },
    { name: 'clarketm',       url: 'https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt' },
    { name: 'jetkai',         url: 'https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt' },
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

function parse(raw) {
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

(async () => {
    console.log('[scrape] ' + SOURCES.length + ' sources');

    const perSource = await Promise.all(SOURCES.map(async (s) => {
        const t0 = Date.now();
        const data = await fetchUrl(s.url);
        const list = parse(data);
        console.log('  ' + s.name.padEnd(18) + ' ' + String(list.length).padStart(6) + ' (' + (Date.now()-t0) + 'ms)');
        return list;
    }));

    const all = new Set();
    for (const l of perSource) for (const p of l) all.add(p);
    const merged = [...all];

    // shuffle biar round-robin proxy gak selalu dari sumber sama
    for (let i = merged.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [merged[i], merged[j]] = [merged[j], merged[i]];
    }

    fs.writeFileSync(OUT, merged.join('\n') + '\n');
    console.log('[scrape] total ' + merged.length + ' unique → ' + OUT);
})();

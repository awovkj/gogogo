import { connect as rawConnect } from 'cloudflare:sockets';

const connect = (options) => rawConnect(options);

const UUID = '26bca0a8-d45f-495a-ab10-3a4556b5c1af';
const SUB_PASSWORD = '123456';
const SUB_TOKEN = '';
const DEFAULT_PROXY_IP = 'pr.510517.xyz:50001';
const DEFAULT_SUB_DOMAIN = 'sub.cmliussss.net';
const DEFAULT_CONVERTER = 'https://subapi.cmliussss.net';
const CLASH_CONFIG = 'https://faster1.510517.xyz/https://raw.githubusercontent.com/awovkj/ACL4SSR/refs/heads/main/Clash/config/ACL4SSR_Online_Full_MultiMode_CF.ini';
const SINGBOX_CONFIG_V12 = 'https://raw.githubusercontent.com/sinspired/sub-store-template/main/1.12.x/sing-box.json';
const SINGBOX_CONFIG_V11 = 'https://raw.githubusercontent.com/sinspired/sub-store-template/main/1.11.x/sing-box.json';
const DLS = '5000';
const DEFAULT_PS = '';

const P_V = 'vless';
const P_S = 'socks';
const P_S5 = 'socks5';

let ECH = true;
let ECH_DNS = 'https://doh.cmliussss.net/CMLiussss';
let ECH_SNI = 'cloudflare-ech.com';
let FP = ECH ? 'chrome' : 'randomized';

const MAX_PENDING = 2 * 1024 * 1024;
const KEEPALIVE = 15000;
const STALL_TO = 8000;
const MAX_STALL = 12;
const MAX_RECONN = 24;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function envValue(env, key, fallback = '') {
  const value = env?.[key];
  return typeof value === 'string' && value.trim() !== '' ? value : fallback;
}

function splitCSV(value) {
  return (value || '').split(',').map((item) => item.trim()).filter(Boolean);
}

async function getDynamicUUID(key, refresh = 86400) {
  const time = Math.floor(Date.now() / 1000 / Number(refresh || 86400));
  const msg = textEncoder.encode(`${key}-${time}`);
  const hash = await crypto.subtle.digest('SHA-256', msg);
  const bytes = new Uint8Array(hash);
  return [...bytes.slice(0, 16)]
    .map((n) => n.toString(16).padStart(2, '0'))
    .join('')
    .replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, '$1-$2-$3-$4-$5');
}

function buildUUID(arr, offset) {
  return Array.from(arr.slice(offset, offset + 16))
    .map((n) => n.toString(16).padStart(2, '0'))
    .join('')
    .replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, '$1-$2-$3-$4-$5');
}

function extractAddr(buffer) {
  const optOffset = 18 + buffer[17] + 1;
  const port = (buffer[optOffset] << 8) | buffer[optOffset + 1];
  const type = buffer[optOffset + 2];
  let addrOffset = optOffset + 3;
  let host;
  let length;
  switch (type) {
    case 1:
      length = 4;
      host = buffer.slice(addrOffset, addrOffset + length).join('.');
      break;
    case 2:
      length = buffer[addrOffset++];
      host = textDecoder.decode(buffer.slice(addrOffset, addrOffset + length));
      break;
    case 3:
      length = 16;
      host = `[${Array.from({ length: 8 }, (_, i) => ((buffer[addrOffset + i * 2] << 8) | buffer[addrOffset + i * 2 + 1]).toString(16)).join(':')}]`;
      break;
    default:
      throw new Error('Addr type err');
  }
  return { host, port, payload: buffer.slice(addrOffset + length), addressType: type };
}

function stripIPv6Brackets(host) {
  return host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
}

function isIPv6Host(host) {
  return stripIPv6Brackets(host).includes(':');
}

function formatHostForUrl(host) {
  return isIPv6Host(host) ? `[${stripIPv6Brackets(host)}]` : stripIPv6Brackets(host);
}

function parseAddressPort(segment) {
  const raw = (segment || '').trim();
  if (!raw) return ['', 443];
  if (raw.startsWith('[')) {
    const matched = raw.match(/^\[([^\]]+)\](?::(\d+))?$/);
    if (matched) return [matched[1], Number(matched[2] || 443)];
    return [stripIPv6Brackets(raw), 443];
  }
  const colonCount = (raw.match(/:/g) || []).length;
  if (colonCount > 1) return [raw, 443];
  const index = raw.lastIndexOf(':');
  if (index > -1) {
    const address = raw.slice(0, index);
    const portText = raw.slice(index + 1);
    if (/^\d+$/.test(portText)) return [address, Number(portText)];
  }
  return [raw, 443];
}

function parserSq(raw) {
  let username;
  let password;
  let hostname;
  let port;
  let authPart = '';
  let hostPart = raw;
  const at = raw.lastIndexOf('@');
  if (at !== -1) {
    authPart = raw.substring(0, at);
    hostPart = raw.substring(at + 1);
  }
  if (authPart && !authPart.includes(':')) {
    try {
      const padded = authPart.replace(/%3D/g, '=').padEnd(authPart.length + (4 - authPart.length % 4) % 4, '=');
      const decoded = atob(padded);
      const pair = decoded.split(':');
      if (pair.length === 2) [username, password] = pair;
    } catch (_error) {
      username = username || undefined;
      password = password || undefined;
    }
  }
  if (!username && authPart && authPart.includes(':')) {
    const index = authPart.indexOf(':');
    username = authPart.substring(0, index);
    password = authPart.substring(index + 1);
  }
  const [host, parsedPort] = parseAddressPort(hostPart);
  hostname = host;
  port = parsedPort || (raw.includes('http=') ? 80 : 1080);
  if (!hostname || Number.isNaN(port)) throw new Error('Invalid cfg');
  return { username, password, hostname, port };
}

function parsePC(path) {
  let proxyIP = null;
  let sq = null;
  let enSq = null;
  let gp = null;

  const reGlobal = new RegExp(`(${P_S}5?|https?):\\/\\/([^/#?]+)`, 'i');
  const globalMatch = path.match(reGlobal);
  if (globalMatch) {
    try {
      const cfg = parserSq(globalMatch[2]);
      const type = globalMatch[1].toLowerCase().includes('5') || globalMatch[1].includes(P_S) ? P_S5 : 'http';
      gp = { type, cfg };
      return { proxyIP, sq, enSq, gp };
    } catch (_error) {
      gp = null;
    }
  }

  const ipMatch = path.match(/(?:^|\/)(?:proxy)?ip[=\/]([^?#]+)/i);
  const hasProxyProto = path.match(new RegExp(`(?:^|\\/)(${P_S}5?|s5|http)[=\\/]`, 'i'));
  if (ipMatch && !hasProxyProto) {
    const [addr, port = 443] = parseAddressPort(ipMatch[1]);
    proxyIP = { address: stripIPv6Brackets(addr), port: Number(port) };
  }

  const reLocal = new RegExp(`(?:^|\\/)(${P_S}5?|s5|http)[=\\/]([^/#?]+)`, 'i');
  const localMatch = path.match(reLocal);
  if (localMatch) {
    try {
      sq = parserSq(localMatch[2]);
      enSq = localMatch[1].toLowerCase().includes('http') ? 'http' : P_S5;
    } catch (_error) {
      sq = null;
      enSq = null;
    }
  }

  return { proxyIP, sq, enSq, gp };
}

async function connSq(addressType, addressRemote, portRemote, cfg) {
  const { username, password, hostname, port } = cfg;
  const socket = connect({ hostname, port });
  const writer = socket.writable.getWriter();
  await writer.write(new Uint8Array([5, username ? 2 : 1, 0, username ? 2 : 0]));
  const reader = socket.readable.getReader();
  let response = (await reader.read()).value;
  if (response[1] === 2) {
    const auth = new Uint8Array([1, username.length, ...textEncoder.encode(username), password.length, ...textEncoder.encode(password)]);
    await writer.write(auth);
    response = (await reader.read()).value;
    if (response[1] !== 0) throw new Error('Auth fail');
  }
  let dst;
  if (addressType === 1) {
    dst = new Uint8Array([1, ...addressRemote.split('.').map(Number)]);
  } else if (addressType === 2) {
    dst = new Uint8Array([3, addressRemote.length, ...textEncoder.encode(addressRemote)]);
  } else if (addressType === 3) {
    const ipv6 = stripIPv6Brackets(addressRemote);
    const sections = ipv6.split('::');
    const left = sections[0] ? sections[0].split(':').filter(Boolean) : [];
    const right = sections[1] ? sections[1].split(':').filter(Boolean) : [];
    const fill = sections.length === 2 ? Array(Math.max(0, 8 - left.length - right.length)).fill('0') : [];
    const parts = [...left, ...fill, ...right];
    const bytes = [];
    for (const part of parts) {
      const value = parseInt(part || '0', 16);
      bytes.push((value >> 8) & 0xff, value & 0xff);
    }
    dst = new Uint8Array([4, ...bytes]);
  } else {
    throw new Error('Unsupported address type');
  }
  await writer.write(new Uint8Array([5, 1, 0, ...dst, (portRemote >> 8) & 0xff, portRemote & 0xff]));
  response = (await reader.read()).value;
  if (response[1] !== 0) throw new Error('Conn fail');
  writer.releaseLock();
  reader.releaseLock();
  return socket;
}

async function connHttp(_addressType, addressRemote, portRemote, cfg) {
  const { username, password, hostname, port } = cfg;
  const socket = connect({ hostname, port });
  let req = `CONNECT ${addressRemote}:${portRemote} HTTP/1.1\r\nHost: ${addressRemote}:${portRemote}\r\n`;
  if (username && password) req += `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r\n`;
  req += 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36\r\nConnection: keep-alive\r\n\r\n';
  const writer = socket.writable.getWriter();
  await writer.write(textEncoder.encode(req));
  writer.releaseLock();
  const reader = socket.readable.getReader();
  let buffer = new Uint8Array(0);
  while (true) {
    const { value, done } = await reader.read();
    if (done) throw new Error('Http close');
    const merged = new Uint8Array(buffer.length + value.length);
    merged.set(buffer);
    merged.set(value, buffer.length);
    buffer = merged;
    if (buffer.length > 65536) throw new Error('Http large');
    const text = textDecoder.decode(buffer);
    if (text.includes('\r\n\r\n')) {
      if (/^HTTP\/1\.[01] 2/i.test(text.split('\r\n')[0])) {
        reader.releaseLock();
        return socket;
      }
      throw new Error(`Http ref: ${text.split('\r\n')[0]}`);
    }
  }
}

class Pool {
  constructor() {
    this.buf = new ArrayBuffer(16384);
    this.ptr = 0;
    this.pool = [];
    this.max = 8;
    this.large = false;
  }

  alloc(size) {
    if (size <= 4096 && size <= 16384 - this.ptr) {
      const view = new Uint8Array(this.buf, this.ptr, size);
      this.ptr += size;
      return view;
    }
    const recycled = this.pool.pop();
    if (recycled && recycled.byteLength >= size) return new Uint8Array(recycled.buffer, 0, size);
    return new Uint8Array(size);
  }

  free(buffer) {
    if (buffer.buffer === this.buf) {
      this.ptr = Math.max(0, this.ptr - buffer.length);
      return;
    }
    if (this.pool.length < this.max && buffer.byteLength >= 1024) this.pool.push(buffer);
  }

  enableLarge() {
    this.large = true;
  }

  reset() {
    this.ptr = 0;
    this.pool.length = 0;
    this.large = false;
  }
}

function handle(ws, pip, sq, enSq, gp, uid) {
  const pool = new Pool();
  let sock;
  let writer;
  let reader;
  let info;
  let first = true;
  let rxBytes = 0;
  let stalls = 0;
  let reconns = 0;
  let lastAct = Date.now();
  let connecting = false;
  let reading = false;
  const timers = {};
  const pending = [];
  let pendingBytes = 0;
  let score = 1.0;
  let lastChk = Date.now();
  let lastRx = 0;
  const stats = { tot: 0, cnt: 0, big: 0, win: 0, ts: Date.now() };
  let mode = 'adaptive';
  let avgSz = 0;
  const tputs = [];

  const updateMode = (size) => {
    stats.tot += size;
    stats.cnt += 1;
    if (size > 8192) stats.big += 1;
    avgSz = avgSz * 0.9 + size * 0.1;
    const now = Date.now();
    if (now - stats.ts > 1000) {
      const rate = stats.win;
      tputs.push(rate);
      if (tputs.length > 5) tputs.shift();
      stats.win = size;
      stats.ts = now;
      const avg = tputs.reduce((acc, item) => acc + item, 0) / tputs.length;
      if (stats.cnt >= 20) {
        if (avg < 8388608 || avgSz < 4096) {
          if (mode !== 'buffered') {
            mode = 'buffered';
            pool.enableLarge();
          }
        } else if (avg > 16777216 && avgSz > 12288) {
          mode = 'direct';
        } else {
          mode = 'adaptive';
        }
      }
    } else {
      stats.win += size;
    }
  };

  const flushPendingBatch = (batch, batchSize) => {
    if (!batchSize || ws.readyState !== 1) return;
    const merged = new Uint8Array(batchSize);
    let pos = 0;
    for (const chunk of batch) {
      merged.set(chunk, pos);
      pos += chunk.length;
    }
    ws.send(merged);
  };

  const cleanSock = () => {
    reading = false;
    try {
      writer?.releaseLock();
    } catch (_error) {
      writer = undefined;
    }
    try {
      reader?.releaseLock();
    } catch (_error) {
      reader = undefined;
    }
    try {
      sock?.close();
    } catch (_error) {
      sock = undefined;
    }
  };

  const cleanup = () => {
    Object.values(timers).forEach(clearInterval);
    cleanSock();
    while (pending.length) pool.free(pending.shift());
    pendingBytes = 0;
    pool.reset();
  };

  const tryConnect = async (host, port, addressType) => {
    if (gp) {
      if (gp.type === P_S5) return connSq(addressType, host, port, gp.cfg);
      if (gp.type === 'http') return connHttp(addressType, host, port, gp.cfg);
    }
    try {
      const socket = connect({ hostname: stripIPv6Brackets(host), port });
      if (socket.opened) await socket.opened;
      return socket;
    } catch (error) {
      if (!sq && !pip) throw error;
      if (sq) {
        try {
          const localSocket = enSq === 'http' ? await connHttp(addressType, host, port, sq) : await connSq(addressType, host, port, sq);
          if (localSocket.opened) await localSocket.opened;
          return localSocket;
        } catch (_error) {
          void _error;
        }
      }
      if (pip) {
        const fallbackSocket = connect({ hostname: stripIPv6Brackets(pip.address), port: pip.port });
        if (fallbackSocket.opened) await fallbackSocket.opened;
        return fallbackSocket;
      }
      throw error;
    }
  };

  const readLoop = async () => {
    if (reading) return;
    reading = true;
    let batch = [];
    let batchSize = 0;
    let batchTimer = null;
    const flush = () => {
      flushPendingBatch(batch, batchSize);
      batch = [];
      batchSize = 0;
      if (batchTimer) {
        clearTimeout(batchTimer);
        batchTimer = null;
      }
    };
    try {
      while (true) {
        if (pendingBytes > MAX_PENDING) {
          await new Promise((resolve) => setTimeout(resolve, 100));
          continue;
        }
        const { done, value } = await reader.read();
        if (value?.length) {
          rxBytes += value.length;
          lastAct = Date.now();
          stalls = 0;
          updateMode(value.length);
          const now = Date.now();
          if (now - lastChk > 5000) {
            const elapsed = now - lastChk;
            const bytes = rxBytes - lastRx;
            const throughput = bytes / elapsed;
            if (throughput > 500) score = Math.min(1.0, score + 0.05);
            else if (throughput < 50) score = Math.max(0.1, score - 0.05);
            lastChk = now;
            lastRx = rxBytes;
          }
          if (mode === 'buffered') {
            if (value.length < 16384) {
              batch.push(value);
              batchSize += value.length;
              if (batchSize >= 65536) flush();
              else if (!batchTimer) batchTimer = setTimeout(flush, avgSz > 8192 ? 8 : 25);
            } else {
              flush();
              if (ws.readyState === 1) ws.send(value);
            }
          } else if (mode === 'direct') {
            flush();
            if (ws.readyState === 1) ws.send(value);
          } else if (value.length < 8192) {
            batch.push(value);
            batchSize += value.length;
            if (batchSize >= 49152) flush();
            else if (!batchTimer) batchTimer = setTimeout(flush, 12);
          } else {
            flush();
            if (ws.readyState === 1) ws.send(value);
          }
        }
        if (done) {
          flush();
          reading = false;
          reconn();
          break;
        }
      }
    } catch {
      flush();
      if (batchTimer) clearTimeout(batchTimer);
      reading = false;
      reconn();
    }
  };

  const establish = async () => {
    try {
      sock = await tryConnect(info.host, info.port, info.addressType);
      if (sock.opened) await sock.opened;
      writer = sock.writable.getWriter();
      reader = sock.readable.getReader();
      const batch = pending.splice(0, 10);
      for (const chunk of batch) {
        await writer.write(chunk);
        pendingBytes -= chunk.length;
        pool.free(chunk);
      }
      connecting = false;
      reconns = 0;
      score = Math.min(1.0, score + 0.15);
      lastAct = Date.now();
      readLoop();
    } catch {
      connecting = false;
      score = Math.max(0.1, score - 0.2);
      reconn();
    }
  };

  const reconn = async () => {
    if (!info || ws.readyState !== 1) {
      cleanup();
      ws.close(1011);
      return;
    }
    if (reconns >= MAX_RECONN) {
      cleanup();
      ws.close(1011);
      return;
    }
    if (connecting) return;
    reconns += 1;
    let delay = Math.min(50 * Math.pow(1.5, reconns - 1), 3000) * (1.5 - score * 0.5);
    delay = Math.max(50, Math.floor(delay));
    try {
      cleanSock();
      if (pendingBytes > MAX_PENDING * 2) {
        while (pendingBytes > MAX_PENDING && pending.length > 5) {
          const dropped = pending.shift();
          pendingBytes -= dropped.length;
          pool.free(dropped);
        }
      }
      await new Promise((resolve) => setTimeout(resolve, delay));
      connecting = true;
      sock = await tryConnect(info.host, info.port, info.addressType);
      if (sock.opened) await sock.opened;
      writer = sock.writable.getWriter();
      reader = sock.readable.getReader();
      const batch = pending.splice(0, 10);
      for (const chunk of batch) {
        await writer.write(chunk);
        pendingBytes -= chunk.length;
        pool.free(chunk);
      }
      connecting = false;
      reconns = 0;
      score = Math.min(1.0, score + 0.15);
      stalls = 0;
      lastAct = Date.now();
      readLoop();
    } catch {
      connecting = false;
      score = Math.max(0.1, score - 0.2);
      if (reconns < MAX_RECONN && ws.readyState === 1) setTimeout(reconn, 500);
      else {
        cleanup();
        ws.close(1011);
      }
    }
  };

  const startTimers = () => {
    timers.ka = setInterval(async () => {
      if (!connecting && writer && Date.now() - lastAct > KEEPALIVE) {
        try {
          await writer.write(new Uint8Array(0));
          lastAct = Date.now();
        } catch {
          reconn();
        }
      }
    }, KEEPALIVE / 3);
    timers.hc = setInterval(() => {
      if (!connecting && stats.tot > 0 && Date.now() - lastAct > STALL_TO) {
        stalls += 1;
        if (stalls >= MAX_STALL) {
          if (reconns < MAX_RECONN) {
            stalls = 0;
            reconn();
          } else {
            cleanup();
            ws.close(1011);
          }
        }
      }
    }, STALL_TO / 2);
  };

  ws.addEventListener('message', async (event) => {
    try {
      const incoming = event.data instanceof ArrayBuffer ? new Uint8Array(event.data) : new Uint8Array(await new Response(event.data).arrayBuffer());
      if (first) {
        first = false;
        if (buildUUID(incoming, 1).toLowerCase() !== uid.toLowerCase()) throw new Error('Auth fail');
        const { host, port, payload, addressType } = extractAddr(incoming);
        info = { host, port, addressType };
        ws.send(new Uint8Array([incoming[0], 0]));
        connecting = true;
        if (payload.length) {
          const buf = pool.alloc(payload.length);
          buf.set(payload);
          pending.push(buf);
          pendingBytes += buf.length;
        }
        startTimers();
        establish();
      } else {
        lastAct = Date.now();
        if (connecting || !writer) {
          const buf = pool.alloc(incoming.byteLength);
          buf.set(incoming);
          pending.push(buf);
          pendingBytes += buf.length;
        } else {
          await writer.write(incoming);
        }
      }
    } catch {
      cleanup();
      ws.close(1006);
    }
  });
  ws.addEventListener('close', cleanup);
  ws.addEventListener('error', cleanup);
}

async function _getECH() {
  if (!ECH) return null;
  try {
    const parts = ECH_SNI.split('.');
    const qname = [];
    for (const part of parts) qname.push(part.length, ...textEncoder.encode(part));
    qname.push(0);
    const hdr = new Uint8Array([0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    const qtype = new Uint8Array([0x00, 0x41]);
    const qclass = new Uint8Array([0x00, 0x01]);
    const query = new Uint8Array([...hdr, ...qname, ...qtype, ...qclass]);
    const res = await fetch(ECH_DNS, {
      method: 'POST',
      headers: { 'content-type': 'application/dns-message', accept: 'application/dns-message' },
      body: query,
    });
    if (!res.ok) return null;
    const buf = new Uint8Array(await res.arrayBuffer());
    let offset = 12;
    const ancount = (buf[6] << 8) | buf[7];
    while (buf[offset] !== 0) {
      if ((buf[offset] & 0xc0) === 0xc0) {
        offset += 2;
        break;
      }
      offset += buf[offset] + 1;
    }
    if (buf[offset] === 0) offset += 1;
    offset += 4;
    for (let i = 0; i < ancount; i += 1) {
      if ((buf[offset] & 0xc0) === 0xc0) offset += 2;
      else {
        while (buf[offset] !== 0) offset += buf[offset] + 1;
        offset += 1;
      }
      const rtype = (buf[offset] << 8) | buf[offset + 1];
      offset += 8;
      const rdlen = (buf[offset] << 8) | buf[offset + 1];
      offset += 2;
      if (rtype === 65) {
        const rdataEnd = offset + rdlen;
        offset += 2;
        if (buf[offset] === 0) offset += 1;
        else if ((buf[offset] & 0xc0) === 0xc0) offset += 2;
        else {
          while (buf[offset] !== 0) offset += buf[offset] + 1;
          offset += 1;
        }
        while (offset < rdataEnd) {
          const key = (buf[offset] << 8) | buf[offset + 1];
          offset += 2;
          const vlen = (buf[offset] << 8) | buf[offset + 1];
          offset += 2;
          if (key === 5) {
            const echRaw = buf.slice(offset, offset + vlen);
            const b64 = btoa(String.fromCharCode(...echRaw));
            return `-----BEGIN ECH CONFIGS-----\n${b64}\n-----END ECH CONFIGS-----`;
          }
          offset += vlen;
        }
      } else {
        offset += rdlen;
      }
    }
    return null;
  } catch {
    return null;
  }
}

async function pSB(text) {
  if (!ECH) return text;
  try {
    const cfg = JSON.parse(text);
    const echPem = await _getECH();
    if (!echPem) return text;
    if (cfg.outbounds) {
      for (const node of cfg.outbounds) {
        if (node.tls) {
          node.tls.ech = { enabled: true, config: echPem };
          if (!node.tls.utls) node.tls.utls = {};
          node.tls.utls.enabled = true;
          node.tls.utls.fingerprint = FP;
        }
      }
    }
    return JSON.stringify(cfg);
  } catch {
    return text;
  }
}

function pCL(text, uuid) {
  if (!ECH) return text;
  try {
    const echLine = `ech-opts: {enable: true, query-server-name: ${ECH_SNI}}`;
    const nsEntry = `${ECH_SNI}: [https://1.1.1.1/dns-query, https://8.8.8.8/dns-query]`;
    const lines = text.split('\n');
    const out = [];
    let inProxies = false;
    for (let i = 0; i < lines.length; i += 1) {
      const line = lines[i];
      if (/^proxies:/.test(line)) {
        inProxies = true;
        out.push(line);
        continue;
      }
      if (inProxies && /^\S/.test(line) && !/^\s/.test(line)) inProxies = false;
      if (inProxies && line.match(/^\s*-\s*\{.*uuid.*\}/i)) {
        const index = line.lastIndexOf('}');
        if (index > 0) {
          out.push(`${line.slice(0, index)}, ${echLine}}`);
          continue;
        }
      }
      out.push(line);
      if (inProxies && /^\s+uuid:/i.test(line) && uuid && line.includes(uuid.slice(0, 8))) {
        const indent = (line.match(/^(\s+)/) || ['', '  '])[1];
        let j = i + 1;
        while (j < lines.length && /^\s+\S/.test(lines[j]) && !/^\s+-\s/.test(lines[j])) {
          out.push(lines[j]);
          j += 1;
          i += 1;
        }
        out.push(`${indent}${echLine}`);
      }
    }
    let result = out.join('\n');
    const policy = 'nameserver-policy';
    if (!result.includes(policy)) {
      if (result.includes('dns:')) {
        result = result.replace(/(dns:[\s\S]*?)(\n\S)/, `$1\n  ${policy}:\n    ${nsEntry}\n$2`);
      } else {
        result = `dns:\n  enable: true\n  enhanced-mode: fake-ip\n  nameserver:\n    - https://1.1.1.1/dns-query\n    - https://8.8.8.8/dns-query\n  ${policy}:\n    ${nsEntry}\n\n${result}`;
      }
    } else if (!result.includes(ECH_SNI)) {
      result = result.replace(new RegExp(`(${policy}:\\s*\\n)`), `$1    ${nsEntry}\n`);
    }
    return result;
  } catch {
    return text;
  }
}

async function getCustomIPs(env, dlsThreshold) {
  const allIPs = [];
  const threshold = Number(dlsThreshold) || 5000;
  const addText = envValue(env, 'ADD', '');
  if (addText) {
    addText.split('\n').forEach((line) => {
      const trimmed = line.trim();
      if (trimmed && !trimmed.startsWith('#')) allIPs.push(trimmed);
    });
  }
  const addApi = envValue(env, 'ADDAPI', '');
  if (addApi) {
    const urls = addApi.split('\n').map((item) => item.trim()).filter((item) => item.startsWith('http'));
    for (const url of urls) {
      try {
        const res = await fetch(url, { headers: { 'User-Agent': 'Mozilla/5.0' } });
        if (!res.ok) continue;
        const text = await res.text();
        text.split('\n').forEach((line) => {
          const trimmed = line.trim();
          if (trimmed && !trimmed.startsWith('#')) allIPs.push(trimmed);
        });
      } catch (_error) {
        void _error;
      }
    }
  }
  const addCsv = envValue(env, 'ADDCSV', '');
  if (addCsv) {
    const urls = addCsv.split('\n').map((item) => item.trim()).filter((item) => item.startsWith('http'));
    for (const url of urls) {
      try {
        const res = await fetch(url, { headers: { 'User-Agent': 'Mozilla/5.0' } });
        if (!res.ok) continue;
        const text = await res.text();
        text.split('\n').forEach((line) => {
          const trimmed = line.trim();
          if (!trimmed || trimmed.startsWith('#')) return;
          const cols = trimmed.split(',');
          if (cols.length >= 8) {
            const speed = Number(cols[7]);
            if (!Number.isNaN(speed) && speed < threshold) return;
          }
          const csvIp = cols[0]?.trim();
          const csvPort = cols[1]?.trim() || '';
          if (csvIp) allIPs.push(csvPort && csvPort !== '443' ? `${csvIp}:${csvPort}` : csvIp);
        });
      } catch (_error) {
        void _error;
      }
    }
  }
  return [...new Set(allIPs)];
}

function encodeBase64Utf8(value) {
  return btoa(unescape(encodeURIComponent(value)));
}

function buildProxyPath(proxyIP, sourceSub, uuid) {
  const segments = [];
  if (sourceSub) segments.push(`sub=${sourceSub}`);
  if (proxyIP) segments.push(`proxyip=${proxyIP}`);
  if (uuid) segments.push(`uuid=${uuid}`);
  return `/${segments.join('&') || ''}`.replace(/\/$/, '/') || '/';
}

function genNodes(host, uuid, proxyIP, customIPs, psName, sourceSub = '') {
  const echParam = ECH ? `&ech=${encodeURIComponent((ECH_SNI ? `${ECH_SNI}+` : '') + ECH_DNS)}` : '';
  const commonUrlPart = `?encryption=none&security=tls&sni=${host}&fp=${FP}&alpn=h3&type=ws&host=${host}${echParam}`;
  const suffix = psName ? ` ${psName}` : '';
  const result = [];
  if (!customIPs || customIPs.length === 0) {
    const path = buildProxyPath(proxyIP, sourceSub, uuid);
    const nodeName = `${psName || 'Worker'} - Default`;
    const defaultHost = formatHostForUrl(proxyIP || host);
    return `${P_V}://${uuid}@${defaultHost}:443${commonUrlPart}&path=${encodeURIComponent(path)}#${encodeURIComponent(nodeName)}`;
  }
  for (const ipInfo of customIPs) {
    let [addressPart, ...nameParts] = ipInfo.split('#');
    const uniqueName = nameParts.join('#').trim();
    addressPart = addressPart.trim();
    const [ip, port] = parseAddressPort(addressPart);
    const path = buildProxyPath(proxyIP, sourceSub, uuid);
    let nodeName = uniqueName || ip;
    if (psName) nodeName = `${nodeName}${suffix}`;
    result.push(`${P_V}://${uuid}@${formatHostForUrl(ip)}:${port}${commonUrlPart}&path=${encodeURIComponent(path)}#${encodeURIComponent(nodeName)}`);
  }
  return result.join('\n');
}

function extractSourceSub(value) {
  const match = (value || '').match(/(?:^|[?&\/])sub=([^&#/]+)/i);
  return match ? decodeURIComponent(match[1].trim()) : '';
}

function extractPathProxyIp(value) {
  const match = (value || '').match(/(?:^|[?&\/])proxyip=([^&#/]+)/i);
  return match ? decodeURIComponent(match[1].trim()) : '';
}

function sanitizeProxyIp(value) {
  if (!value) return '';
  const trimmed = value.trim().replace(/^\/+/, '');
  return trimmed.replace(/[?#].*$/, '');
}

function getProxyPathDetails(url, defaultProxyIp, defaultUUID) {
  const pathname = decodeURIComponent(url.pathname || '/');
  const proxyipFromQuery = sanitizeProxyIp(url.searchParams.get('proxyip') || '');
  const proxyipFromPath = sanitizeProxyIp((pathname.match(/(?:^|[\/&])proxyip=([^&#/]+)/i) || [])[1] || '');
  const sourceSub = extractSourceSub(pathname) || extractSourceSub(url.search || '');
  const uuidFromPath = (pathname.match(/(?:^|[\/&])uuid=([0-9a-fA-F-]{36})/i) || [])[1] || '';
  return {
    proxyIP: proxyipFromQuery || proxyipFromPath || defaultProxyIp,
    sourceSub,
    uuid: uuidFromPath || defaultUUID,
  };
}

function getDurableProxyBinding(env) {
  const candidates = ['PROXY_SESSIONS', 'PROXY_SESSION', 'DURABLE_PROXY', 'BACKEND_PROXY_DO'];
  for (const key of candidates) {
    const binding = env?.[key];
    if (binding && typeof binding.idFromName === 'function') return binding;
  }
  return null;
}

async function maybeProxyThroughDurableObject(request, env) {
  const binding = getDurableProxyBinding(env);
  if (!binding) return null;
  const upgrade = (request.headers.get('Upgrade') || '').toLowerCase();
  if (upgrade !== 'websocket') return null;
  const url = new URL(request.url);
  if (url.searchParams.get('direct') === '1') return null;
  const key = `${url.pathname}|${url.search}` || 'default';
  const id = binding.idFromName(key);
  const stub = binding.get(id);
  return stub.fetch(new Request(request));
}

async function buildRuntimeConfig(request, env) {
  const host = new URL(request.url).hostname;
  const uuid = env.KEY ? await getDynamicUUID(env.KEY, envValue(env, 'UUID_REFRESH', 86400)) : envValue(env, 'UUID', UUID);
  const proxyIpSource = envValue(env, 'PROXYIP', DEFAULT_PROXY_IP);
  const proxyIPs = splitCSV(proxyIpSource);
  const proxyIP = proxyIPs[Math.floor(Date.now() / 1000) % Math.max(proxyIPs.length, 1)] || proxyIpSource;
  const subDomains = splitCSV(envValue(env, 'SUB_DOMAIN', DEFAULT_SUB_DOMAIN)).map((item) => {
    let value = item;
    if (value.includes('://')) value = value.split('://')[1];
    if (value.includes('/')) value = value.split('/')[0];
    return value;
  }).filter(Boolean);
  const converters = splitCSV(envValue(env, 'SUBAPI', DEFAULT_CONVERTER)).map((item) => {
    let value = item.trim();
    if (value.endsWith('/')) value = value.slice(0, -1);
    if (!value.includes('://')) value = `https://${value}`;
    return value;
  }).filter(Boolean);
  const dls = envValue(env, 'DLS', DLS);
  const ps = envValue(env, 'PS', DEFAULT_PS);
  const subPassword = envValue(env, 'SUB_PASSWORD', SUB_PASSWORD);
  const subToken = envValue(env, 'SUB_TOKEN', SUB_TOKEN);
  ECH = envValue(env, 'ECH_ENABLED', ECH ? 'true' : 'false') === 'true';
  ECH_SNI = envValue(env, 'ECH_SNI', ECH_SNI);
  ECH_DNS = envValue(env, 'ECH_DNS', ECH_DNS);
  FP = ECH ? 'chrome' : 'randomized';
  return {
    host,
    uuid,
    proxyIP,
    subDomains: subDomains.length ? subDomains : [host],
    converters: converters.length ? converters : [DEFAULT_CONVERTER],
    dls,
    ps,
    subPassword,
    subToken,
    clashConfig: envValue(env, 'CLASH_CONFIG', CLASH_CONFIG),
    singboxV11: envValue(env, 'SINGBOX_CONFIG_V11', SINGBOX_CONFIG_V11),
    singboxV12: envValue(env, 'SINGBOX_CONFIG_V12', SINGBOX_CONFIG_V12),
  };
}

function shouldBlockUA(userAgent) {
  const ua = (userAgent || '').toLowerCase();
  return ua.includes('spider') || ua.includes('bot') || ua.includes('python') || ua.includes('scrapy') || ua.includes('curl') || ua.includes('wget');
}

async function buildDesireBase(config, allIPs, overrideProxyIp, sourceSub, runtimeUuid) {
  const baseIp = allIPs[0] || overrideProxyIp || config.proxyIP || config.host;
  const node = genNodes(config.host, runtimeUuid || config.uuid, overrideProxyIp, baseIp ? [baseIp] : [], config.ps, sourceSub);
  return (typeof node === 'string' ? node : String(node).split('\n')[0]).split('\n')[0];
}

async function handleQuickSubscription(request, env, config) {
  const url = new URL(request.url);
  const userAgent = (request.headers.get('User-Agent') || '').toLowerCase();
  const details = getProxyPathDetails(url, config.proxyIP, config.uuid);
  const requestProxyIp = details.proxyIP || config.proxyIP;
  const pathParam = buildProxyPath(requestProxyIp, details.sourceSub, details.uuid);

  if (userAgent.includes('sing-box') || userAgent.includes('singbox') || userAgent.includes('clash') || userAgent.includes('meta') || userAgent.includes('loon') || userAgent.includes('surge')) {
    const type = userAgent.includes('clash') || userAgent.includes('meta') ? 'clash' : 'singbox';
    const configList = type === 'clash' ? [config.clashConfig] : Array.from(new Set([config.singboxV11, config.singboxV12].filter(Boolean)));
    let lastRes = null;
    for (const converterUrl of config.converters) {
      const targetSubDomain = details.sourceSub || config.subDomains[0] || config.host;
      let subUrl;
      if (config.subToken) {
        const desireIPs = await getCustomIPs(env, config.dls);
        const desireBase = await buildDesireBase(config, desireIPs, requestProxyIp, details.sourceSub, details.uuid);
        subUrl = `https://${targetSubDomain}/sub?base=${encodeURIComponent(desireBase)}&token=${encodeURIComponent(config.subToken)}`;
      } else {
        subUrl = `https://${targetSubDomain}/sub?uuid=${details.uuid}&encryption=none&security=tls&sni=${config.host}&alpn=h3&fp=${FP}&allowInsecure=0&type=ws&host=${config.host}&path=${encodeURIComponent(pathParam)}` + (ECH ? `&ech=${encodeURIComponent((ECH_SNI ? `${ECH_SNI}+` : '') + ECH_DNS)}` : '');
      }
      for (const converterConfig of configList) {
        const subApi = `${converterUrl}/sub?target=${type}&url=${encodeURIComponent(subUrl)}&config=${encodeURIComponent(converterConfig)}&emoji=true&list=false&sort=false&fdn=false&scv=false`;
        try {
          const res = await fetch(subApi, { headers: { 'User-Agent': 'Mozilla/5.0' } });
          if (res.ok) {
            lastRes = res;
            break;
          }
        } catch (_error) {
          void _error;
        }
      }
      if (lastRes) break;
    }
    if (lastRes) {
      let body = await lastRes.text();
      if (ECH) body = type === 'singbox' ? await pSB(body) : pCL(body, details.uuid);
      return new Response(body, { status: 200, headers: lastRes.headers });
    }
  }

  try {
    for (const subDomain of details.sourceSub ? [details.sourceSub, ...config.subDomains.filter((item) => item !== details.sourceSub)] : config.subDomains) {
      if (config.host.toLowerCase() === subDomain.toLowerCase()) continue;
      let subUrl;
      if (config.subToken) {
        const desireIPs = await getCustomIPs(env, config.dls);
        const desireBase = await buildDesireBase(config, desireIPs, requestProxyIp, details.sourceSub, details.uuid);
        subUrl = `https://${subDomain}/sub?base=${encodeURIComponent(desireBase)}&token=${encodeURIComponent(config.subToken)}`;
      } else {
        subUrl = `https://${subDomain}/sub?uuid=${details.uuid}&encryption=none&security=tls&sni=${config.host}&alpn=h3&fp=${FP}&allowInsecure=0&type=ws&host=${config.host}&path=${encodeURIComponent(pathParam)}` + (ECH ? `&ech=${encodeURIComponent((ECH_SNI ? `${ECH_SNI}+` : '') + ECH_DNS)}` : '');
      }
      try {
        const res = await fetch(subUrl, { headers: { 'User-Agent': request.headers.get('User-Agent') || '' } });
        if (!res.ok) continue;
        let body = await res.text();
        try {
          const decoded = atob(body);
          const lines = decoded.split('\n').map((line) => {
            let current = line.trim();
            if (!current || !current.includes('://')) return current;
            if (ECH && !current.includes('&ech=')) {
              const echValue = encodeURIComponent((ECH_SNI ? `${ECH_SNI}+` : '') + ECH_DNS);
              const hashIndex = current.indexOf('#');
              current = hashIndex > 0 ? `${current.slice(0, hashIndex)}&ech=${echValue}${current.slice(hashIndex)}` : `${current}&ech=${echValue}`;
            }
            if (ECH && current.includes('fp=')) current = current.replace(/fp=[^&#]+/, `fp=${FP}`);
            if (config.ps) current = current.includes('#') ? `${current}${encodeURIComponent(` ${config.ps}`)}` : `${current}#${encodeURIComponent(config.ps)}`;
            return current;
          });
          body = btoa(lines.join('\n'));
        } catch (_error) {
          body = body;
        }
        return new Response(body, { status: 200, headers: res.headers });
      } catch (_error) {
        void _error;
      }
    }
  } catch (_error) {
    void _error;
  }

  const allIPs = await getCustomIPs(env, config.dls);
  const listText = genNodes(config.host, details.uuid, requestProxyIp, allIPs, config.ps, details.sourceSub);
  return new Response(encodeBase64Utf8(listText), {
    status: 200,
    headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}

async function handleSubRoute(request, env, config) {
  const url = new URL(request.url);
  const baseLink = url.searchParams.get('base');
  const details = getProxyPathDetails(url, config.proxyIP, config.uuid);

  if (baseLink) {
    const reqToken = url.searchParams.get('token');
    if (config.subToken && reqToken !== config.subToken) {
      const errNode = `${P_V}://00000000-0000-0000-0000-000000000000@127.0.0.1:80?encryption=none&security=none&type=tcp#${encodeURIComponent('❌ Token验证失败')}`;
      return new Response(btoa(errNode), { headers: { 'Content-Type': 'text/plain;charset=utf-8' } });
    }
    const source = url.searchParams.get('source');
    const extUrl = url.searchParams.get('ext_url');
    let allIPs = [];
    if (source === 'ext' && extUrl) {
      try {
        const extRes = await fetch(extUrl, { headers: { 'User-Agent': 'Mozilla/5.0' } });
        const extText = await extRes.text();
        allIPs = extText.split('\n').map((item) => item.trim()).filter((item) => item && !item.startsWith('#'));
      } catch {
        allIPs = [];
      }
    } else {
      allIPs = await getCustomIPs(env, config.dls);
    }
    const links = allIPs.map((ipInfo) => {
      let [addrPart, ...nameParts] = ipInfo.split('#');
      const nodeName = nameParts.join('#').trim();
      addrPart = addrPart.trim();
      const [ip, portValue] = parseAddressPort(addrPart);
      const port = String(portValue || 443);
      try {
        if (baseLink.startsWith(`${P_V}://`)) {
          const parsed = new URL(baseLink);
          const originalHost = parsed.hostname;
          const currentPath = buildProxyPath(details.proxyIP || config.proxyIP, details.sourceSub, details.uuid);
          parsed.hostname = stripIPv6Brackets(ip);
          parsed.port = port;
          parsed.hash = nodeName || ip;
          parsed.searchParams.set('path', currentPath);
          if (!parsed.searchParams.has('host')) parsed.searchParams.set('host', originalHost);
          if (!parsed.searchParams.has('sni')) parsed.searchParams.set('sni', originalHost);
          return parsed.toString();
        }
        if (baseLink.startsWith('vmess://')) {
          const b64 = baseLink.slice(8).replace(/-/g, '+').replace(/_/g, '/');
          const parsed = JSON.parse(decodeURIComponent(escape(atob(b64))));
          const currentPath = buildProxyPath(details.proxyIP || config.proxyIP, details.sourceSub, details.uuid);
          if (!parsed.sni) parsed.sni = parsed.add;
          if (!parsed.host) parsed.host = parsed.add;
          parsed.add = ip;
          parsed.port = port;
          parsed.ps = nodeName || ip;
          parsed.path = currentPath;
          return `vmess://${btoa(unescape(encodeURIComponent(JSON.stringify(parsed))))}`;
        }
      } catch {
        return null;
      }
      return null;
    }).filter(Boolean);
    const output = links.length
      ? links.join('\n')
      : `${P_V}://00000000-0000-0000-0000-000000000000@127.0.0.1:80?encryption=none&security=none&type=tcp#${encodeURIComponent('❌ 无可用优选IP')}`;
    return new Response(encodeBase64Utf8(output), { headers: { 'Content-Type': 'text/plain;charset=utf-8' } });
  }

  const requestUUID = url.searchParams.get('uuid');
  if (!requestUUID || requestUUID.toLowerCase() !== config.uuid.toLowerCase()) {
    return new Response('Invalid UUID', { status: 403 });
  }
  let proxyIp = url.searchParams.get('proxyip') || details.proxyIP || config.proxyIP;
  const pathParam = url.searchParams.get('path');
  const pathProxyIp = extractPathProxyIp(pathParam || '');
  if (pathProxyIp) proxyIp = pathProxyIp;
  const allIPs = await getCustomIPs(env, config.dls);
  const listText = genNodes(config.host, details.uuid, proxyIp, allIPs, config.ps, details.sourceSub);
  return new Response(encodeBase64Utf8(listText), {
    status: 200,
    headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}

async function proxyWebSocket(request, env, config) {
  const viaDo = await maybeProxyThroughDurableObject(request, env);
  if (viaDo) return viaDo;
  const url = new URL(request.url);
  const runtimeDetails = getProxyPathDetails(url, config.proxyIP, config.uuid);
  const parsedPath = parsePC(url.pathname);
  const proxyIP = parsedPath.proxyIP || (runtimeDetails.proxyIP ? (() => {
    const [address, port = 443] = parseAddressPort(runtimeDetails.proxyIP);
    return { address: stripIPv6Brackets(address), port: Number(port) };
  })() : null);
  const { 0: client, 1: server } = new WebSocketPair();
  server.accept();
  server.binaryType = 'arraybuffer';
  handle(server, proxyIP, parsedPath.sq, parsedPath.enSq, parsedPath.gp, runtimeDetails.uuid || config.uuid);
  return new Response(null, { status: 101, webSocket: client });
}

async function fetchHandler(request, env) {
  const url = new URL(request.url);
  if (url.pathname === '/favicon.ico') return new Response(null, { status: 404 });
  if (shouldBlockUA(request.headers.get('User-Agent'))) return new Response('Not Found', { status: 404 });
  const config = await buildRuntimeConfig(request, env);

   if (url.pathname === '/' && url.searchParams.get('sub')) {
    const subValue = url.searchParams.get('sub') || '';
    const proxyValue = url.searchParams.get('proxyip') || '';
    const uuidValue = url.searchParams.get('uuid') || config.uuid;
    const pathValue = buildProxyPath(proxyValue || config.proxyIP, subValue, uuidValue);
    const routed = new URL(url.toString());
    routed.pathname = '/sub';
    routed.searchParams.set('uuid', uuidValue);
    if (proxyValue) routed.searchParams.set('proxyip', proxyValue);
    routed.searchParams.set('path', pathValue);
    return handleSubRoute(new Request(routed.toString(), request), env, config);
  }

  if (config.subPassword && url.pathname === `/${config.subPassword}`) {
    return handleQuickSubscription(request, env, config);
  }

  if (url.pathname === '/sub') {
    return handleSubRoute(request, env, config);
  }

  if ((request.headers.get('Upgrade') || '').toLowerCase() === 'websocket') {
    return proxyWebSocket(request, env, config);
  }

  return new Response('Backend proxy worker is running.', {
    status: 200,
    headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}

export class ProxySessionDO {
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request) {
    const url = new URL(request.url);
    url.searchParams.set('direct', '1');
    return fetchHandler(new Request(url.toString(), request), this.env);
  }
}

export default {
  async fetch(request, env) {
    try {
      return await fetchHandler(request, env);
    } catch {
      return new Response('Internal Server Error', { status: 500 });
    }
  },
};

// MeshLink Electron — ECC + AES-256-GCM
const { app, BrowserWindow, ipcMain, Notification, Tray, Menu, nativeImage } = require('electron');
const path   = require('path');
const fs     = require('fs');
const os     = require('os');
const crypto = require('crypto');
const http   = require('http');
const WebSocket = require('ws');

let noble = null;
try { noble = require('@abandonware/noble'); } catch(e) {}

const MESH_SERVICE_UUID = 'fe2c';
const MESH_CHAR_TX_UUID = 'fe2d';
const MESH_CHAR_RX_UUID = 'fe2e';
const MESH_NAME_PREFIX  = 'ML-';
const WS_PORT           = 9731;

let mainWin = null, tray = null, wsServer = null;
let wsClients = new Map(), bleChars = new Map();
let peers = new Map(), scfQueue = new Map();
let myId = '', myName = '', scanning = false;

// ECC
let myECDH = null, myPublicKeyB64 = '';
const peerKeys = new Map();

function initECC() {
  myECDH = crypto.createECDH('prime256v1');
  myECDH.generateKeys();
  myPublicKeyB64 = myECDH.getPublicKey('base64');
}

function deriveSharedKey(pubB64) {
  try {
    const secret = myECDH.computeSecret(Buffer.from(pubB64, 'base64'));
    return crypto.createHash('sha256').update(secret).digest();
  } catch(e) { return null; }
}

function onKeyExchange(peerId, pubKey) {
  if (!pubKey || peerKeys.has(peerId)) return;
  const key = deriveSharedKey(pubKey);
  if (key) peerKeys.set(peerId, key);
}

// Shared broadcast key — same on all devices (Android + PC)
const BROADCAST_KEY = crypto.pbkdf2Sync('meshlink-ble-v3', 'ml3s', 50000, 32, 'sha256');

function encryptMsg(text, peerId) {
  const key = (peerId && peerKeys.get(peerId)) || BROADCAST_KEY;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  return { c: Buffer.concat([ct, cipher.getAuthTag()]).toString('base64'), i: iv.toString('base64') };
}

function decryptMsg(payload, peerId) {
  if (!payload) return '[no payload]';
  if (payload.r === 1 || !payload.i) {
    try { return Buffer.from(payload.c, 'base64').toString('utf8'); } catch(e) { return '[?]'; }
  }
  const keys = [];
  if (peerId && peerKeys.has(peerId)) keys.push(peerKeys.get(peerId));
  keys.push(BROADCAST_KEY);
  for (const key of keys) {
    try {
      const iv = Buffer.from(payload.i, 'base64');
      const data = Buffer.from(payload.c, 'base64');
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
      decipher.setAuthTag(data.slice(data.length - 16));
      return decipher.update(data.slice(0, data.length - 16)) + decipher.final('utf8');
    } catch(e) {}
  }
  return '[decryption failed]';
}

function makeHello() {
  return JSON.stringify({ type: 'hello', id: myId, name: myName, publicKey: myPublicKeyB64 });
}

function loadIdentity() {
  const p = path.join(app.getPath('userData'), 'identity.json');
  try { if (fs.existsSync(p)) return JSON.parse(fs.readFileSync(p, 'utf8')); } catch(e) {}
  return null;
}
function saveIdentity(id, name) {
  fs.writeFileSync(path.join(app.getPath('userData'), 'identity.json'), JSON.stringify({ id, name }));
}
function genId() { return crypto.randomBytes(4).toString('hex').toUpperCase(); }

function startWSServer() {
  const server = http.createServer();
  wsServer = new WebSocket.Server({ server });
  wsServer.on('connection', (ws) => {
    let peerId = null;
    ws.on('message', (data) => {
      try {
        const pkt = JSON.parse(data.toString());
        if (pkt.type === 'hello') {
          peerId = pkt.id;
          wsClients.set(peerId, ws);
          addOrUpdatePeer(pkt.id, pkt.name, -60, true, 'lan');
          if (pkt.publicKey) onKeyExchange(peerId, pkt.publicKey);
          ws.send(makeHello());
          deliverSCF(peerId);
          mainWin?.webContents.send('peer-online', getPeer(peerId));
        } else { handleIncomingPacket(pkt, peerId); }
      } catch(e) {}
    });
    ws.on('close', () => {
      if (peerId) {
        wsClients.delete(peerId);
        const p = peers.get(peerId);
        if (p) { p.online = false; peers.set(peerId, p); }
        mainWin?.webContents.send('peer-offline', peerId);
      }
    });
    ws.send(makeHello());
  });
  server.listen(WS_PORT, '0.0.0.0', () => {});
  server.on('error', () => {});
}

function scanLAN() {
  const interfaces = os.networkInterfaces();
  const ips = [];
  Object.values(interfaces).forEach(iface => {
    iface.forEach(addr => {
      if (addr.family === 'IPv4' && !addr.internal) {
        const subnet = addr.address.split('.').slice(0, 3).join('.');
        for (let i = 1; i <= 254; i++) { const ip = `${subnet}.${i}`; if (ip !== addr.address) ips.push(ip); }
      }
    });
  });
  ips.forEach(ip => {
    const ws = new WebSocket(`ws://${ip}:${WS_PORT}`, { timeout: 800 });
    ws.on('open', () => ws.send(makeHello()));
    ws.on('message', (data) => {
      try {
        const pkt = JSON.parse(data.toString());
        if (pkt.type === 'hello' && pkt.id !== myId) {
          const peerId = pkt.id;
          wsClients.set(peerId, ws);
          addOrUpdatePeer(peerId, pkt.name, -55, true, 'lan');
          if (pkt.publicKey) onKeyExchange(peerId, pkt.publicKey);
          deliverSCF(peerId);
          mainWin?.webContents.send('peer-online', getPeer(peerId));
          ws.on('message', (d2) => { try { handleIncomingPacket(JSON.parse(d2.toString()), peerId); } catch(e) {} });
          ws.on('close', () => {
            wsClients.delete(peerId);
            const p = peers.get(peerId);
            if (p) { p.online = false; peers.set(peerId, p); }
            mainWin?.webContents.send('peer-offline', peerId);
          });
        }
      } catch(e) {}
    });
    ws.on('error', () => {});
  });
}

function startBluetooth() {
  if (!noble) { mainWin?.webContents.send('bt-status', { available: false }); return; }
  noble.on('stateChange', (state) => {
    mainWin?.webContents.send('bt-status', { available: state === 'poweredOn', state });
    if (state === 'poweredOn' && scanning) noble.startScanning([MESH_SERVICE_UUID], true);
  });
  noble.on('discover', (peripheral) => {
    const name = peripheral.advertisement?.localName || '';
    if (!name.startsWith(MESH_NAME_PREFIX)) return;
    const peerId = peripheral.id;
    const peerName = name.replace(MESH_NAME_PREFIX, '');
    addOrUpdatePeer(peerId, peerName, peripheral.rssi || -70, true, 'ble');
    mainWin?.webContents.send('peer-online', getPeer(peerId));
    connectBLEPeer(peripheral, peerId, peerName);
  });
}

function connectBLEPeer(peripheral, peerId, peerName) {
  peripheral.connect((err) => {
    if (err) return;
    addOrUpdatePeer(peerId, peerName, peripheral.rssi || -70, true, 'ble');
    mainWin?.webContents.send('peer-online', getPeer(peerId));
    peripheral.discoverSomeServicesAndCharacteristics(
      [MESH_SERVICE_UUID], [MESH_CHAR_TX_UUID, MESH_CHAR_RX_UUID],
      (err, services, chars) => {
        if (err || !chars || !chars.length) return;
        const txChar = chars.find(c => c.uuid === MESH_CHAR_TX_UUID);
        const rxChar = chars.find(c => c.uuid === MESH_CHAR_RX_UUID);
        if (txChar) { bleChars.set(peerId, txChar); txChar.write(Buffer.from(makeHello()), true, () => {}); deliverSCF(peerId); }
        if (rxChar) {
          rxChar.subscribe(() => {});
          rxChar.on('data', (data) => {
            try {
              const msg = JSON.parse(data.toString());
              if (msg.type === 'hello') {
                if (msg.publicKey) onKeyExchange(peerId, msg.publicKey);
                addOrUpdatePeer(peerId, msg.name || peerName, peripheral.rssi || -70, true, 'ble');
                mainWin?.webContents.send('peer-online', getPeer(peerId));
              } else { handleIncomingPacket(msg, peerId); }
            } catch(e) {}
          });
        }
      }
    );
    peripheral.on('disconnect', () => {
      const p = peers.get(peerId);
      if (p) { p.online = false; peers.set(peerId, p); }
      bleChars.delete(peerId);
      mainWin?.webContents.send('peer-offline', peerId);
    });
  });
}

function handleIncomingPacket(pkt, fromId) {
  if (!pkt || !pkt.type) return;
  if (pkt.type === 'hello') {
    if (pkt.publicKey) onKeyExchange(fromId, pkt.publicKey);
    addOrUpdatePeer(fromId, pkt.name, -60, true, 'ble');
    mainWin?.webContents.send('peer-online', getPeer(fromId));
    return;
  }
  if (pkt.type === 'chat') {
    const isBcast = pkt.ch === 'broadcast';
    const text = isBcast ? decryptMsg(pkt.payload, null) : decryptMsg(pkt.payload, fromId);
    mainWin?.webContents.send('message-in', { ...pkt, plaintext: text });
    if (mainWin && !mainWin.isFocused()) {
      new Notification({ title: `💬 ${pkt.name}`, body: text.slice(0, 80), icon: path.join(__dirname, 'icon.png') }).show();
    }
    if ((pkt.hops || 0) < (pkt.maxHops || 5)) broadcastToAll({ ...pkt, hops: (pkt.hops || 0) + 1 }, fromId);
  }
  if (pkt.type === 'location') mainWin?.webContents.send('location-in', pkt);
}

function sendToePeer(peerId, pkt) {
  const data = JSON.stringify(pkt);
  const txChar = bleChars.get(peerId);
  if (txChar) { try { txChar.write(Buffer.from(data), true, () => {}); return true; } catch(e) {} }
  const ws = wsClients.get(peerId);
  if (ws && ws.readyState === WebSocket.OPEN) { try { ws.send(data); return true; } catch(e) {} }
  return false;
}

function broadcastToAll(pkt, exceptId) {
  const data = JSON.stringify(pkt);
  bleChars.forEach((txChar, id) => { if (id !== exceptId) { try { txChar.write(Buffer.from(data), true, () => {}); } catch(e) {} } });
  wsClients.forEach((ws, id) => { if (id !== exceptId && ws.readyState === WebSocket.OPEN) { try { ws.send(data); } catch(e) {} } });
}

function queueSCF(peerId, pkt) {
  if (!scfQueue.has(peerId)) scfQueue.set(peerId, []);
  const q = scfQueue.get(peerId); q.push(pkt); if (q.length > 100) q.shift();
}
function deliverSCF(peerId) {
  const q = scfQueue.get(peerId) || []; q.forEach(p => sendToePeer(peerId, p)); scfQueue.set(peerId, []);
}

function addOrUpdatePeer(id, name, rssi, online, transport) {
  const ex = peers.get(id) || {};
  peers.set(id, { id, name: name || ex.name || `Node-${id.slice(0,4)}`, rssi: rssi || ex.rssi || -60, online, transport, lastSeen: Date.now(), msgCount: ex.msgCount || 0, lastMsg: ex.lastMsg || '' });
}
function getPeer(id) { return peers.get(id); }

ipcMain.handle('get-identity', () => ({ id: myId, name: myName, publicKey: myPublicKeyB64 }));
ipcMain.handle('get-peers', () => Array.from(peers.values()));

ipcMain.handle('send-message', async (e, { peerId, text, channel }) => {
  const isBcast = channel === 'broadcast' || !peerId;
  const payload = encryptMsg(text, isBcast ? null : peerId);
  const pkt = { type: 'chat', id: myId, name: myName, ch: isBcast ? 'broadcast' : peerId, payload, t: Date.now(), mid: crypto.randomBytes(4).toString('hex'), hops: 0, maxHops: 5 };
  if (isBcast) broadcastToAll(pkt); else if (!sendToePeer(peerId, pkt)) queueSCF(peerId, pkt);
  return pkt;
});

ipcMain.handle('start-scan', async () => {
  scanning = true; mainWin?.webContents.send('scan-started'); scanLAN();
  if (noble && noble.state === 'poweredOn') { noble.startScanning([MESH_SERVICE_UUID], true); setTimeout(() => { if (noble) noble.stopScanning(); }, 15000); }
  return { ok: true };
});
ipcMain.handle('stop-scan', () => { scanning = false; if (noble) { try { noble.stopScanning(); } catch(e) {} } return { ok: true }; });
ipcMain.handle('set-identity', async (e, { id, name }) => { myId = id; myName = name; saveIdentity(id, name); return { ok: true }; });
ipcMain.handle('broadcast-location', async (e, { lat, lng }) => { broadcastToAll({ type: 'location', id: myId, name: myName, lat, lng, t: Date.now() }); return { ok: true }; });

function createWindow() {
  mainWin = new BrowserWindow({ width: 420, height: 820, minWidth: 360, minHeight: 600, backgroundColor: '#070d1a', webPreferences: { nodeIntegration: false, contextIsolation: true, preload: path.join(__dirname, 'preload.js') }, icon: path.join(__dirname, 'icon.png'), title: 'MeshLink' });
  mainWin.loadFile(path.join(__dirname, 'renderer', 'index.html'));
  mainWin.on('close', () => app.exit(0));
}

function createTray() {
  const iconPath = path.join(__dirname, 'icon.png');
  if (!fs.existsSync(iconPath)) return;
  tray = new Tray(nativeImage.createFromPath(iconPath).resize({ width: 16 }));
  tray.setToolTip('MeshLink');
  tray.setContextMenu(Menu.buildFromTemplate([{ label: 'Open MeshLink', click: () => mainWin?.show() }, { type: 'separator' }, { label: 'Quit', click: () => app.exit(0) }]));
  tray.on('click', () => mainWin?.show());
}

app.whenReady().then(() => {
  initECC();
  const saved = loadIdentity();
  if (saved) { myId = saved.id; myName = saved.name; } else { myId = genId(); }
  startWSServer(); startBluetooth(); createWindow(); createTray();
  setTimeout(scanLAN, 2000);
});
app.on('window-all-closed', () => {});
app.on('activate', () => mainWin?.show());
app.on('before-quit', () => { if (noble) { try { noble.stopScanning(); } catch(e) {} } wsServer?.close(); });

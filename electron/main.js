// ═══════════════════════════════════════════════════
//  MeshLink Electron — Real Bluetooth Discovery
//  PC Desktop App — Windows / Mac / Linux
// ═══════════════════════════════════════════════════
const { app, BrowserWindow, ipcMain, Notification, Tray, Menu, nativeImage } = require('electron');
const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const http = require('http');
const WebSocket = require('ws');

let noble = null;
try { noble = require('@abandonware/noble'); } catch(e) {
  console.log('noble not available');
}

const MESH_SERVICE_UUID = 'fe2c';
const MESH_CHAR_TX_UUID = 'fe2d';
const MESH_CHAR_RX_UUID = 'fe2e';
const MESH_NAME_PREFIX  = 'ML-';
const WS_PORT           = 9731;

let mainWin = null;
let tray = null;
let wsServer = null;
let wsClients = new Map();
let bleChars  = new Map();
let peers     = new Map();
let myId = '';
let myName = '';
let scanning = false;
let scfQueue = new Map();

// ── Identity ──────────────────────────────────────────
function loadIdentity() {
  const p = path.join(app.getPath('userData'), 'identity.json');
  try { if (fs.existsSync(p)) return JSON.parse(fs.readFileSync(p, 'utf8')); } catch(e) {}
  return null;
}
function saveIdentity(id, name) {
  fs.writeFileSync(path.join(app.getPath('userData'), 'identity.json'), JSON.stringify({ id, name }));
}
function genId() { return crypto.randomBytes(4).toString('hex').toUpperCase(); }

// ── Encryption AES-256-GCM ────────────────────────────
const MESH_KEY = crypto.scryptSync('meshlink-ble-v3', 'ml3s', 32);

function encrypt(text) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', MESH_KEY, iv);
  const ct = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  return { c: Buffer.concat([ct, cipher.getAuthTag()]).toString('base64'), i: iv.toString('base64') };
}

function decrypt(payload) {
  try {
    const iv   = Buffer.from(payload.i, 'base64');
    const data = Buffer.from(payload.c, 'base64');
    const decipher = crypto.createDecipheriv('aes-256-gcm', MESH_KEY, iv);
    decipher.setAuthTag(data.slice(data.length - 16));
    return decipher.update(data.slice(0, data.length - 16)) + decipher.final('utf8');
  } catch(e) { return '[encrypted]'; }
}

// ── WebSocket Server (LAN) ────────────────────────────
function startWSServer() {
  const server = http.createServer();
  wsServer = new WebSocket.Server({ server });
  wsServer.on('connection', (ws, req) => {
    let peerId = null;
    ws.on('message', (data) => {
      try {
        const pkt = JSON.parse(data.toString());
        if (pkt.type === 'hello') {
          peerId = pkt.id;
          wsClients.set(peerId, ws);
          addOrUpdatePeer(pkt.id, pkt.name, -60, true, 'lan');
          ws.send(JSON.stringify({ type: 'hello', id: myId, name: myName }));
          deliverSCF(peerId);
          mainWin?.webContents.send('peer-online', getPeer(peerId));
        } else {
          handleIncomingPacket(pkt, peerId);
        }
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
    ws.send(JSON.stringify({ type: 'hello', id: myId, name: myName }));
  });
  server.listen(WS_PORT, '0.0.0.0', () => console.log(`WS server on port ${WS_PORT}`));
  server.on('error', (e) => console.log('WS error:', e.message));
}

// ── LAN Scan ──────────────────────────────────────────
function scanLAN() {
  const interfaces = os.networkInterfaces();
  const ips = [];
  Object.values(interfaces).forEach(iface => {
    iface.forEach(addr => {
      if (addr.family === 'IPv4' && !addr.internal) {
        const subnet = addr.address.split('.').slice(0, 3).join('.');
        for (let i = 1; i <= 254; i++) {
          const ip = `${subnet}.${i}`;
          if (ip !== addr.address) ips.push(ip);
        }
      }
    });
  });
  ips.forEach(ip => {
    const ws = new WebSocket(`ws://${ip}:${WS_PORT}`, { timeout: 800 });
    ws.on('open', () => ws.send(JSON.stringify({ type: 'hello', id: myId, name: myName })));
    ws.on('message', (data) => {
      try {
        const pkt = JSON.parse(data.toString());
        if (pkt.type === 'hello' && pkt.id !== myId) {
          const peerId = pkt.id;
          wsClients.set(peerId, ws);
          addOrUpdatePeer(peerId, pkt.name, -55, true, 'lan');
          deliverSCF(peerId);
          mainWin?.webContents.send('peer-online', getPeer(peerId));
          ws.on('message', (d2) => {
            try { handleIncomingPacket(JSON.parse(d2.toString()), peerId); } catch(e) {}
          });
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

// ── Bluetooth ─────────────────────────────────────────
function startBluetooth() {
  if (!noble) {
    mainWin?.webContents.send('bt-status', { available: false });
    return;
  }
  noble.on('stateChange', (state) => {
    mainWin?.webContents.send('bt-status', { available: state === 'poweredOn', state });
    if (state === 'poweredOn' && scanning) noble.startScanning([MESH_SERVICE_UUID], true);
  });
  noble.on('discover', (peripheral) => {
    const name = peripheral.advertisement?.localName || '';
    if (!name.startsWith(MESH_NAME_PREFIX)) return;
    const peerId   = peripheral.id;
    const peerName = name.replace(MESH_NAME_PREFIX, '');
    const rssi     = peripheral.rssi || -70;
    console.log(`BT found: ${name} (${rssi} dBm)`);
    // Mark ONLINE immediately — device is right here
    addOrUpdatePeer(peerId, peerName, rssi, true, 'ble');
    mainWin?.webContents.send('peer-online', getPeer(peerId));
    connectBLEPeer(peripheral, peerId, peerName);
  });
}

function connectBLEPeer(peripheral, peerId, peerName) {
  peripheral.connect((err) => {
    if (err) {
      console.log('BLE connect error:', err);
      return;
    }
    addOrUpdatePeer(peerId, peerName, peripheral.rssi || -70, true, 'ble');
    mainWin?.webContents.send('peer-online', getPeer(peerId));

    peripheral.discoverSomeServicesAndCharacteristics(
      [MESH_SERVICE_UUID], [MESH_CHAR_TX_UUID, MESH_CHAR_RX_UUID],
      (err, services, chars) => {
        if (err || !chars || !chars.length) return;
        const txChar = chars.find(c => c.uuid === MESH_CHAR_TX_UUID);
        const rxChar = chars.find(c => c.uuid === MESH_CHAR_RX_UUID);

        if (txChar) {
          bleChars.set(peerId, txChar);
          txChar.write(Buffer.from(JSON.stringify({ type: 'hello', id: myId, name: myName })), true, () => {});
          deliverSCF(peerId);
        }
        if (rxChar) {
          rxChar.subscribe(() => {});
          rxChar.on('data', (data) => {
            try {
              const msg = JSON.parse(data.toString());
              if (msg.type === 'hello') {
                addOrUpdatePeer(peerId, msg.name || peerName, peripheral.rssi || -70, true, 'ble');
                mainWin?.webContents.send('peer-online', getPeer(peerId));
              } else {
                handleIncomingPacket(msg, peerId);
              }
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

function getLocalIP() {
  for (const iface of Object.values(os.networkInterfaces())) {
    for (const addr of iface) {
      if (addr.family === 'IPv4' && !addr.internal) return addr.address;
    }
  }
  return '127.0.0.1';
}

// ── Message Handling ──────────────────────────────────
function handleIncomingPacket(pkt, fromId) {
  if (!pkt || !pkt.type) return;
  if (pkt.type === 'chat') {
    const text = decrypt(pkt.payload || { c: '', i: '' });
    mainWin?.webContents.send('message-in', { ...pkt, plaintext: text });
    if (mainWin && !mainWin.isFocused()) {
      new Notification({ title: `💬 ${pkt.name}`, body: text.slice(0, 80), icon: path.join(__dirname, 'icon.png') }).show();
    }
    // Relay
    if (pkt.hops < (pkt.maxHops || 5)) {
      const relayed = { ...pkt, hops: (pkt.hops || 0) + 1 };
      broadcastToAll(relayed, fromId);
    }
  }
  if (pkt.type === 'location') mainWin?.webContents.send('location-in', pkt);
}

// ── Send ──────────────────────────────────────────────
function sendToePeer(peerId, pkt) {
  const data = JSON.stringify(pkt);
  const txChar = bleChars.get(peerId);
  if (txChar) {
    try { txChar.write(Buffer.from(data), true, () => {}); return true; } catch(e) {}
  }
  const ws = wsClients.get(peerId);
  if (ws && ws.readyState === WebSocket.OPEN) {
    try { ws.send(data); return true; } catch(e) {}
  }
  return false;
}

function broadcastToAll(pkt, exceptId) {
  const data = JSON.stringify(pkt);
  bleChars.forEach((txChar, id) => {
    if (id !== exceptId) { try { txChar.write(Buffer.from(data), true, () => {}); } catch(e) {} }
  });
  wsClients.forEach((ws, id) => {
    if (id !== exceptId && ws.readyState === WebSocket.OPEN) {
      try { ws.send(data); } catch(e) {}
    }
  });
}

// ── SCF ───────────────────────────────────────────────
function queueSCF(peerId, pkt) {
  if (!scfQueue.has(peerId)) scfQueue.set(peerId, []);
  const q = scfQueue.get(peerId);
  q.push(pkt);
  if (q.length > 100) q.shift();
}
function deliverSCF(peerId) {
  const q = scfQueue.get(peerId) || [];
  q.forEach(p => sendToePeer(peerId, p));
  scfQueue.set(peerId, []);
}

// ── Peers ─────────────────────────────────────────────
function addOrUpdatePeer(id, name, rssi, online, transport) {
  const ex = peers.get(id) || {};
  peers.set(id, {
    id, name: name || ex.name || `Node-${id.slice(0,4)}`,
    rssi: rssi || ex.rssi || -60,
    online, transport, lastSeen: Date.now(),
    msgCount: ex.msgCount || 0, lastMsg: ex.lastMsg || ''
  });
}
function getPeer(id) { return peers.get(id); }

// ── IPC ───────────────────────────────────────────────
ipcMain.handle('get-identity', () => ({ id: myId, name: myName }));
ipcMain.handle('get-peers', () => Array.from(peers.values()));

ipcMain.handle('send-message', async (e, { peerId, text, channel }) => {
  const payload = encrypt(text);
  const pkt = {
    type: 'chat', id: myId, name: myName,
    ch: channel || peerId || 'broadcast',
    payload, t: Date.now(),
    mid: crypto.randomBytes(4).toString('hex'),
    hops: 0, maxHops: 5
  };
  if (channel === 'broadcast' || !peerId) broadcastToAll(pkt);
  else if (!sendToePeer(peerId, pkt)) queueSCF(peerId, pkt);
  return pkt;
});

ipcMain.handle('start-scan', async () => {
  scanning = true;
  mainWin?.webContents.send('scan-started');
  scanLAN();
  if (noble && noble.state === 'poweredOn') {
    noble.startScanning([MESH_SERVICE_UUID], true);
    setTimeout(() => { if (noble) noble.stopScanning(); }, 15000);
  }
  return { ok: true };
});

ipcMain.handle('stop-scan', () => {
  scanning = false;
  if (noble) { try { noble.stopScanning(); } catch(e) {} }
  return { ok: true };
});

ipcMain.handle('set-identity', async (e, { id, name }) => {
  myId = id; myName = name;
  saveIdentity(id, name);
  return { ok: true };
});

ipcMain.handle('broadcast-location', async (e, { lat, lng }) => {
  broadcastToAll({ type: 'location', id: myId, name: myName, lat, lng, t: Date.now() });
  return { ok: true };
});

// ── Window ────────────────────────────────────────────
function createWindow() {
  mainWin = new BrowserWindow({
    width: 420, height: 820, minWidth: 360, minHeight: 600,
    backgroundColor: '#070d1a',
    webPreferences: {
      nodeIntegration: false, contextIsolation: true,
      preload: path.join(__dirname, 'preload.js')
    },
    icon: path.join(__dirname, 'icon.png'),
    title: 'MeshLink'
  });
  mainWin.loadFile(path.join(__dirname, 'renderer', 'index.html'));
  mainWin.on('close', () => app.exit(0));
}

function createTray() {
  const iconPath = path.join(__dirname, 'icon.png');
  if (!fs.existsSync(iconPath)) return;
  tray = new Tray(nativeImage.createFromPath(iconPath).resize({ width: 16 }));
  tray.setToolTip('MeshLink');
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: 'Open MeshLink', click: () => mainWin?.show() },
    { type: 'separator' },
    { label: 'Quit', click: () => app.exit(0) }
  ]));
  tray.on('click', () => mainWin?.show());
}

// ── Boot ──────────────────────────────────────────────
app.whenReady().then(() => {
  const saved = loadIdentity();
  if (saved) { myId = saved.id; myName = saved.name; }
  else { myId = genId(); }
  startWSServer();
  startBluetooth();
  createWindow();
  createTray();
  setTimeout(scanLAN, 2000);
});

app.on('window-all-closed', () => {});
app.on('activate', () => mainWin?.show());
app.on('before-quit', () => {
  if (noble) { try { noble.stopScanning(); } catch(e) {} }
  wsServer?.close();
});

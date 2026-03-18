package com.meshlink.app;

import android.Manifest;
import android.bluetooth.*;
import android.bluetooth.le.*;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.location.Location;
import android.location.LocationManager;
import android.os.*;
import android.webkit.*;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import org.json.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;
import android.util.Base64;
import android.util.Log;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "MeshLink";
    private static final String MESH_SERVICE_UUID = "0000fe2c-0000-1000-8000-00805f9b34fb";
    private static final String MESH_CHAR_TX_UUID  = "0000fe2d-0000-1000-8000-00805f9b34fb";
    private static final String MESH_CHAR_RX_UUID  = "0000fe2e-0000-1000-8000-00805f9b34fb";
    private static final String PREFS_NAME = "MeshLinkPrefs";
    private static final int PERM_REQUEST = 1001;

    private WebView webView;
    private BluetoothAdapter btAdapter;
    private BluetoothLeScanner bleScanner;
    private BluetoothLeAdvertiser bleAdvertiser;
    private BluetoothGattServer gattServer;
    private boolean scanning = false;
    private String myId = "";
    private String myName = "";
    private SecretKey aesKey;

    private final Map<String, BluetoothGatt> connectedGatts = new ConcurrentHashMap<>();
    private final Map<String, BluetoothGattCharacteristic> txChars = new ConcurrentHashMap<>();
    private final Map<String, String> peerNames = new ConcurrentHashMap<>();
    private final Set<BluetoothDevice> serverClients = Collections.synchronizedSet(new HashSet<>());

    // ── Lifecycle ──────────────────────────────────────
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        myId   = prefs.getString("nodeId", "");
        myName = prefs.getString("nodeName", "");

        try { initCrypto(); } catch (Exception e) { Log.e(TAG, "Crypto init failed", e); }

        setupWebView();
        requestAllPermissions();
    }

    // ── WebView Setup ──────────────────────────────────
    @SuppressWarnings("SetJavaScriptEnabled")
    private void setupWebView() {
        webView = findViewById(R.id.webView);
        WebSettings ws = webView.getSettings();
        ws.setJavaScriptEnabled(true);
        ws.setDomStorageEnabled(true);
        ws.setGeolocationEnabled(true);
        ws.setGeolocationDatabasePath(getFilesDir().getPath());
        ws.setAllowFileAccessFromFileURLs(true);
        ws.setAllowUniversalAccessFromFileURLs(true);
        WebView.setWebContentsDebuggingEnabled(true);

        webView.addJavascriptInterface(new AndroidBridge(), "AndroidBridge");

        // ── KEY GPS FIX: grant geolocation to WebView ──
        webView.setWebChromeClient(new WebChromeClient() {
            @Override
            public void onGeolocationPermissionsShowPrompt(String origin,
                    GeolocationPermissions.Callback callback) {
                callback.invoke(origin, true, false);
            }
            @Override
            public boolean onConsoleMessage(ConsoleMessage msg) {
                Log.d(TAG, "JS: " + msg.message());
                return true;
            }
        });

        webView.setWebViewClient(new WebViewClient() {
            @Override
            public void onPageFinished(WebView view, String url) {
                if (!myId.isEmpty() && !myName.isEmpty()) {
                    runOnUiThread(() -> view.evaluateJavascript(
                        "if(window.onAndroidReady) window.onAndroidReady('"
                        + myId + "','" + myName + "')", null));
                }
            }
        });

        webView.loadUrl("file:///android_asset/www/index.html");
    }

    // ── Android ↔ JS Bridge ───────────────────────────
    public class AndroidBridge {

        @JavascriptInterface
        public String getIdentity() {
            JSONObject o = new JSONObject();
            try { o.put("id", myId); o.put("name", myName); } catch (Exception e) {}
            return o.toString();
        }

        @JavascriptInterface
        public void setIdentity(String id, String name) {
            myId = id; myName = name;
            SharedPreferences.Editor ed = getSharedPreferences(PREFS_NAME,
                Context.MODE_PRIVATE).edit();
            ed.putString("nodeId", id);
            ed.putString("nodeName", name);
            ed.apply();
            runOnUiThread(() -> {
                startGattServer();
                startBLEAdvertising();
            });
        }

        @JavascriptInterface
        public void startScan() { runOnUiThread(() -> startBLEScan()); }

        @JavascriptInterface
        public void stopScan() { runOnUiThread(() -> stopBLEScan()); }

        @JavascriptInterface
        public void sendMessage(String peerId, String payloadJson,
                String channel, String mid, long ts) {
            try {
                JSONObject pkt = new JSONObject();
                pkt.put("type", "chat");
                pkt.put("id", myId); pkt.put("name", myName);
                pkt.put("ch", channel);
                pkt.put("payload", new JSONObject(payloadJson));
                pkt.put("t", ts); pkt.put("mid", mid);
                String data = pkt.toString();
                if (channel.equals("broadcast") || peerId == null || peerId.isEmpty()) {
                    broadcastToAll(data, null);
                } else {
                    sendToPeerId(peerId, data);
                }
            } catch (Exception e) { Log.e(TAG, "sendMessage", e); }
        }

        @JavascriptInterface
        public String encrypt(String text) {
            try { return encryptAES(text).toString(); }
            catch (Exception e) {
                try {
                    JSONObject r = new JSONObject();
                    r.put("c", Base64.encodeToString(
                        text.getBytes(StandardCharsets.UTF_8), Base64.NO_WRAP));
                    r.put("i", ""); r.put("r", 1);
                    return r.toString();
                } catch (Exception ex) { return "{}"; }
            }
        }

        @JavascriptInterface
        public String decrypt(String json) {
            try { return decryptAES(new JSONObject(json)); }
            catch (Exception e) { return "[encrypted]"; }
        }

        @JavascriptInterface
        public void broadcastLocation(double lat, double lng) {
            try {
                JSONObject pkt = new JSONObject();
                pkt.put("type", "location");
                pkt.put("id", myId); pkt.put("name", myName);
                pkt.put("lat", lat); pkt.put("lng", lng);
                pkt.put("t", System.currentTimeMillis());
                broadcastToAll(pkt.toString(), null);
            } catch (Exception e) {}
        }

        // Native GPS fallback
        @JavascriptInterface
        public String getLastLocation() {
            try {
                if (ActivityCompat.checkSelfPermission(MainActivity.this,
                        Manifest.permission.ACCESS_FINE_LOCATION)
                        != PackageManager.PERMISSION_GRANTED) return "{}";
                LocationManager lm = (LocationManager)
                    getSystemService(Context.LOCATION_SERVICE);
                if (lm == null) return "{}";
                Location loc = lm.getLastKnownLocation(LocationManager.GPS_PROVIDER);
                if (loc == null) loc = lm.getLastKnownLocation(LocationManager.NETWORK_PROVIDER);
                if (loc == null) return "{}";
                JSONObject o = new JSONObject();
                o.put("lat", loc.getLatitude());
                o.put("lng", loc.getLongitude());
                o.put("accuracy", loc.getAccuracy());
                return o.toString();
            } catch (Exception e) { return "{}"; }
        }
    }

    // ── Notify WebView ─────────────────────────────────
    private void sendToWebView(String event, String data) {
        runOnUiThread(() -> webView.evaluateJavascript(
            "if(window.onAndroidEvent) window.onAndroidEvent('"
            + event + "'," + data + ")", null));
    }

    private void notifyPeer(String id, String name, int rssi,
            boolean online, String transport) {
        try {
            JSONObject p = new JSONObject();
            p.put("id", id); p.put("name", name);
            p.put("rssi", rssi); p.put("online", online);
            p.put("transport", transport);
            sendToWebView(online ? "peer-online" : "peer-found", p.toString());
        } catch (Exception e) {}
    }

    // ── GATT Server ────────────────────────────────────
    // KEY FIX: phone runs GATT server so laptop can connect to phone
    // When laptop connects → phone automatically sees laptop on radar
    private void startGattServer() {
        BluetoothManager btMgr =
            (BluetoothManager) getSystemService(Context.BLUETOOTH_SERVICE);
        if (btMgr == null) return;

        BluetoothGattService svc = new BluetoothGattService(
            UUID.fromString(MESH_SERVICE_UUID),
            BluetoothGattService.SERVICE_TYPE_PRIMARY);

        BluetoothGattCharacteristic tx = new BluetoothGattCharacteristic(
            UUID.fromString(MESH_CHAR_TX_UUID),
            BluetoothGattCharacteristic.PROPERTY_WRITE |
            BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
            BluetoothGattCharacteristic.PERMISSION_WRITE);

        BluetoothGattCharacteristic rx = new BluetoothGattCharacteristic(
            UUID.fromString(MESH_CHAR_RX_UUID),
            BluetoothGattCharacteristic.PROPERTY_NOTIFY |
            BluetoothGattCharacteristic.PROPERTY_READ,
            BluetoothGattCharacteristic.PERMISSION_READ);

        BluetoothGattDescriptor desc = new BluetoothGattDescriptor(
            UUID.fromString("00002902-0000-1000-8000-00805f9b34fb"),
            BluetoothGattDescriptor.PERMISSION_READ |
            BluetoothGattDescriptor.PERMISSION_WRITE);
        rx.addDescriptor(desc);

        svc.addCharacteristic(tx);
        svc.addCharacteristic(rx);

        gattServer = btMgr.openGattServer(this, new BluetoothGattServerCallback() {

            @Override
            public void onConnectionStateChange(BluetoothDevice device,
                    int status, int newState) {
                String devId = device.getAddress().replace(":", "");
                if (newState == BluetoothProfile.STATE_CONNECTED) {
                    Log.d(TAG, "Device connected to GATT server: " + device.getAddress());
                    serverClients.add(device);
                    // Send hello after short delay
                    new Handler(Looper.getMainLooper()).postDelayed(
                        () -> sendHelloToClient(device), 600);
                    // Show this device on phone radar immediately
                    String name = peerNames.getOrDefault(
                        device.getAddress(),
                        device.getName() != null
                            ? device.getName().replace("ML-", "") : "PC");
                    notifyPeer(devId, name, -60, true, "ble");
                } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                    serverClients.remove(device);
                    sendToWebView("peer-offline", "\"" + devId + "\"");
                }
            }

            @Override
            public void onCharacteristicWriteRequest(BluetoothDevice device,
                    int requestId, BluetoothGattCharacteristic characteristic,
                    boolean preparedWrite, boolean responseNeeded,
                    int offset, byte[] value) {
                if (responseNeeded)
                    gattServer.sendResponse(device, requestId,
                        BluetoothGatt.GATT_SUCCESS, 0, null);
                handleIncoming(
                    new String(value, StandardCharsets.UTF_8),
                    device.getAddress().replace(":", ""),
                    device.getAddress());
            }

            @Override
            public void onDescriptorWriteRequest(BluetoothDevice device,
                    int requestId, BluetoothGattDescriptor descriptor,
                    boolean preparedWrite, boolean responseNeeded,
                    int offset, byte[] value) {
                if (responseNeeded)
                    gattServer.sendResponse(device, requestId,
                        BluetoothGatt.GATT_SUCCESS, 0, null);
            }
        });

        gattServer.addService(svc);
        Log.d(TAG, "GATT server started");
    }

    private void sendHelloToClient(BluetoothDevice device) {
        if (gattServer == null) return;
        try {
            JSONObject hello = new JSONObject();
            hello.put("type", "hello");
            hello.put("id", myId);
            hello.put("name", myName);
            BluetoothGattService s = gattServer.getService(
                UUID.fromString(MESH_SERVICE_UUID));
            if (s == null) return;
            BluetoothGattCharacteristic rx = s.getCharacteristic(
                UUID.fromString(MESH_CHAR_RX_UUID));
            if (rx == null) return;
            rx.setValue(hello.toString().getBytes(StandardCharsets.UTF_8));
            gattServer.notifyCharacteristicChanged(device, rx, false);
        } catch (Exception e) {}
    }

    // Send to all server clients (devices connected to our GATT server)
    private void sendToServerClients(String data, String exceptAddr) {
        BluetoothGattService s = gattServer == null ? null :
            gattServer.getService(UUID.fromString(MESH_SERVICE_UUID));
        if (s == null) return;
        BluetoothGattCharacteristic rx = s.getCharacteristic(
            UUID.fromString(MESH_CHAR_RX_UUID));
        if (rx == null) return;
        byte[] bytes = data.getBytes(StandardCharsets.UTF_8);
        synchronized (serverClients) {
            for (BluetoothDevice device : serverClients) {
                if (exceptAddr != null &&
                        device.getAddress().equals(exceptAddr)) continue;
                rx.setValue(bytes);
                gattServer.notifyCharacteristicChanged(device, rx, false);
            }
        }
    }

    // ── BLE Advertising ────────────────────────────────
    private void startBLEAdvertising() {
        if (bleAdvertiser == null || myName.isEmpty()) return;
        String advName = "ML-" + myName.toUpperCase()
            .replace(" ", "")
            .substring(0, Math.min(myName.length(), 8));
        try { btAdapter.setName(advName); } catch (Exception e) {}

        AdvertiseSettings settings = new AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
            .setConnectable(true)
            .setTimeout(0)
            .build();

        AdvertiseData data = new AdvertiseData.Builder()
            .setIncludeDeviceName(true)
            .addServiceUuid(new ParcelUuid(UUID.fromString(MESH_SERVICE_UUID)))
            .build();

        bleAdvertiser.startAdvertising(settings, data, new AdvertiseCallback() {
            @Override
            public void onStartSuccess(AdvertiseSettings s) {
                Log.d(TAG, "Advertising as " + advName);
                sendToWebView("bt-status",
                    "{\"available\":true,\"advertising\":true}");
            }
            @Override
            public void onStartFailure(int err) {
                Log.w(TAG, "Advertising failed: " + err);
                sendToWebView("bt-status",
                    "{\"available\":true,\"advertising\":false}");
            }
        });
    }

    // ── BLE Scanning ──────────────────────────────────
    private void startBLEScan() {
        if (bleScanner == null || scanning) return;
        scanning = true;

        ScanFilter f1 = new ScanFilter.Builder()
            .setServiceUuid(new ParcelUuid(UUID.fromString(MESH_SERVICE_UUID)))
            .build();

        ScanSettings settings = new ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .build();

        bleScanner.startScan(Collections.singletonList(f1), settings, scanCallback);
        Log.d(TAG, "BLE scan started");

        new Handler(Looper.getMainLooper()).postDelayed(() -> {
            stopBLEScan();
            sendToWebView("scan-done", "{}");
        }, 15000);
    }

    private void stopBLEScan() {
        if (bleScanner != null && scanning) {
            bleScanner.stopScan(scanCallback);
            scanning = false;
            Log.d(TAG, "BLE scan stopped");
        }
    }

    private final ScanCallback scanCallback = new ScanCallback() {
        @Override
        public void onScanResult(int callbackType, ScanResult result) {
            BluetoothDevice device = result.getDevice();
            String name = result.getScanRecord() != null
                ? result.getScanRecord().getDeviceName() : null;
            if (name == null) name = device.getName();
            if (name == null) name = "Unknown";

            String peerName = name.replace("ML-", "");
            String devAddr  = device.getAddress();
            String devId    = devAddr.replace(":", "");
            int rssi        = result.getRssi();

            peerNames.put(devAddr, peerName);

            Log.d(TAG, "Found: " + name + " (" + rssi + " dBm)");
            notifyPeer(devId, peerName, rssi, false, "ble");

            if (!connectedGatts.containsKey(devAddr)) {
                device.connectGatt(MainActivity.this, false,
                    gattCallback, BluetoothDevice.TRANSPORT_LE);
            }
        }

        @Override
        public void onScanFailed(int err) {
            Log.w(TAG, "Scan failed: " + err);
            sendToWebView("bt-status",
                "{\"available\":true,\"scanError\":" + err + "}");
        }
    };

    // ── GATT Client (connect to discovered peer) ───────
    private final BluetoothGattCallback gattCallback = new BluetoothGattCallback() {
        @Override
        public void onConnectionStateChange(BluetoothGatt gatt,
                int status, int newState) {
            String addr  = gatt.getDevice().getAddress();
            String devId = addr.replace(":", "");
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                connectedGatts.put(addr, gatt);
                gatt.discoverServices();
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                connectedGatts.remove(addr);
                txChars.remove(addr);
                gatt.close();
                sendToWebView("peer-offline", "\"" + devId + "\"");
            }
        }

        @Override
        public void onServicesDiscovered(BluetoothGatt gatt, int status) {
            if (status != BluetoothGatt.GATT_SUCCESS) return;
            String addr = gatt.getDevice().getAddress();

            BluetoothGattService svc = gatt.getService(
                UUID.fromString(MESH_SERVICE_UUID));
            if (svc == null) return;

            BluetoothGattCharacteristic tx = svc.getCharacteristic(
                UUID.fromString(MESH_CHAR_TX_UUID));
            BluetoothGattCharacteristic rx = svc.getCharacteristic(
                UUID.fromString(MESH_CHAR_RX_UUID));

            if (tx != null) txChars.put(addr, tx);

            if (rx != null) {
                gatt.setCharacteristicNotification(rx, true);
                BluetoothGattDescriptor d = rx.getDescriptor(
                    UUID.fromString("00002902-0000-1000-8000-00805f9b34fb"));
                if (d != null) {
                    d.setValue(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE);
                    gatt.writeDescriptor(d);
                }
            }

            // Send hello
            sendHelloToAddr(addr);
            String name = peerNames.getOrDefault(addr, "Unknown");
            notifyPeer(addr.replace(":", ""), name, -55, true, "ble");
        }

        @Override
        public void onCharacteristicChanged(BluetoothGatt gatt,
                BluetoothGattCharacteristic characteristic) {
            String addr = gatt.getDevice().getAddress();
            String data = new String(characteristic.getValue(),
                StandardCharsets.UTF_8);
            handleIncoming(data, addr.replace(":", ""), addr);
        }
    };

    // ── Send helpers ───────────────────────────────────
    private void sendHelloToAddr(String addr) {
        try {
            JSONObject hello = new JSONObject();
            hello.put("type", "hello");
            hello.put("id", myId);
            hello.put("name", myName);
            writeToAddr(addr, hello.toString());
        } catch (Exception e) {}
    }

    private void writeToAddr(String addr, String data) {
        BluetoothGattCharacteristic tx = txChars.get(addr);
        BluetoothGatt gatt = connectedGatts.get(addr);
        if (tx == null || gatt == null) return;
        byte[] bytes = data.getBytes(StandardCharsets.UTF_8);
        tx.setValue(bytes);
        gatt.writeCharacteristic(tx);
    }

    private void sendToPeerId(String peerId, String data) {
        // Try GATT client connection first
        for (Map.Entry<String, BluetoothGatt> e : connectedGatts.entrySet()) {
            if (e.getKey().replace(":", "").equals(peerId)) {
                writeToAddr(e.getKey(), data);
                return;
            }
        }
        // Try server clients
        synchronized (serverClients) {
            for (BluetoothDevice d : serverClients) {
                if (d.getAddress().replace(":", "").equals(peerId)) {
                    sendToServerClients(data, null);
                    return;
                }
            }
        }
    }

    private void broadcastToAll(String data, String exceptAddr) {
        // Send to all GATT client connections
        for (String addr : connectedGatts.keySet()) {
            if (exceptAddr != null && addr.equals(exceptAddr)) continue;
            writeToAddr(addr, data);
        }
        // Send to all GATT server clients (devices that connected TO us)
        sendToServerClients(data, exceptAddr);
    }

    // ── Handle incoming packet ─────────────────────────
    private void handleIncoming(String data, String fromId, String fromAddr) {
        try {
            JSONObject pkt = new JSONObject(data);
            String type = pkt.optString("type");

            if ("hello".equals(type)) {
                String name = pkt.optString("name", "Unknown");
                peerNames.put(fromAddr, name);
                notifyPeer(fromId, name, -55, true, "ble");

            } else if ("chat".equals(type)) {
                JSONObject payload = pkt.optJSONObject("payload");
                String text = payload != null ? decryptAES(payload) : "";
                pkt.put("plaintext", text);
                sendToWebView("message-in", pkt.toString());
                runOnUiThread(() -> Toast.makeText(MainActivity.this,
                    "💬 " + pkt.optString("name") + ": " + text,
                    Toast.LENGTH_SHORT).show());
                // Relay to others
                broadcastToAll(data, fromAddr);

            } else if ("location".equals(type)) {
                sendToWebView("location-in", pkt.toString());
            }
        } catch (Exception e) { Log.e(TAG, "handleIncoming", e); }
    }

    // ── Permissions ────────────────────────────────────
    private void requestAllPermissions() {
        List<String> perms = new ArrayList<>(Arrays.asList(
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_COARSE_LOCATION
        ));
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            perms.add(Manifest.permission.BLUETOOTH_SCAN);
            perms.add(Manifest.permission.BLUETOOTH_CONNECT);
            perms.add(Manifest.permission.BLUETOOTH_ADVERTISE);
        } else {
            perms.add(Manifest.permission.BLUETOOTH);
            perms.add(Manifest.permission.BLUETOOTH_ADMIN);
        }
        List<String> needed = new ArrayList<>();
        for (String p : perms) {
            if (ContextCompat.checkSelfPermission(this, p)
                    != PackageManager.PERMISSION_GRANTED)
                needed.add(p);
        }
        if (!needed.isEmpty()) {
            ActivityCompat.requestPermissions(this,
                needed.toArray(new String[0]), PERM_REQUEST);
        } else {
            initBluetooth();
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode,
            String[] permissions, int[] results) {
        super.onRequestPermissionsResult(requestCode, permissions, results);
        if (requestCode == PERM_REQUEST) initBluetooth();
    }

    // ── Init Bluetooth ─────────────────────────────────
    private void initBluetooth() {
        BluetoothManager btMgr =
            (BluetoothManager) getSystemService(Context.BLUETOOTH_SERVICE);
        if (btMgr == null) {
            sendToWebView("bt-status", "{\"available\":false}");
            return;
        }
        btAdapter = btMgr.getAdapter();
        if (btAdapter == null || !btAdapter.isEnabled()) {
            sendToWebView("bt-status", "{\"available\":false,\"reason\":\"disabled\"}");
            return;
        }
        bleScanner    = btAdapter.getBluetoothLeScanner();
        bleAdvertiser = btAdapter.getBluetoothLeAdvertiser();
        sendToWebView("bt-status", "{\"available\":true}");

        if (!myName.isEmpty()) {
            startGattServer();
            startBLEAdvertising();
            new Handler(Looper.getMainLooper()).postDelayed(
                this::startBLEScan, 1500);
        }
    }

    // ── AES-256-GCM ───────────────────────────────────
    private void initCrypto() throws Exception {
        byte[] salt = "ml3s".getBytes(StandardCharsets.UTF_8);
        byte[] pass = "meshlink-ble-v3".getBytes(StandardCharsets.UTF_8);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(
            new String(pass, StandardCharsets.UTF_8).toCharArray(),
            salt, 50000, 256);
        aesKey = new SecretKeySpec(f.generateSecret(spec).getEncoded(), "AES");
    }

    private JSONObject encryptAES(String text) throws Exception {
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));
        byte[] ct = c.doFinal(text.getBytes(StandardCharsets.UTF_8));
        JSONObject r = new JSONObject();
        r.put("c", Base64.encodeToString(ct, Base64.NO_WRAP));
        r.put("i", Base64.encodeToString(iv, Base64.NO_WRAP));
        return r;
    }

    private String decryptAES(JSONObject payload) throws Exception {
        if (payload.optInt("r", 0) == 1)
            return new String(Base64.decode(payload.optString("c"),
                Base64.DEFAULT), StandardCharsets.UTF_8);
        byte[] ct = Base64.decode(payload.optString("c"), Base64.DEFAULT);
        byte[] iv = Base64.decode(payload.optString("i"), Base64.DEFAULT);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));
        return new String(c.doFinal(ct), StandardCharsets.UTF_8);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        stopBLEScan();
        if (bleAdvertiser != null)
            bleAdvertiser.stopAdvertising(new AdvertiseCallback() {});
        for (BluetoothGatt g : connectedGatts.values()) g.close();
        if (gattServer != null) gattServer.close();
    }
}

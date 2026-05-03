package com.ese.flix;

import android.annotation.SuppressLint;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.FrameLayout;
import android.widget.ProgressBar;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.google.zxing.integration.android.IntentIntegrator;
import com.google.zxing.integration.android.IntentResult;
import android.content.Intent;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * eSE — Android client for eMule streaming server.
 * 
 * Connection strategy (multi-fallback):
 *   1. Try last known working URL (fastest)
 *   2. Try saved local IPs (same WiFi)
 *   3. Try saved public IP (UPnP)
 *   4. Query ntfy.sh for current tunnel URL (always works)
 * 
 * First-time pairing:
 *   User scans QR from PC → APK gets ntfy topic + connection seeds → saves forever
 */
public class MainActivity extends AppCompatActivity {

    private static final String TAG = "eSE";
    private static final String PREFS = "ese_prefs";
    private static final String KEY_TOPIC = "ntfy_topic";
    private static final String KEY_LAST_URL = "last_working_url";
    private static final String KEY_LOCAL_IPS = "local_ips";
    private static final String KEY_PUBLIC_IP = "public_ip";
    private static final String KEY_PORT = "port";
    private static final int CONNECT_TIMEOUT = 5000;

    private WebView webView;
    private FrameLayout splashScreen;
    private TextView statusText;
    private ProgressBar progressBar;
    private SharedPreferences prefs;
    private ExecutorService executor;
    private Handler mainHandler;
    private boolean isConnected = false;

    @Override
    @SuppressLint("SetJavaScriptEnabled")
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Fullscreen immersive — no status bar, no nav bar
        requestWindowFeature(Window.FEATURE_NO_TITLE);
        getWindow().setFlags(
            WindowManager.LayoutParams.FLAG_FULLSCREEN | WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON,
            WindowManager.LayoutParams.FLAG_FULLSCREEN | WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON
        );
        getWindow().getDecorView().setSystemUiVisibility(
            View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY |
            View.SYSTEM_UI_FLAG_FULLSCREEN |
            View.SYSTEM_UI_FLAG_HIDE_NAVIGATION |
            View.SYSTEM_UI_FLAG_LAYOUT_STABLE |
            View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION |
            View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN
        );

        setContentView(R.layout.activity_main);

        webView = findViewById(R.id.webview);
        splashScreen = findViewById(R.id.splash_screen);
        statusText = findViewById(R.id.status_text);
        progressBar = findViewById(R.id.progress_bar);

        prefs = getSharedPreferences(PREFS, MODE_PRIVATE);
        executor = Executors.newSingleThreadExecutor();
        mainHandler = new Handler(Looper.getMainLooper());

        setupWebView();

        // Check if we have a saved topic (already paired)
        String topic = prefs.getString(KEY_TOPIC, null);
        if (topic != null) {
            updateStatus("Conectando...");
            startMultiStrategyConnect();
        } else {
            updateStatus("Primera conexión — escanea el QR en tu PC");
            startQRScanner();
        }
    }

    @SuppressLint("SetJavaScriptEnabled")
    private void setupWebView() {
        WebSettings ws = webView.getSettings();
        ws.setJavaScriptEnabled(true);
        ws.setDomStorageEnabled(true);
        ws.setMediaPlaybackRequiresUserGesture(false);
        ws.setAllowFileAccess(true);
        ws.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);
        ws.setUserAgentString(ws.getUserAgentString() + " eSE-App/1.0");

        webView.setBackgroundColor(Color.parseColor("#0d0d12"));

        webView.setWebViewClient(new WebViewClient() {
            @Override
            public void onPageFinished(WebView view, String url) {
                super.onPageFinished(view, url);
                if (!url.contains("/connect") && !url.contains("/pair/")) {
                    // Successfully loaded main page
                    isConnected = true;
                    prefs.edit().putString(KEY_LAST_URL, url.replaceAll("/\\?.*", "").replaceAll("/$", "")).apply();
                    showWebView();
                }
            }

            @Override
            public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) {
                if (request.isForMainFrame()) {
                    Log.w(TAG, "WebView error: " + error.getDescription());
                    isConnected = false;
                    showSplash();
                    updateStatus("Conexión perdida, reconectando...");
                    retryConnect(3000);
                }
            }
        });

        webView.setWebChromeClient(new WebChromeClient() {
            // Support fullscreen video
            private View customView;
            
            @Override
            public void onShowCustomView(View view, CustomViewCallback callback) {
                customView = view;
                ((FrameLayout) getWindow().getDecorView()).addView(view);
                webView.setVisibility(View.GONE);
            }

            @Override
            public void onHideCustomView() {
                if (customView != null) {
                    ((FrameLayout) getWindow().getDecorView()).removeView(customView);
                    customView = null;
                }
                webView.setVisibility(View.VISIBLE);
            }
        });
    }

    private void startQRScanner() {
        IntentIntegrator integrator = new IntentIntegrator(this);
        integrator.setDesiredBarcodeFormats(IntentIntegrator.QR_CODE);
        integrator.setPrompt("Escanea el QR de eSE en tu PC");
        integrator.setBeepEnabled(false);
        integrator.setOrientationLocked(false);
        integrator.setCameraId(0);
        integrator.initiateScan();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        IntentResult result = IntentIntegrator.parseActivityResult(requestCode, resultCode, data);
        if (result != null && result.getContents() != null) {
            String qrUrl = result.getContents();
            Log.i(TAG, "QR scanned: " + qrUrl);
            updateStatus("Vinculando con servidor...");
            executePairing(qrUrl);
        } else {
            // User cancelled QR scanner
            updateStatus("Escanea el QR para conectar");
            // Show retry button
            mainHandler.postDelayed(this::startQRScanner, 2000);
        }
    }

    private void executePairing(String pairUrl) {
        executor.execute(() -> {
            try {
                HttpURLConnection conn = (HttpURLConnection) new URL(pairUrl).openConnection();
                conn.setConnectTimeout(CONNECT_TIMEOUT);
                conn.setReadTimeout(CONNECT_TIMEOUT);
                conn.setInstanceFollowRedirects(true);

                int code = conn.getResponseCode();
                if (code == 200) {
                    // Read the pairing page HTML — extract seed from base64
                    BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) sb.append(line);
                    reader.close();

                    String html = sb.toString();
                    // The pair page contains a redirect with seed data
                    // Try to extract the JSON seed
                    String seedJson = extractSeedFromResponse(html, pairUrl);
                    
                    if (seedJson != null) {
                        JSONObject seed = new JSONObject(seedJson);
                        String topic = seed.optString("s", null);
                        int port = seed.optInt("p", 8080);
                        String tunnel = seed.optString("t", null);
                        
                        // Save local IPs
                        JSONArray localIPs = seed.optJSONArray("l");
                        String ipsStr = localIPs != null ? localIPs.toString() : "[]";
                        
                        // Save public IP
                        String publicIP = seed.optString("e", null);

                        SharedPreferences.Editor editor = prefs.edit();
                        editor.putString(KEY_TOPIC, topic);
                        editor.putInt(KEY_PORT, port);
                        editor.putString(KEY_LOCAL_IPS, ipsStr);
                        if (publicIP != null) editor.putString(KEY_PUBLIC_IP, publicIP);
                        if (tunnel != null) editor.putString(KEY_LAST_URL, tunnel);
                        editor.apply();

                        Log.i(TAG, "Pairing successful! Topic: " + topic);
                        mainHandler.post(() -> {
                            updateStatus("¡Vinculado! Conectando...");
                            startMultiStrategyConnect();
                        });
                    } else {
                        mainHandler.post(() -> updateStatus("Error de vinculación — intenta de nuevo"));
                        mainHandler.postDelayed(this::startQRScanner, 3000);
                    }
                } else {
                    mainHandler.post(() -> updateStatus("Código expirado — genera uno nuevo en el PC"));
                    mainHandler.postDelayed(this::startQRScanner, 3000);
                }
            } catch (Exception e) {
                Log.e(TAG, "Pairing error", e);
                mainHandler.post(() -> updateStatus("Error de conexión — verifica que estás en la misma red"));
                mainHandler.postDelayed(this::startQRScanner, 3000);
            }
        });
    }

    private String extractSeedFromResponse(String html, String pairUrl) {
        try {
            // The pair endpoint returns HTML with embedded seed
            // Look for base64 encoded seed in the page
            int seedIdx = html.indexOf("seed=");
            if (seedIdx >= 0) {
                String b64 = html.substring(seedIdx + 5);
                int end = b64.indexOf('&');
                if (end < 0) end = b64.indexOf('"');
                if (end < 0) end = b64.indexOf('\'');
                if (end > 0) b64 = b64.substring(0, end);
                return new String(Base64.decode(b64, Base64.DEFAULT));
            }
            
            // Alternative: try to call the pair URL directly as API
            // The server redirects to /?seed=BASE64
            // Try parsing as JSON directly
            if (html.startsWith("{")) {
                return html;
            }
        } catch (Exception e) {
            Log.e(TAG, "Seed extraction error", e);
        }
        
        // Fallback: call the connect-seed API using the base URL from pair URL
        try {
            String baseUrl = pairUrl.substring(0, pairUrl.indexOf("/pair/"));
            HttpURLConnection conn = (HttpURLConnection) new URL(baseUrl + "/api/connect-seed").openConnection();
            conn.setConnectTimeout(CONNECT_TIMEOUT);
            BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) sb.append(line);
            reader.close();
            return sb.toString();
        } catch (Exception e) {
            Log.e(TAG, "Connect-seed fallback error", e);
        }
        return null;
    }

    /**
     * Multi-strategy connection: try fastest options first, fall back to ntfy.
     */
    private void startMultiStrategyConnect() {
        executor.execute(() -> {
            String workingUrl = null;

            // Strategy 1: Last known working URL
            String lastUrl = prefs.getString(KEY_LAST_URL, null);
            if (lastUrl != null) {
                mainHandler.post(() -> updateStatus("Probando última conexión..."));
                if (isServerReachable(lastUrl)) {
                    workingUrl = lastUrl;
                }
            }

            // Strategy 2: Local IPs (same WiFi)
            if (workingUrl == null) {
                int port = prefs.getInt(KEY_PORT, 8080);
                try {
                    JSONArray ips = new JSONArray(prefs.getString(KEY_LOCAL_IPS, "[]"));
                    for (int i = 0; i < ips.length(); i++) {
                        String ip = ips.getString(i);
                        String localUrl = "http://" + ip + ":" + port;
                        mainHandler.post(() -> updateStatus("Buscando en red local..."));
                        if (isServerReachable(localUrl)) {
                            workingUrl = localUrl;
                            break;
                        }
                    }
                } catch (Exception e) {
                    Log.w(TAG, "Local IP check failed", e);
                }
            }

            // Strategy 3: Public IP (UPnP)
            if (workingUrl == null) {
                String publicIP = prefs.getString(KEY_PUBLIC_IP, null);
                int port = prefs.getInt(KEY_PORT, 8080);
                if (publicIP != null) {
                    String pubUrl = "http://" + publicIP + ":" + port;
                    mainHandler.post(() -> updateStatus("Probando IP pública..."));
                    if (isServerReachable(pubUrl)) {
                        workingUrl = pubUrl;
                    }
                }
            }

            // Strategy 4: ntfy.sh lookup (tunnel URL)
            if (workingUrl == null) {
                String topic = prefs.getString(KEY_TOPIC, null);
                if (topic != null) {
                    mainHandler.post(() -> updateStatus("Obteniendo URL del servidor..."));
                    String tunnelUrl = fetchFromNtfy(topic);
                    if (tunnelUrl != null && isServerReachable(tunnelUrl)) {
                        workingUrl = tunnelUrl;
                    }
                }
            }

            if (workingUrl != null) {
                final String url = workingUrl;
                // Save as last working URL
                prefs.edit().putString(KEY_LAST_URL, url).apply();
                mainHandler.post(() -> {
                    updateStatus("¡Conectado!");
                    webView.loadUrl(url);
                });
                // Also refresh saved IPs from the server
                refreshConnectionInfo(workingUrl);
            } else {
                mainHandler.post(() -> {
                    updateStatus("No se pudo conectar — tu PC está apagado?");
                    retryConnect(10000);
                });
            }
        });
    }

    private boolean isServerReachable(String baseUrl) {
        try {
            HttpURLConnection conn = (HttpURLConnection) new URL(baseUrl + "/api/status").openConnection();
            conn.setConnectTimeout(CONNECT_TIMEOUT);
            conn.setReadTimeout(CONNECT_TIMEOUT);
            conn.setRequestMethod("GET");
            int code = conn.getResponseCode();
            conn.disconnect();
            return code == 200;
        } catch (Exception e) {
            return false;
        }
    }

    private String fetchFromNtfy(String topic) {
        try {
            String ntfyUrl = "https://ntfy.sh/" + topic + "/json?poll=1&since=24h";
            HttpURLConnection conn = (HttpURLConnection) new URL(ntfyUrl).openConnection();
            conn.setConnectTimeout(CONNECT_TIMEOUT);
            conn.setReadTimeout(CONNECT_TIMEOUT);

            BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            String lastMessage = null;
            String line;
            while ((line = reader.readLine()) != null) {
                try {
                    JSONObject msg = new JSONObject(line);
                    if (msg.has("message")) {
                        lastMessage = msg.getString("message");
                    }
                } catch (Exception ignored) {}
            }
            reader.close();

            // Extract URL from message (format: "🔗 URL: https://xxx.trycloudflare.com\n...")
            if (lastMessage != null) {
                String[] lines = lastMessage.split("\n");
                for (String l : lines) {
                    if (l.contains("http")) {
                        // Extract URL
                        int httpIdx = l.indexOf("http");
                        String url = l.substring(httpIdx).trim();
                        // Clean trailing text
                        int spaceIdx = url.indexOf(' ');
                        if (spaceIdx > 0) url = url.substring(0, spaceIdx);
                        int newlineIdx = url.indexOf('\n');
                        if (newlineIdx > 0) url = url.substring(0, newlineIdx);
                        return url;
                    }
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "ntfy fetch failed", e);
        }
        return null;
    }

    private void refreshConnectionInfo(String workingUrl) {
        executor.execute(() -> {
            try {
                HttpURLConnection conn = (HttpURLConnection) new URL(workingUrl + "/api/connect-seed").openConnection();
                conn.setConnectTimeout(CONNECT_TIMEOUT);
                BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) sb.append(line);
                reader.close();

                JSONObject seed = new JSONObject(sb.toString());
                JSONArray localIPs = seed.optJSONArray("localIPs");
                String publicIP = seed.optString("publicIP", null);
                String tunnel = seed.optString("tunnel", null);

                SharedPreferences.Editor editor = prefs.edit();
                if (localIPs != null) editor.putString(KEY_LOCAL_IPS, localIPs.toString());
                if (publicIP != null) editor.putString(KEY_PUBLIC_IP, publicIP);
                if (tunnel != null) editor.putString(KEY_LAST_URL, tunnel);
                editor.apply();
            } catch (Exception e) {
                Log.w(TAG, "Refresh connection info failed", e);
            }
        });
    }

    private void retryConnect(int delayMs) {
        mainHandler.postDelayed(this::startMultiStrategyConnect, delayMs);
    }

    private void updateStatus(String text) {
        if (statusText != null) statusText.setText(text);
    }

    private void showWebView() {
        splashScreen.setVisibility(View.GONE);
        webView.setVisibility(View.VISIBLE);
    }

    private void showSplash() {
        splashScreen.setVisibility(View.VISIBLE);
        webView.setVisibility(View.GONE);
    }

    @Override
    public void onBackPressed() {
        if (webView.canGoBack()) {
            webView.goBack();
        } else {
            super.onBackPressed();
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (executor != null) executor.shutdown();
    }
}

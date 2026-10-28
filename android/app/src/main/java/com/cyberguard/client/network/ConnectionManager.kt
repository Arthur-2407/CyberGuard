package com.cyberguard.client.network

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.util.Log
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import okhttp3.OkHttpClient
import org.json.JSONObject
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.net.HttpURLConnection
import java.net.Inet4Address
import java.net.URL
import java.util.concurrent.TimeUnit

enum class ConnectionMode {
    CLOUD,
    LOCAL_LAN,
    HYBRID
}

enum class HybridPriority {
    LOCAL_FIRST,
    CLOUD_FIRST
}

data class EndpointHealthResult(
    val url: String,
    val isReachable: Boolean,
    val isCyberGuardBackend: Boolean,
    val isStaticFrontend: Boolean = false,
    val statusCode: Int = 0,
    val latencyMs: Long = 0,
    val serviceName: String? = null,
    val version: String? = null,
    val details: String? = null
)

data class ConnectionConfig(
    val mode: ConnectionMode = ConnectionMode.HYBRID,
    val hybridPriority: HybridPriority = HybridPriority.LOCAL_FIRST,
    val cloudUrl: String = ConnectionManager.DEFAULT_CLOUD_BACKEND_URL,
    val localHost: String = ConnectionManager.DEFAULT_LOCAL_HOST,
    val localPort: Int = ConnectionManager.DEFAULT_LOCAL_PORT,
    val customBasePath: String = ""
)

enum class ConnectionState {
    DISCONNECTED,
    NETWORK_UNAVAILABLE,
    DISCOVERING,
    DISCOVERY_TIMEOUT,
    NODE_FOUND,
    VALIDATING,
    BACKEND_UNREACHABLE,
    BACKEND_UNHEALTHY,
    CONNECTED_CLOUD,
    CONNECTED_LOCAL,
    CONNECTED_HYBRID,
    CONNECTED,
    AUTH_REQUIRED,
    PARTIALLY_AVAILABLE,
    ERROR
}

class ConnectionManager(private val context: Context) {
    companion object {
        const val DEFAULT_TUNNEL_URL = "https://cyberguard-backend-8rbz.onrender.com"
        const val DEFAULT_STATIC_FRONTEND_URL = "https://cyber-guard-backend-ashen.vercel.app"
        const val DEFAULT_CLOUD_BACKEND_URL = "https://cyberguard-backend-8rbz.onrender.com"
        const val DEFAULT_LOCAL_HOST = "10.103.174.181"
        const val DEFAULT_LOCAL_PORT = 3000

        val CLOUD_BACKEND_FALLBACKS = listOf(
            "https://cyberguard-backend-8rbz.onrender.com",
            "https://cyber-guard-backend-ashen.vercel.app",
            "https://cyber-guard-backend-j3bo9l8hm-arthur-03fc.vercel.app",
            "https://arthur-2407.github.io/CyberGuard"
        )

        fun isCloudUrl(hostOrUrl: String): Boolean {
            val trimmed = hostOrUrl.trim().lowercase()
            return trimmed.startsWith("https://") ||
                    trimmed.contains(".trycloudflare.com") ||
                    trimmed.contains(".ngrok-free.app") ||
                    trimmed.contains(".loca.lt") ||
                    trimmed.contains(".vercel.app") ||
                    trimmed.contains(".pages.dev") ||
                    trimmed.contains(".github.io") ||
                    trimmed.contains(".render.com") ||
                    trimmed.contains(".onrender.com")
        }

        fun isEmulatorEnvironment(): Boolean {
            val fingerprint = Build.FINGERPRINT.lowercase()
            val hardware = Build.HARDWARE.lowercase()
            val model = Build.MODEL.lowercase()
            return fingerprint.startsWith("generic") ||
                    fingerprint.startsWith("unknown") ||
                    hardware.contains("goldfish") ||
                    hardware.contains("ranchu") ||
                    model.contains("google_sdk") ||
                    model.contains("emulator") ||
                    model.contains("android sdk")
        }

        fun formatEndpointUrl(hostOrUrl: String, port: Int = 3000): String {
            var trimmed = hostOrUrl.trim()
            if (trimmed.isEmpty()) return "http://127.0.0.1:$port/"

            // Clean multiple slashes at the end
            while (trimmed.endsWith("/")) {
                trimmed = trimmed.substring(0, trimmed.length - 1).trim()
            }

            return when {
                trimmed.startsWith("http://") || trimmed.startsWith("https://") -> {
                    "$trimmed/"
                }
                isCloudUrl(trimmed) || port == 443 -> {
                    "https://$trimmed/"
                }
                else -> {
                    if (trimmed.contains(":")) {
                        "http://$trimmed/"
                    } else {
                        "http://$trimmed:$port/"
                    }
                }
            }
        }
    }

    private val prefs = context.getSharedPreferences("cyberguard_connection_prefs", Context.MODE_PRIVATE)

    // Current high-level connection state
    private val _connectionState = MutableStateFlow(ConnectionState.DISCONNECTED)
    val connectionState: StateFlow<ConnectionState> = _connectionState.asStateFlow()

    // Active server URL Retrofit & WebSockets are bound to
    private val _serverUrl = MutableStateFlow<String?>(null)
    val serverUrl: StateFlow<String?> = _serverUrl.asStateFlow()

    val discoveryStatus = MutableStateFlow("INITIALIZING QUANTUM SCANNER...")

    // Mode and Config management
    private val _connectionConfig = MutableStateFlow(loadPersistedConfig())
    val connectionConfig: StateFlow<ConnectionConfig> = _connectionConfig.asStateFlow()

    private val _activeMode = MutableStateFlow(ConnectionMode.HYBRID)
    val activeMode: StateFlow<ConnectionMode> = _activeMode.asStateFlow()

    private val _activeEndpoint = MutableStateFlow<String?>(null)
    val activeEndpoint: StateFlow<String?> = _activeEndpoint.asStateFlow()

    private val _activeEndpointType = MutableStateFlow<String?>("LOCAL_LAN") // "LOCAL_LAN" | "CLOUD_TUNNEL" | "NONE"
    val activeEndpointType: StateFlow<String?> = _activeEndpointType.asStateFlow()

    private val _cloudHealth = MutableStateFlow<EndpointHealthResult?>(null)
    val cloudHealth: StateFlow<EndpointHealthResult?> = _cloudHealth.asStateFlow()

    private val _localHealth = MutableStateFlow<EndpointHealthResult?>(null)
    val localHealth: StateFlow<EndpointHealthResult?> = _localHealth.asStateFlow()

    private val _failoverNotice = MutableStateFlow<String?>(null)
    val failoverNotice: StateFlow<String?> = _failoverNotice.asStateFlow()

    private val _isFailoverActive = MutableStateFlow(false)
    val isFailoverActive: StateFlow<Boolean> = _isFailoverActive.asStateFlow()

    private var nsdManager: NsdManager? = null
    private var discoveryListener: NsdManager.DiscoveryListener? = null

    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    private var wifiMulticastLock: WifiManager.MulticastLock? = null
    private var subnetProbeJob: Job? = null
    private var hybridSupervisorJob: Job? = null

    private val SERVICE_TYPE = "_cyberguard._tcp."

    private var discoveryJob: Job? = null
    private var isResolving = false

    val authManager = com.cyberguard.client.model.AuthManager.getInstance(context)

    val okHttpClient = OkHttpClient.Builder()
        .addInterceptor(AuthInterceptor(authManager))
        .connectTimeout(12, TimeUnit.SECONDS)
        .readTimeout(60, TimeUnit.SECONDS)
        .writeTimeout(60, TimeUnit.SECONDS)
        .build()

    var api: CyberGuardApi? = null
        private set

    init {
        connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()

        networkCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                Log.d("ConnectionManager", "Network interface became available.")
                CoroutineScope(Dispatchers.Main).launch {
                    val currentState = _connectionState.value
                    if (currentState == ConnectionState.DISCONNECTED || currentState == ConnectionState.ERROR || currentState == ConnectionState.NETWORK_UNAVAILABLE) {
                        applyConfigAndConnect()
                    }
                }
            }

            override fun onLost(network: Network) {
                Log.d("ConnectionManager", "Network interface lost.")
                CoroutineScope(Dispatchers.Main).launch {
                    val cm = connectivityManager
                    val activeNet = cm?.activeNetwork
                    val caps = cm?.getNetworkCapabilities(activeNet)
                    val stillHasNetwork = caps != null && (
                        caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
                        caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) ||
                        caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)
                    )

                    if (!stillHasNetwork) {
                        _connectionState.value = ConnectionState.NETWORK_UNAVAILABLE
                        _serverUrl.value = null
                        api = null
                        discoveryStatus.value = "LOCAL INTERFACE OFFLINE"
                    } else if (_connectionConfig.value.mode == ConnectionMode.HYBRID) {
                        // Re-evaluate hybrid endpoint routing on network handoff (e.g. Wi-Fi <-> Cellular)
                        applyConfigAndConnect()
                    }
                }
            }
        }
        try {
            connectivityManager?.registerNetworkCallback(request, networkCallback!!)
        } catch (e: Exception) {
            Log.e("ConnectionManager", "Failed to register network callback", e)
        }
    }

    private fun loadPersistedConfig(): ConnectionConfig {
        val modeStr = prefs.getString("conn_mode", ConnectionMode.HYBRID.name)
        val mode = try { ConnectionMode.valueOf(modeStr ?: ConnectionMode.HYBRID.name) } catch (e: Exception) { ConnectionMode.HYBRID }

        val priorityStr = prefs.getString("hybrid_priority", HybridPriority.LOCAL_FIRST.name)
        val priority = try { HybridPriority.valueOf(priorityStr ?: HybridPriority.LOCAL_FIRST.name) } catch (e: Exception) { HybridPriority.LOCAL_FIRST }

        val rawCloud = prefs.getString("cloud_url", null)
        val cloudHost = rawCloud?.removePrefix("https://")?.removePrefix("http://")?.substringBefore("/")?.substringBefore(":")
        val isCloudHostValid = !cloudHost.isNullOrBlank() && cloudHost.contains(".") && !cloudHost.endsWith(".")

        val cloudUrl = if (rawCloud.isNullOrBlank() ||
            rawCloud == "https://avon-personals-coverage-ask.trycloudflare.com" ||
            rawCloud.contains("expired") ||
            !isCloudHostValid ||
            (rawCloud.contains("val-regarding-config-imp") && !rawCloud.contains(".trycloudflare.com"))
        ) {
            DEFAULT_CLOUD_BACKEND_URL.also {
                prefs.edit().putString("cloud_url", it).apply()
            }
        } else {
            rawCloud
        }
        val fallbackHost = if (isEmulatorEnvironment()) "10.0.2.2" else (getDetectedGatewayOrHostIp() ?: DEFAULT_LOCAL_HOST)
        var localHost = prefs.getString("local_host", fallbackHost) ?: fallbackHost
        val allLocalIps = getAllLocalIpAddresses()
        val isOn172_16 = allLocalIps.any { it.startsWith("172.16.31.") }
        if (localHost == "172.16.31.2" && !isOn172_16 && allLocalIps.isNotEmpty()) {
            val detected = getDetectedGatewayOrHostIp() ?: fallbackHost
            if (detected != "172.16.31.2") {
                localHost = detected
                prefs.edit().putString("local_host", localHost).apply()
            }
        }
        val localPort = prefs.getInt("local_port", DEFAULT_LOCAL_PORT)
        val customBasePath = prefs.getString("custom_base_path", "") ?: ""

        return ConnectionConfig(
            mode = mode,
            hybridPriority = priority,
            cloudUrl = cloudUrl,
            localHost = localHost,
            localPort = localPort,
            customBasePath = customBasePath
        )
    }

    fun persistConfig(config: ConnectionConfig) {
        prefs.edit()
            .putString("conn_mode", config.mode.name)
            .putString("hybrid_priority", config.hybridPriority.name)
            .putString("cloud_url", config.cloudUrl)
            .putString("local_host", config.localHost)
            .putInt("local_port", config.localPort)
            .putString("custom_base_path", config.customBasePath)
            .apply()
        _connectionConfig.value = config
    }

    fun restoreDefaultConfig(): ConnectionConfig {
        val currentLocalHost = prefs.getString("local_host", null)
        val currentLocalPort = prefs.getInt("local_port", DEFAULT_LOCAL_PORT)
        val fallbackHost = currentLocalHost ?: (if (isEmulatorEnvironment()) "10.0.2.2" else (getDetectedGatewayOrHostIp() ?: DEFAULT_LOCAL_HOST))
        val defaultConfig = ConnectionConfig(
            mode = _connectionConfig.value.mode,
            hybridPriority = _connectionConfig.value.hybridPriority,
            cloudUrl = DEFAULT_CLOUD_BACKEND_URL,
            localHost = fallbackHost,
            localPort = currentLocalPort,
            customBasePath = ""
        )
        persistConfig(defaultConfig)
        return defaultConfig
    }

    fun updateConfig(config: ConnectionConfig) {
        persistConfig(config)
    }

    fun getHotspotClientIps(): List<String> {
        val clients = mutableListOf<String>()
        try {
            val arp = java.io.File("/proc/net/arp")
            if (arp.exists() && arp.canRead()) {
                arp.forEachLine { line ->
                    val parts = line.split(Regex("\\s+"))
                    if (parts.size >= 4 && parts[0] != "IP" && parts[2] != "0x0") {
                        val ip = parts[0]
                        if (ip.matches(Regex("\\d+\\.\\d+\\.\\d+\\.\\d+")) && ip != "0.0.0.0" && ip != "192.0.0.1") {
                            clients.add(ip)
                        }
                    }
                }
            }
        } catch (e: Exception) {
            Log.w("ConnectionManager", "ARP scan notice: ${e.message}")
        }
        return clients
    }

    fun getAllLocalIpAddresses(): List<String> {
        val ips = mutableListOf<String>()
        try {
            val interfaces = java.net.NetworkInterface.getNetworkInterfaces() ?: return ips
            for (intf in interfaces) {
                if (intf.isLoopback || !intf.isUp) continue
                for (addr in intf.inetAddresses) {
                    if (!addr.isLoopbackAddress && addr is Inet4Address) {
                        val host = addr.hostAddress
                        if (!host.isNullOrBlank() && !host.startsWith("127.") && host != "0.0.0.0") {
                            ips.add(host)
                        }
                    }
                }
            }
        } catch (e: Exception) {
            Log.w("ConnectionManager", "Interface scan notice: ${e.message}")
        }
        return ips
    }

    fun getDetectedGatewayOrHostIp(): String? {
        if (isEmulatorEnvironment()) {
            return "10.0.2.2"
        }

        // Priority 1: Check hotspot client peers if phone is acting as Wi-Fi hotspot
        val hotspotClients = getHotspotClientIps()
        if (hotspotClients.isNotEmpty()) {
            return hotspotClients.first()
        }

        // Priority 2: Check active default gateway route
        try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            val lp = cm?.getLinkProperties(cm.activeNetwork)
            for (route in lp?.routes ?: emptyList()) {
                if (route.isDefaultRoute && route.gateway is Inet4Address) {
                    val gw = route.gateway?.hostAddress
                    // Ignore 0.0.0.0 and cellular dummy carrier addresses (192.0.0.1)
                    if (!gw.isNullOrBlank() && gw != "0.0.0.0" && gw != "192.0.0.1" && gw.matches(Regex("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$"))) {
                        return gw
                    }
                }
            }
        } catch (e: Exception) {
            Log.w("ConnectionManager", "Gateway detection notice: ${e.message}")
        }

        // Priority 3: Fallback to last verified local LAN IP in preferences (must be a valid IPv4, not a URL)
        val lastLocal = prefs.getString("last_local_ip", null)
        if (!lastLocal.isNullOrBlank() && lastLocal.matches(Regex("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$"))) {
            return lastLocal
        }

        return null
    }

    fun getLocalIpAddress(): String? {
        try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            val lp = cm?.getLinkProperties(cm.activeNetwork)
            for (linkAddress in lp?.linkAddresses ?: emptyList()) {
                val addr = linkAddress.address
                if (!addr.isLoopbackAddress && addr is Inet4Address) {
                    val ip = addr.hostAddress
                    if (ip != null && !ip.startsWith("192.0.0.")) return ip
                }
            }
        } catch (e: Exception) {
            Log.w("ConnectionManager", "Local IP notice: ${e.message}")
        }
        return getAllLocalIpAddresses().firstOrNull()
    }

    val isConnected: Boolean
        get() = (_connectionState.value == ConnectionState.CONNECTED ||
                _connectionState.value == ConnectionState.CONNECTED_CLOUD ||
                _connectionState.value == ConnectionState.CONNECTED_LOCAL ||
                _connectionState.value == ConnectionState.CONNECTED_HYBRID) && api != null

    fun isCloudUrl(hostOrUrl: String): Boolean = Companion.isCloudUrl(hostOrUrl)

    fun formatEndpointUrl(hostOrUrl: String, port: Int = 3000): String = Companion.formatEndpointUrl(hostOrUrl, port)

    private fun probeHttpStatusCode(targetUrl: String, timeoutMs: Int): Int {
        var conn: HttpURLConnection? = null
        return try {
            val url = URL(targetUrl)
            conn = url.openConnection() as HttpURLConnection
            conn.instanceFollowRedirects = true
            conn.connectTimeout = timeoutMs
            conn.readTimeout = timeoutMs
            conn.requestMethod = "GET"
            conn.setRequestProperty("User-Agent", "CyberGuard-Android/1.0")
            conn.setRequestProperty("Accept", "application/json, */*")
            conn.connect()
            conn.responseCode
        } catch (e: Exception) {
            -1
        } finally {
            try { conn?.disconnect() } catch (ignored: Exception) {}
        }
    }

    /**
     * Deep endpoint verification:
     * Discovers whether the candidate serves an authentic CyberGuard Python FastAPI backend
     * or merely a static frontend deployment (such as Vercel / GitHub Pages).
     */
    fun verifyEndpoint(hostOrUrl: String, port: Int = 3000, timeoutMs: Int = 3500): EndpointHealthResult {
        val cleanUrl = formatEndpointUrl(hostOrUrl, port)
        val startTime = System.currentTimeMillis()
        var conn: HttpURLConnection? = null

        return try {
            val target = URL("${cleanUrl}health")
            val host = target.host ?: ""

            // Host syntax and domain completeness validation
            if (!host.contains(".") && !host.equals("localhost", ignoreCase = true) && !host.equals("127.0.0.1", ignoreCase = true)) {
                return EndpointHealthResult(
                    url = cleanUrl,
                    isReachable = false,
                    isCyberGuardBackend = false,
                    latencyMs = 0,
                    details = "Incomplete hostname '$host'. Fully qualified domain name required (e.g. *.trycloudflare.com)."
                )
            }
            conn = target.openConnection() as HttpURLConnection
            conn.instanceFollowRedirects = true
            conn.connectTimeout = timeoutMs
            conn.readTimeout = timeoutMs
            conn.requestMethod = "GET"
            conn.setRequestProperty("User-Agent", "CyberGuard-Android/1.0")
            conn.setRequestProperty("Accept", "application/json, */*")
            conn.connect()

            val code = conn.responseCode
            val latency = System.currentTimeMillis() - startTime

            if (code in 200..299) {
                val body = conn.inputStream.bufferedReader().use { it.readText() }
                conn.disconnect()
                conn = null

                val trimmed = body.trim()
                if (trimmed.startsWith("<!DOCTYPE", ignoreCase = true) || trimmed.startsWith("<html", ignoreCase = true)) {
                    return EndpointHealthResult(
                        url = cleanUrl,
                        isReachable = true,
                        isCyberGuardBackend = false,
                        isStaticFrontend = true,
                        statusCode = code,
                        latencyMs = latency,
                        details = "Endpoint returned an HTML web page instead of CyberGuard API."
                    )
                }

                try {
                    val json = JSONObject(trimmed)
                    val status = json.optString("status", "")
                    val service = json.optString("service", "")
                    val version = json.optString("version", "")
                    val backendTag = json.optString("backend", "")

                    val isGenuineBackend = (service.equals("CyberGuard", ignoreCase = true) && (status == "ok" || status == "healthy")) ||
                            json.has("detector_ready") ||
                            json.has("threat_intel") ||
                            backendTag.contains("docker", ignoreCase = true)

                    // Distinguish static Vercel mock file {"status":"operational","service":"CyberGuard Cloud Node","version":"v4.7"}
                    val isVercelStaticMock = (service.contains("Cloud Node", ignoreCase = true) || version == "v4.7" || cleanUrl.contains(".vercel.app")) && !isGenuineBackend

                    if (isVercelStaticMock) {
                        // Confirm if actual API exists by probing /api/health
                        val apiHealthCode = probeHttpStatusCode("${cleanUrl}api/health", timeoutMs = 2000)
                        if (apiHealthCode != 200) {
                            return EndpointHealthResult(
                                url = cleanUrl,
                                isReachable = true,
                                isCyberGuardBackend = false,
                                isStaticFrontend = true,
                                statusCode = code,
                                latencyMs = latency,
                                serviceName = service,
                                version = version,
                                details = "Static Vercel Frontend detected. Real Python FastAPI backend not available at this hostname."
                            )
                        }
                    }

                    if (isGenuineBackend || status == "ok") {
                        return EndpointHealthResult(
                            url = cleanUrl,
                            isReachable = true,
                            isCyberGuardBackend = true,
                            isStaticFrontend = false,
                            statusCode = code,
                            latencyMs = latency,
                            serviceName = service.ifBlank { "CyberGuard" },
                            version = version.ifBlank { "1.0.0" },
                            details = "Verified CyberGuard SOC AI backend active ($latency ms)."
                        )
                    }

                    return EndpointHealthResult(
                        url = cleanUrl,
                        isReachable = true,
                        isCyberGuardBackend = false,
                        statusCode = code,
                        latencyMs = latency,
                        serviceName = service,
                        version = version,
                        details = "Service reachable but did not identify as CyberGuard backend."
                    )
                } catch (e: Exception) {
                    return EndpointHealthResult(
                        url = cleanUrl,
                        isReachable = true,
                        isCyberGuardBackend = false,
                        statusCode = code,
                        latencyMs = latency,
                        details = "Invalid API payload: ${e.message}"
                    )
                }
            } else if (code == 401 || code == 403) {
                return EndpointHealthResult(
                    url = cleanUrl,
                    isReachable = true,
                    isCyberGuardBackend = true,
                    statusCode = code,
                    latencyMs = latency,
                    details = "Authentication required (HTTP $code)."
                )
            } else {
                return EndpointHealthResult(
                    url = cleanUrl,
                    isReachable = true,
                    isCyberGuardBackend = false,
                    statusCode = code,
                    latencyMs = latency,
                    details = "HTTP $code returned by server."
                )
            }
        } catch (e: java.net.ConnectException) {
            EndpointHealthResult(
                url = cleanUrl,
                isReachable = false,
                isCyberGuardBackend = false,
                latencyMs = System.currentTimeMillis() - startTime,
                details = "Connection refused on port ${if (cleanUrl.startsWith("https")) 443 else port}."
            )
        } catch (e: java.net.SocketTimeoutException) {
            EndpointHealthResult(
                url = cleanUrl,
                isReachable = false,
                isCyberGuardBackend = false,
                latencyMs = System.currentTimeMillis() - startTime,
                details = "Connection timed out."
            )
        } catch (e: java.net.UnknownHostException) {
            val host = try { URL(cleanUrl).host } catch (_: Exception) { hostOrUrl }
            val detailMsg = if (!host.contains(".") && !host.equals("localhost", ignoreCase = true)) {
                "Incomplete hostname '$host'. Fully qualified domain name required."
            } else {
                "DNS resolution failed for hostname '$host'."
            }
            EndpointHealthResult(
                url = cleanUrl,
                isReachable = false,
                isCyberGuardBackend = false,
                latencyMs = System.currentTimeMillis() - startTime,
                details = detailMsg
            )
        } catch (e: javax.net.ssl.SSLException) {
            EndpointHealthResult(
                url = cleanUrl,
                isReachable = false,
                isCyberGuardBackend = false,
                latencyMs = System.currentTimeMillis() - startTime,
                details = "TLS/SSL certificate handshake failed: ${e.message}"
            )
        } catch (e: Exception) {
            val isCleartextBlocked = e.message?.contains("Cleartext HTTP traffic", ignoreCase = true) == true
            EndpointHealthResult(
                url = cleanUrl,
                isReachable = false,
                isCyberGuardBackend = false,
                latencyMs = System.currentTimeMillis() - startTime,
                details = if (isCleartextBlocked) {
                    "Android policy blocked unencrypted HTTP to this host."
                } else {
                    e.message ?: "Network transport error."
                }
            )
        } finally {
            try { conn?.disconnect() } catch (ignored: Exception) {}
        }
    }

    private fun quickCheckEndpoint(hostOrUrl: String, port: Int = 3000, timeoutMs: Int = 1200): Boolean {
        val result = verifyEndpoint(hostOrUrl, port, timeoutMs)
        return result.isReachable && result.isCyberGuardBackend
    }

    fun applyConfigAndConnect(config: ConnectionConfig = _connectionConfig.value) {
        stopDiscovery()
        hybridSupervisorJob?.cancel()
        persistConfig(config)

        _activeMode.value = config.mode
        _connectionState.value = ConnectionState.VALIDATING

        when (config.mode) {
            ConnectionMode.CLOUD -> {
                connectModeCloud(config)
            }
            ConnectionMode.LOCAL_LAN -> {
                connectModeLocalLan(config)
            }
            ConnectionMode.HYBRID -> {
                connectModeHybrid(config)
            }
        }
    }

    private fun connectModeCloud(config: ConnectionConfig) {
        CoroutineScope(Dispatchers.IO).launch {
            discoveryStatus.value = "PROBING CLOUD DEFENSE NODE..."
            val result = verifyEndpoint(config.cloudUrl, 443, timeoutMs = 4000)
            _cloudHealth.value = result

            withContext(Dispatchers.Main) {
                if (result.isCyberGuardBackend && (result.statusCode in 200..299)) {
                    bindClientEndpoint(result.url, "CLOUD_TUNNEL")
                    _connectionState.value = ConnectionState.CONNECTED
                    discoveryStatus.value = "CLOUD DEFENSE UPLINK SYNCHRONIZED"
                    _failoverNotice.value = null
                    _isFailoverActive.value = false
                } else if (result.statusCode == 401 || result.statusCode == 403) {
                    bindClientEndpoint(result.url, "CLOUD_TUNNEL")
                    _connectionState.value = ConnectionState.AUTH_REQUIRED
                    discoveryStatus.value = "CLOUD AUTHENTICATION REQUIRED (${result.statusCode})"
                    _failoverNotice.value = "Cloud node reachable. Please authenticate using operator credentials."
                } else if (result.isStaticFrontend) {
                    _connectionState.value = ConnectionState.BACKEND_UNHEALTHY
                    discoveryStatus.value = "STATIC FRONTEND DETECTED // NO CLOUD API"
                    _failoverNotice.value = "The configured cloud URL is a static web portal (no Python backend API). Configure Cloudflare tunnel or switch to Local LAN mode."
                } else if (result.isReachable) {
                    _connectionState.value = ConnectionState.BACKEND_UNHEALTHY
                    discoveryStatus.value = "CLOUD NODE UNHEALTHY (${result.statusCode})"
                    _failoverNotice.value = result.details
                } else {
                    _connectionState.value = ConnectionState.BACKEND_UNREACHABLE
                    discoveryStatus.value = when {
                        result.details?.contains("DNS", ignoreCase = true) == true -> "CLOUD DNS RESOLUTION FAILED"
                        result.details?.contains("TLS", ignoreCase = true) == true -> "CLOUD TLS HANDSHAKE FAILED"
                        result.details?.contains("timed out", ignoreCase = true) == true -> "CLOUD CONNECTION TIMED OUT"
                        else -> "CLOUD NODE UNREACHABLE"
                    }
                    _failoverNotice.value = result.details ?: "Cloud endpoint could not be reached."
                }
            }
        }
    }

    private fun connectModeLocalLan(config: ConnectionConfig) {
        CoroutineScope(Dispatchers.IO).launch {
            discoveryStatus.value = "CHECKING LOCAL WORKSTATION NODE..."
            var activeResult = verifyEndpoint(config.localHost, config.localPort, timeoutMs = 2500)
            var activeConfig = config

            if (!activeResult.isCyberGuardBackend) {
                // Auto-probe candidate local host addresses on current subnet
                val candidates = mutableListOf<String>()
                candidates.addAll(getHotspotClientIps())
                getDetectedGatewayOrHostIp()?.let { candidates.add(it) }
                prefs.getString("last_local_ip", null)?.let { candidates.add(it) }
                for (localIp in getAllLocalIpAddresses()) {
                    val prefix = localIp.substringBeforeLast(".")
                    if (prefix != "192.0.0" && prefix != "127.0.0") {
                        candidates.add("$prefix.181")
                        candidates.add("$prefix.2")
                        candidates.add("$prefix.1")
                        candidates.add("$prefix.205")
                        candidates.add("$prefix.100")
                    }
                }

                for (candidate in candidates.distinct()) {
                    if (candidate.isBlank() || candidate == config.localHost) continue
                    val probe = verifyEndpoint(candidate, config.localPort, timeoutMs = 1200)
                    if (probe.isCyberGuardBackend) {
                        Log.i("ConnectionManager", "Auto-discovered active local Docker node at $candidate:${config.localPort}")
                        activeResult = probe
                        activeConfig = config.copy(localHost = candidate)
                        persistConfig(activeConfig)
                        break
                    }
                }
            }
            val result = activeResult
            _localHealth.value = result

            withContext(Dispatchers.Main) {
                if (result.isCyberGuardBackend && (result.statusCode in 200..299)) {
                    bindClientEndpoint(result.url, "LOCAL_LAN")
                    _connectionState.value = ConnectionState.CONNECTED
                    discoveryStatus.value = "LOCAL WORKSTATION NODE CONNECTED"
                    _failoverNotice.value = null
                    _isFailoverActive.value = false

                    // Persist local host for fast subsequent connects
                    prefs.edit()
                        .putString("last_local_ip", config.localHost)
                        .putInt("last_local_port", config.localPort)
                        .apply()
                } else if (result.statusCode == 401 || result.statusCode == 403) {
                    bindClientEndpoint(result.url, "LOCAL_LAN")
                    _connectionState.value = ConnectionState.AUTH_REQUIRED
                    discoveryStatus.value = "AUTHENTICATION REQUIRED (${result.statusCode})"
                    _failoverNotice.value = "Local node reachable. Please authenticate using operator credentials."
                } else {
                    val activeNet = connectivityManager?.activeNetwork
                    val caps = connectivityManager?.getNetworkCapabilities(activeNet)
                    val hasWifi = caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
                    val hasCellular = caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true
                    val hasEthernet = caps?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true

                    if (!hasWifi && !hasCellular && !hasEthernet && !isEmulatorEnvironment()) {
                        _connectionState.value = ConnectionState.NETWORK_UNAVAILABLE
                        discoveryStatus.value = "NETWORK INTERFACE OFFLINE"
                        _failoverNotice.value = "All network interfaces offline. Connect to Wi-Fi or cellular."
                    } else if (result.isReachable) {
                        _connectionState.value = ConnectionState.BACKEND_UNHEALTHY
                        discoveryStatus.value = "LOCAL NODE UNHEALTHY (${result.statusCode})"
                        _failoverNotice.value = result.details
                    } else {
                        _connectionState.value = ConnectionState.BACKEND_UNREACHABLE
                        discoveryStatus.value = when {
                            result.details?.contains("refused", ignoreCase = true) == true -> "TARGET PORT ${config.localPort} REFUSED"
                            result.details?.contains("timed out", ignoreCase = true) == true -> "CONNECTION TIMED OUT"
                            result.details?.contains("policy blocked", ignoreCase = true) == true || result.details?.contains("Cleartext", ignoreCase = true) == true -> "CLEARTEXT HTTP RESTRICTED"
                            result.details?.contains("DNS", ignoreCase = true) == true -> "LOCAL DNS RESOLUTION FAILED"
                            else -> "LOCAL NODE UNREACHABLE"
                        }
                        _failoverNotice.value = result.details ?: "Local node could not be reached. Ensure server is running."
                    }
                }
            }
        }
    }

    private fun connectModeHybrid(config: ConnectionConfig) {
        CoroutineScope(Dispatchers.IO).launch {
            discoveryStatus.value = "EVALUATING HYBRID NODES..."

            // Independent parallel verification of both endpoints
            val localDeferred = async { verifyEndpoint(config.localHost, config.localPort, timeoutMs = 2000) }
            val cloudDeferred = async { verifyEndpoint(config.cloudUrl, 443, timeoutMs = 3500) }

            val localResult = localDeferred.await()
            val cloudResult = cloudDeferred.await()

            _localHealth.value = localResult
            _cloudHealth.value = cloudResult

            withContext(Dispatchers.Main) {
                val preferLocal = config.hybridPriority == HybridPriority.LOCAL_FIRST

                if (preferLocal) {
                    if (localResult.isCyberGuardBackend && (localResult.statusCode in 200..299)) {
                        bindClientEndpoint(localResult.url, "LOCAL_LAN")
                        _connectionState.value = ConnectionState.CONNECTED
                        discoveryStatus.value = "HYBRID ACTIVE // LOCAL NODE PRIMARY"
                        _failoverNotice.value = null
                        _isFailoverActive.value = false
                    } else if (cloudResult.isCyberGuardBackend && (cloudResult.statusCode in 200..299)) {
                        bindClientEndpoint(cloudResult.url, "CLOUD_TUNNEL")
                        _connectionState.value = ConnectionState.CONNECTED
                        discoveryStatus.value = "HYBRID ACTIVE // CLOUD FAILOVER ACTIVE"
                        _failoverNotice.value = "Local workstation offline (${localResult.details}). Seamless failover to Cloud defense node."
                        _isFailoverActive.value = true
                    } else if (localResult.statusCode == 401 || localResult.statusCode == 403) {
                        bindClientEndpoint(localResult.url, "LOCAL_LAN")
                        _connectionState.value = ConnectionState.AUTH_REQUIRED
                        discoveryStatus.value = "AUTHENTICATION REQUIRED (${localResult.statusCode})"
                        _failoverNotice.value = "Local node verified. Operator login required."
                    } else if (cloudResult.statusCode == 401 || cloudResult.statusCode == 403) {
                        bindClientEndpoint(cloudResult.url, "CLOUD_TUNNEL")
                        _connectionState.value = ConnectionState.AUTH_REQUIRED
                        discoveryStatus.value = "CLOUD AUTHENTICATION REQUIRED (${cloudResult.statusCode})"
                        _failoverNotice.value = "Cloud node verified. Operator login required."
                    } else {
                        handleHybridTotalFailure(localResult, cloudResult)
                    }
                } else {
                    // Cloud-first priority
                    if (cloudResult.isCyberGuardBackend && (cloudResult.statusCode in 200..299)) {
                        bindClientEndpoint(cloudResult.url, "CLOUD_TUNNEL")
                        _connectionState.value = ConnectionState.CONNECTED
                        discoveryStatus.value = "HYBRID ACTIVE // CLOUD NODE PRIMARY"
                        _failoverNotice.value = null
                        _isFailoverActive.value = false
                    } else if (localResult.isCyberGuardBackend && (localResult.statusCode in 200..299)) {
                        bindClientEndpoint(localResult.url, "LOCAL_LAN")
                        _connectionState.value = ConnectionState.CONNECTED
                        discoveryStatus.value = "HYBRID ACTIVE // LOCAL FAILOVER ACTIVE"
                        _failoverNotice.value = "Cloud node unreachable (${cloudResult.details}). Seamless failover to Local LAN node."
                        _isFailoverActive.value = true
                    } else if (cloudResult.statusCode == 401 || cloudResult.statusCode == 403) {
                        bindClientEndpoint(cloudResult.url, "CLOUD_TUNNEL")
                        _connectionState.value = ConnectionState.AUTH_REQUIRED
                        discoveryStatus.value = "CLOUD AUTHENTICATION REQUIRED (${cloudResult.statusCode})"
                        _failoverNotice.value = "Cloud node verified. Operator login required."
                    } else if (localResult.statusCode == 401 || localResult.statusCode == 403) {
                        bindClientEndpoint(localResult.url, "LOCAL_LAN")
                        _connectionState.value = ConnectionState.AUTH_REQUIRED
                        discoveryStatus.value = "AUTHENTICATION REQUIRED (${localResult.statusCode})"
                        _failoverNotice.value = "Local node verified. Operator login required."
                    } else {
                        handleHybridTotalFailure(localResult, cloudResult)
                    }
                }

                // Launch persistent background health supervisor for failback / failover recovery
                startHybridSupervisor(config)
            }
        }
    }

    private fun handleHybridTotalFailure(localResult: EndpointHealthResult, cloudResult: EndpointHealthResult) {
        val activeNet = connectivityManager?.activeNetwork
        val caps = connectivityManager?.getNetworkCapabilities(activeNet)
        val hasNetwork = caps != null && (
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) ||
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)
        )

        if (!hasNetwork) {
            _connectionState.value = ConnectionState.NETWORK_UNAVAILABLE
            discoveryStatus.value = "LOCAL INTERFACE OFFLINE"
            _failoverNotice.value = "No network interfaces active. Activate Wi-Fi or cellular."
        } else if (cloudResult.isStaticFrontend && !localResult.isReachable) {
            _connectionState.value = ConnectionState.BACKEND_UNHEALTHY
            discoveryStatus.value = "LOCAL OFFLINE // CLOUD IS STATIC FRONTEND"
            _failoverNotice.value = "Local server is unreachable (${localResult.details}) and configured Cloud URL serves only static web frontend (no backend API)."
        } else {
            _connectionState.value = ConnectionState.BACKEND_UNREACHABLE
            discoveryStatus.value = "ALL CONFIGURED NODES UNREACHABLE"
            _failoverNotice.value = "Local: ${localResult.details ?: "Unreachable"} | Cloud: ${cloudResult.details ?: "Unreachable"}"
        }
    }

    private fun startHybridSupervisor(config: ConnectionConfig) {
        hybridSupervisorJob?.cancel()
        hybridSupervisorJob = CoroutineScope(Dispatchers.IO).launch {
            while (isActive && _connectionConfig.value.mode == ConnectionMode.HYBRID) {
                delay(20000) // Bounded 20s interval health re-evaluation

                val currentActiveType = _activeEndpointType.value
                val isFailover = _isFailoverActive.value

                if (config.hybridPriority == HybridPriority.LOCAL_FIRST && isFailover) {
                    // We are currently failed over to Cloud; probe Local LAN node to determine if failback is safe
                    val localProbe = verifyEndpoint(config.localHost, config.localPort, timeoutMs = 1500)
                    _localHealth.value = localProbe
                    if (localProbe.isCyberGuardBackend) {
                        Log.i("ConnectionManager", "Preferred Local Docker node recovered! Initiating safe failback...")
                        withContext(Dispatchers.Main) {
                            bindClientEndpoint(localProbe.url, "LOCAL_LAN")
                            discoveryStatus.value = "HYBRID ACTIVE // LOCAL NODE PRIMARY (RESTORED)"
                            _failoverNotice.value = "Preferred Local workstation recovered. Restored to local network."
                            _isFailoverActive.value = false
                        }
                    }
                } else if (config.hybridPriority == HybridPriority.LOCAL_FIRST && currentActiveType == "LOCAL_LAN") {
                    // Actively on Local; verify it is still healthy
                    val localProbe = verifyEndpoint(config.localHost, config.localPort, timeoutMs = 1500)
                    _localHealth.value = localProbe
                    if (!localProbe.isCyberGuardBackend) {
                        Log.w("ConnectionManager", "Local node dropped! Checking Cloud failover candidate...")
                        val cloudProbe = verifyEndpoint(config.cloudUrl, 443, timeoutMs = 3000)
                        _cloudHealth.value = cloudProbe
                        if (cloudProbe.isCyberGuardBackend) {
                            withContext(Dispatchers.Main) {
                                bindClientEndpoint(cloudProbe.url, "CLOUD_TUNNEL")
                                discoveryStatus.value = "HYBRID ACTIVE // CLOUD FAILOVER ACTIVE"
                                _failoverNotice.value = "Local node dropped. Active failover to Cloud defense node."
                                _isFailoverActive.value = true
                            }
                        }
                    }
                }
            }
        }
    }

    private fun bindClientEndpoint(url: String, type: String) {
        _serverUrl.value = url
        _activeEndpoint.value = url
        _activeEndpointType.value = type

        val retrofit = Retrofit.Builder()
            .baseUrl(url)
            .client(okHttpClient)
            .addConverterFactory(GsonConverterFactory.create())
            .build()

        api = retrofit.create(CyberGuardApi::class.java)

        // Persist successful URL in general preferences for legacy callers
        prefs.edit()
            .putString("server_url", url)
            .apply()
    }

    fun startDiscovery() {
        applyConfigAndConnect()
    }

    fun connectManually(hostOrUrl: String, port: Int = 3000) {
        val isCloud = isCloudUrl(hostOrUrl)
        val mode = if (isCloud) ConnectionMode.CLOUD else ConnectionMode.LOCAL_LAN
        val config = _connectionConfig.value.copy(
            mode = mode,
            cloudUrl = if (isCloud) formatEndpointUrl(hostOrUrl, port) else _connectionConfig.value.cloudUrl,
            localHost = if (!isCloud) hostOrUrl else _connectionConfig.value.localHost,
            localPort = if (!isCloud) port else _connectionConfig.value.localPort
        )
        applyConfigAndConnect(config)
    }

    fun connectToDeployedBackend(url: String = DEFAULT_CLOUD_BACKEND_URL) {
        val config = _connectionConfig.value.copy(
            mode = ConnectionMode.CLOUD,
            cloudUrl = url
        )
        applyConfigAndConnect(config)
    }

    fun connectToServer(hostOrUrl: String, port: Int = 3000) {
        connectManually(hostOrUrl, port)
    }

    fun disconnect() {
        stopDiscovery()
        hybridSupervisorJob?.cancel()
        _connectionState.value = ConnectionState.DISCONNECTED
        _serverUrl.value = null
        _activeEndpoint.value = null
        _activeEndpointType.value = null
        api = null
        discoveryStatus.value = "DISCONNECTED BY OPERATOR"
    }

    fun scanSubnetOnDemand(onFound: (String) -> Unit, onFinished: () -> Unit) {
        CoroutineScope(Dispatchers.IO).launch {
            // Priority 1: Check hotspot peers from ARP table
            val hotspotClients = getHotspotClientIps()
            for (client in hotspotClients) {
                if (quickCheckEndpoint(client, 3000)) {
                    withContext(Dispatchers.Main) { onFound(client) }
                    return@launch
                }
            }

            // Priority 2: Check detected gateway
            val gw = getDetectedGatewayOrHostIp()
            if (gw != null && gw != "192.0.0.1" && quickCheckEndpoint(gw, 3000)) {
                withContext(Dispatchers.Main) { onFound(gw) }
                return@launch
            }

            // Priority 3: Fast parallel subnet scan across all local interfaces
            val allIps = getAllLocalIpAddresses()
            for (localIp in allIps) {
                val prefix = localIp.substringBeforeLast(".")
                if (prefix == "192.0.0" || prefix == "127.0.0") continue

                val prioritySuffixes = listOf(181, 205, 1, 2, 3, 100, 101, 102, 103, 104, 105, 50, 254)
                for (s in prioritySuffixes) {
                    val candidate = "$prefix.$s"
                    if (candidate != localIp && quickCheckEndpoint(candidate, 3000)) {
                        withContext(Dispatchers.Main) { onFound(candidate) }
                        return@launch
                    }
                }

                val remaining = (1..254).filter { it !in prioritySuffixes && "$prefix.$it" != localIp }
                for (batch in remaining.chunked(30)) {
                    val deferreds = batch.map { suffix ->
                        async {
                            val candidate = "$prefix.$suffix"
                            if (quickCheckEndpoint(candidate, 3000)) candidate else null
                        }
                    }
                    val found = deferreds.awaitAll().filterNotNull().firstOrNull()
                    if (found != null) {
                        withContext(Dispatchers.Main) { onFound(found) }
                        return@launch
                    }
                }
            }
            withContext(Dispatchers.Main) { onFinished() }
        }
    }

    fun stopDiscovery() {
        discoveryJob?.cancel()
        subnetProbeJob?.cancel()
        try {
            if (wifiMulticastLock?.isHeld == true) {
                wifiMulticastLock?.release()
            }
        } catch (e: Exception) {}
        wifiMulticastLock = null

        if (discoveryListener != null) {
            try {
                nsdManager?.stopServiceDiscovery(discoveryListener)
            } catch (e: Exception) {}
            discoveryListener = null
        }
    }

    fun cleanup() {
        stopDiscovery()
        hybridSupervisorJob?.cancel()
        networkCallback?.let {
            try {
                connectivityManager?.unregisterNetworkCallback(it)
            } catch (e: Exception) {}
        }
    }
}

package com.cyberguard.client.network

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.net.wifi.WifiManager
import android.util.Log
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import okhttp3.OkHttpClient
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.net.HttpURLConnection
import java.net.Inet4Address
import java.net.URL
import java.util.concurrent.TimeUnit

enum class ConnectionState {
    DISCONNECTED, 
    NETWORK_UNAVAILABLE, 
    DISCOVERING, 
    DISCOVERY_TIMEOUT, 
    NODE_FOUND, 
    VALIDATING, 
    BACKEND_UNREACHABLE, 
    BACKEND_UNHEALTHY, 
    CONNECTED, 
    ERROR
}

class ConnectionManager(private val context: Context) {
    companion object {
        const val DEFAULT_CLOUD_BACKEND_URL = "https://cyber-guard-backend-ashen.vercel.app"
        val CLOUD_BACKEND_FALLBACKS = listOf(
            "https://cyber-guard-backend-ashen.vercel.app",
            "https://cyber-guard-backend-j3bo9l8hm-arthur-03fc.vercel.app",
            "https://arthur-2407.github.io/CyberGuard"
        )

        fun isCloudUrl(hostOrUrl: String): Boolean {
            val trimmed = hostOrUrl.trim().lowercase()
            return trimmed.startsWith("https://") ||
                    trimmed.contains(".vercel.app") ||
                    trimmed.contains(".pages.dev") ||
                    trimmed.contains(".github.io") ||
                    trimmed.contains(".render.com")
        }

        fun formatEndpointUrl(hostOrUrl: String, port: Int = 3000): String {
            val trimmed = hostOrUrl.trim()
            return when {
                trimmed.startsWith("http://") || trimmed.startsWith("https://") -> {
                    if (trimmed.endsWith("/")) trimmed else "$trimmed/"
                }
                isCloudUrl(trimmed) || port == 443 -> {
                    "https://$trimmed/"
                }
                else -> {
                    "http://$trimmed:$port/"
                }
            }
        }
    }

    private val _connectionState = MutableStateFlow(ConnectionState.DISCONNECTED)
    val connectionState: StateFlow<ConnectionState> = _connectionState

    private val _serverUrl = MutableStateFlow<String?>(null)
    val serverUrl: StateFlow<String?> = _serverUrl

    val discoveryStatus = MutableStateFlow("INITIALIZING QUANTUM SCANNER...")

    private var nsdManager: NsdManager? = null
    private var discoveryListener: NsdManager.DiscoveryListener? = null
    
    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    private var wifiMulticastLock: WifiManager.MulticastLock? = null
    private var subnetProbeJob: Job? = null

    private val SERVICE_TYPE = "_cyberguard._tcp."
    
    private var discoveryJob: Job? = null
    private var isResolving = false

    val authManager = com.cyberguard.client.model.AuthManager.getInstance(context)

    val okHttpClient = OkHttpClient.Builder()
        .addInterceptor(AuthInterceptor(authManager))
        .connectTimeout(15, TimeUnit.SECONDS)
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
                Log.d("ConnectionManager", "Network available")
                CoroutineScope(Dispatchers.Main).launch {
                    val currentState = _connectionState.value
                    if (currentState == ConnectionState.DISCONNECTED || currentState == ConnectionState.ERROR || currentState == ConnectionState.NETWORK_UNAVAILABLE) {
                        startDiscovery()
                    }
                }
            }

            override fun onLost(network: Network) {
                Log.d("ConnectionManager", "Network lost")
                CoroutineScope(Dispatchers.Main).launch {
                    _connectionState.value = ConnectionState.NETWORK_UNAVAILABLE
                    _serverUrl.value = null
                    api = null
                }
            }
        }
        try {
            connectivityManager?.registerNetworkCallback(request, networkCallback!!)
        } catch (e: Exception) {
            Log.e("ConnectionManager", "Failed to register network callback", e)
        }
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
        // Priority 1: Check hotspot client peers if phone is acting as Wi-Fi hotspot
        val hotspotClients = getHotspotClientIps()
        if (hotspotClients.isNotEmpty()) {
            return hotspotClients.first()
        }

        try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            val lp = cm?.getLinkProperties(cm.activeNetwork)
            for (route in lp?.routes ?: emptyList()) {
                if (route.isDefaultRoute && route.gateway is Inet4Address) {
                    val gw = route.gateway?.hostAddress
                    // Ignore 0.0.0.0 and cellular dummy carrier addresses (192.0.0.1)
                    if (!gw.isNullOrBlank() && gw != "0.0.0.0" && gw != "192.0.0.1") return gw
                }
            }
        } catch (e: Exception) {
            Log.w("ConnectionManager", "Gateway detection notice: ${e.message}")
        }
        val prefs = context.getSharedPreferences("cyberguard_prefs", Context.MODE_PRIVATE)
        return prefs.getString("last_host_ip", null)
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
        get() = _connectionState.value == ConnectionState.CONNECTED && api != null

    fun isCloudUrl(hostOrUrl: String): Boolean = Companion.isCloudUrl(hostOrUrl)

    fun formatEndpointUrl(hostOrUrl: String, port: Int = 3000): String = Companion.formatEndpointUrl(hostOrUrl, port)

    private fun checkHttp(urlString: String, timeoutMs: Int): Boolean {
        var conn: HttpURLConnection? = null
        return try {
            val url = URL(urlString)
            conn = url.openConnection() as HttpURLConnection
            conn.instanceFollowRedirects = true
            conn.connectTimeout = timeoutMs
            conn.readTimeout = timeoutMs
            conn.requestMethod = "GET"
            conn.setRequestProperty("User-Agent", "CyberGuard-Android/1.0")
            conn.setRequestProperty("Accept", "application/json, text/html, */*")
            conn.connect()
            val code = conn.responseCode
            code in 200..299 || code in 300..399
        } catch (e: Exception) {
            false
        } finally {
            try { conn?.disconnect() } catch (ignored: Exception) {}
        }
    }

    private fun quickCheckEndpoint(hostOrUrl: String, port: Int = 3000, timeoutMs: Int = 1200): Boolean {
        val base = formatEndpointUrl(hostOrUrl, port)
        val isCloud = isCloudUrl(base)

        // Check primary /health path
        if (checkHttp("${base}health", timeoutMs)) return true

        // For cloud endpoints, also check health.json and root URL
        if (isCloud) {
            if (checkHttp("${base}health.json", timeoutMs)) return true
            if (checkHttp(base, timeoutMs)) return true
        }
        return false
    }

    fun startDiscovery() {
        val currentState = _connectionState.value
        if (currentState == ConnectionState.DISCOVERING || currentState == ConnectionState.CONNECTED || currentState == ConnectionState.NODE_FOUND || currentState == ConnectionState.VALIDATING) return

        val activeNetwork = connectivityManager?.activeNetwork
        val caps = connectivityManager?.getNetworkCapabilities(activeNetwork)
        val hasNetwork = caps != null && (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) || caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) || caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR))
        
        if (!hasNetwork) {
            _connectionState.value = ConnectionState.NETWORK_UNAVAILABLE
            return
        }

        // Acquire Wi-Fi Multicast Lock to enable mDNS resolution on Android
        try {
            val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
            wifiMulticastLock = wm?.createMulticastLock("CyberGuardMulticastLock")?.apply {
                setReferenceCounted(true)
                acquire()
            }
        } catch (e: Exception) {
            Log.w("ConnectionManager", "Multicast lock notice: ${e.message}")
        }

        _connectionState.value = ConnectionState.DISCOVERING
        isResolving = false

        // Timeout mechanism: 10s safety net that automatically triggers cloud backend fallback
        discoveryJob?.cancel()
        discoveryJob = CoroutineScope(Dispatchers.Main).launch {
            delay(10000)
            if (_connectionState.value == ConnectionState.DISCOVERING) {
                Log.i("ConnectionManager", "Discovery timeout reached. Auto-switching to cloud defense node...")
                discoveryStatus.value = "AUTO-SWITCHING TO CLOUD NODE..."
                connectToDeployedBackend()
            }
        }

        // Stage 1 & 2: Autonomous Local Host Probe -> Cloud Failover
        subnetProbeJob?.cancel()
        subnetProbeJob = CoroutineScope(Dispatchers.IO).launch {
            discoveryStatus.value = "PROBING AUTO-DETECTED HOST CANDIDATE..."

            val localCandidates = mutableListOf<String>()

            // 1. Hotspot peers from ARP table
            val hotspotClients = getHotspotClientIps()
            localCandidates.addAll(hotspotClients)

            // 2. Gateway IP (PC hotspot or router)
            val gw = getDetectedGatewayOrHostIp()
            if (!gw.isNullOrBlank() && !localCandidates.contains(gw)) {
                localCandidates.add(gw)
            }

            // 3. Last known local host from prefs
            val prefs = context.getSharedPreferences("cyberguard_prefs", Context.MODE_PRIVATE)
            val lastHost = prefs.getString("last_host_ip", null)
            if (!lastHost.isNullOrBlank() && !isCloudUrl(lastHost) && !localCandidates.contains(lastHost)) {
                localCandidates.add(0, lastHost)
            }

            // 4. Android emulator candidate
            if (!localCandidates.contains("10.0.2.2")) {
                localCandidates.add("10.0.2.2")
            }

            var localFound: String? = null
            for (candidate in localCandidates) {
                if (_connectionState.value != ConnectionState.DISCOVERING) return@launch
                discoveryStatus.value = "CHECKING CANDIDATE $candidate:3000..."
                if (quickCheckEndpoint(candidate, 3000, timeoutMs = 1200)) {
                    localFound = candidate
                    break
                }
            }

            // If direct candidates (gateway/last host) are unavailable, fast-probe subnet priority IPs in parallel
            if (localFound == null && _connectionState.value == ConnectionState.DISCOVERING) {
                val localIp = getLocalIpAddress()
                if (!localIp.isNullOrBlank()) {
                    val prefix = localIp.substringBeforeLast(".")
                    if (prefix != "192.0.0" && prefix != "127.0.0") {
                        val prioritySuffixes = listOf(2, 3, 100, 101, 102, 103, 141, 205, 50, 254)
                        val subnetCandidates = prioritySuffixes.map { "$prefix.$it" }.filter { it != localIp && !localCandidates.contains(it) }
                        
                        discoveryStatus.value = "FAST-PROBING SUBNET $prefix.0/24..."
                        val deferreds = subnetCandidates.map { ip ->
                            async {
                                if (quickCheckEndpoint(ip, 3000, timeoutMs = 800)) ip else null
                            }
                        }
                        val foundOnSubnet = deferreds.awaitAll().filterNotNull().firstOrNull()
                        if (foundOnSubnet != null) {
                            localFound = foundOnSubnet
                        }
                    }
                }
            }

            if (localFound != null) {
                Log.i("ConnectionManager", "Auto-detected host candidate verified: $localFound:3000")
                withContext(Dispatchers.Main) {
                    if (_connectionState.value == ConnectionState.DISCOVERING) {
                        _connectionState.value = ConnectionState.NODE_FOUND
                        discoveryStatus.value = "LOCAL HOST FOUND // CONNECTING..."
                        connectToServer(localFound, 3000)
                    }
                }
                return@launch
            }

            // Stage 2: Local candidates unavailable -> Auto-switch internally to Deployed Cloud Node!
            Log.i("ConnectionManager", "No local candidate responding on port 3000. Auto-switching to Deployed Cloud Node...")
            withContext(Dispatchers.Main) {
                if (_connectionState.value == ConnectionState.DISCOVERING) {
                    discoveryStatus.value = "LOCAL OFFLINE // AUTO-SWITCHING TO CLOUD NODE..."
                    connectToDeployedBackend()
                }
            }
        }

        // Standard mDNS / DNS-SD Service Discovery
        nsdManager = context.getSystemService(Context.NSD_SERVICE) as NsdManager
        
        discoveryListener = object : NsdManager.DiscoveryListener {
            override fun onDiscoveryStarted(regType: String) {
                Log.d("ConnectionManager", "Service discovery started")
            }

            override fun onServiceFound(service: NsdServiceInfo) {
                Log.d("ConnectionManager", "Service found: ${service.serviceName}")
                if (service.serviceType.contains("_cyberguard._tcp") || service.serviceType.contains("_voiceguard._tcp")) {
                    if (isResolving) return
                    isResolving = true
                    
                    CoroutineScope(Dispatchers.Main).launch {
                        if (_connectionState.value == ConnectionState.DISCOVERING) {
                            _connectionState.value = ConnectionState.NODE_FOUND
                        }
                    }

                    try {
                        nsdManager?.resolveService(service, object : NsdManager.ResolveListener {
                            override fun onResolveFailed(serviceInfo: NsdServiceInfo, errorCode: Int) {
                                Log.e("ConnectionManager", "Resolve failed: $errorCode")
                                isResolving = false
                            }

                            override fun onServiceResolved(serviceInfo: NsdServiceInfo) {
                                isResolving = false
                                val host = serviceInfo.host.hostAddress
                                val port = serviceInfo.port
                                Log.d("ConnectionManager", "Resolved service: $host:$port")
                                if (host != null) {
                                    CoroutineScope(Dispatchers.Main).launch {
                                        connectToServer(host, port)
                                    }
                                }
                            }
                        })
                    } catch (e: Exception) {
                        Log.e("ConnectionManager", "Exception during resolveService", e)
                        isResolving = false
                    }
                }
            }

            override fun onServiceLost(service: NsdServiceInfo) {
                Log.e("ConnectionManager", "Service lost: $service")
                if (_connectionState.value == ConnectionState.CONNECTED) {
                    _connectionState.value = ConnectionState.DISCONNECTED
                    _serverUrl.value = null
                    api = null
                }
            }

            override fun onDiscoveryStopped(serviceType: String) {
                Log.i("ConnectionManager", "Discovery stopped: $serviceType")
            }

            override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) {
                Log.e("ConnectionManager", "Discovery failed: Error code:$errorCode")
                CoroutineScope(Dispatchers.Main).launch {
                    _connectionState.value = ConnectionState.ERROR
                }
                stopDiscovery()
            }

            override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) {
                Log.e("ConnectionManager", "Stop discovery failed: Error code:$errorCode")
                stopDiscovery()
            }
        }
        
        try {
            nsdManager?.discoverServices(SERVICE_TYPE, NsdManager.PROTOCOL_DNS_SD, discoveryListener)
        } catch (e: Exception) {
            _connectionState.value = ConnectionState.ERROR
            Log.e("ConnectionManager", "Failed to start discovery", e)
        }
    }

    fun connectManually(hostOrUrl: String, port: Int = 3000) {
        stopDiscovery()
        connectToServer(hostOrUrl, port)
    }

    fun connectToDeployedBackend(url: String = DEFAULT_CLOUD_BACKEND_URL) {
        stopDiscovery()
        connectToServer(url, 443)
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

                // Check common PC host indices first
                val prioritySuffixes = listOf(205, 1, 2, 3, 100, 101, 102, 103, 104, 105, 50, 254)
                for (s in prioritySuffixes) {
                    val candidate = "$prefix.$s"
                    if (candidate != localIp && quickCheckEndpoint(candidate, 3000)) {
                        withContext(Dispatchers.Main) { onFound(candidate) }
                        return@launch
                    }
                }

                // Parallel batch scan across all remaining IPs in subnet
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

    fun connectToServer(hostOrUrl: String, port: Int = 3000) {
        if (_connectionState.value == ConnectionState.CONNECTED) return
        
        discoveryJob?.cancel()
        subnetProbeJob?.cancel()
        _connectionState.value = ConnectionState.VALIDATING
        
        val url = formatEndpointUrl(hostOrUrl, port)
        val isCloud = isCloudUrl(url)
        
        CoroutineScope(Dispatchers.IO).launch {
            try {
                var isHealthy = false
                var responseCode = 0

                val executeHttpCheck: (String) -> Int = { targetUrl ->
                    var conn: HttpURLConnection? = null
                    try {
                        val httpUrl = URL(targetUrl)
                        conn = httpUrl.openConnection() as HttpURLConnection
                        conn.instanceFollowRedirects = true
                        conn.connectTimeout = 4000
                        conn.readTimeout = 4000
                        conn.requestMethod = "GET"
                        conn.setRequestProperty("User-Agent", "CyberGuard-Android/1.0")
                        conn.setRequestProperty("Accept", "application/json, text/html, */*")
                        conn.connect()
                        conn.responseCode
                    } finally {
                        try { conn?.disconnect() } catch (ignored: Exception) {}
                    }
                }

                try {
                    responseCode = executeHttpCheck("${url}health")
                    if (responseCode in 200..299) {
                        isHealthy = true
                    }
                } catch (e: Exception) {
                    if (!isCloud) throw e
                }

                // Cloud fallback check: health.json or root /
                if (!isHealthy && isCloud) {
                    try {
                        val codeJson = executeHttpCheck("${url}health.json")
                        if (codeJson in 200..299) {
                            isHealthy = true
                        } else {
                            val codeRoot = executeHttpCheck(url)
                            if (codeRoot in 200..299) {
                                isHealthy = true
                            }
                        }
                    } catch (e: Exception) {
                        Log.w("ConnectionManager", "Cloud health probe fallback notice: ${e.message}")
                    }
                }

                if (isHealthy) {
                    withContext(Dispatchers.Main) {
                        _serverUrl.value = url
                        val retrofit = Retrofit.Builder()
                            .baseUrl(url)
                            .client(okHttpClient)
                            .addConverterFactory(GsonConverterFactory.create())
                            .build()
                        
                        api = retrofit.create(CyberGuardApi::class.java)
                        _connectionState.value = ConnectionState.CONNECTED
                        discoveryStatus.value = if (isCloud) "CLOUD DEFENSE UPLINK SYNCHRONIZED" else "LOCAL WORKSTATION NODE CONNECTED"
                        
                        // Persist successful host in preferences for instant subsequent reconnects
                        val prefs = context.getSharedPreferences("cyberguard_prefs", Context.MODE_PRIVATE)
                        prefs.edit()
                            .putString("last_host_ip", hostOrUrl)
                            .putInt("last_host_port", port)
                            .putString("server_url", url)
                            .apply()

                        stopDiscovery()
                    }
                } else {
                    Log.e("ConnectionManager", "Health check failed with code $responseCode for $url")
                    if (!isCloud) {
                        // Local host candidate unhealthy -> auto switch internally to Deployed Cloud Node!
                        Log.i("ConnectionManager", "Local host unhealthy ($responseCode). Auto-switching to deployed cloud node...")
                        withContext(Dispatchers.Main) {
                            discoveryStatus.value = "LOCAL NODE UNHEALTHY // AUTO-SWITCHING TO CLOUD NODE..."
                        }
                        connectToDeployedBackend()
                    } else {
                        withContext(Dispatchers.Main) {
                            _connectionState.value = ConnectionState.BACKEND_UNHEALTHY
                        }
                    }
                }
            } catch (e: java.net.ConnectException) {
                Log.e("ConnectionManager", "Backend unreachable (Connection Refused): ${e.message}")
                if (!isCloud) {
                    // Local host port 3000 refused -> auto switch internally to Deployed Cloud Node!
                    Log.i("ConnectionManager", "Local host port 3000 refused. Auto-switching to deployed cloud node...")
                    withContext(Dispatchers.Main) {
                        discoveryStatus.value = "PORT 3000 CLOSED // AUTO-SWITCHING TO CLOUD NODE..."
                    }
                    connectToDeployedBackend()
                } else {
                    withContext(Dispatchers.Main) {
                        _connectionState.value = ConnectionState.BACKEND_UNREACHABLE
                    }
                }
            } catch (e: java.net.SocketTimeoutException) {
                Log.e("ConnectionManager", "Backend unreachable (Timeout): ${e.message}")
                if (!isCloud) {
                    // Local host timed out -> auto switch internally to Deployed Cloud Node!
                    Log.i("ConnectionManager", "Local host timed out. Auto-switching to deployed cloud node...")
                    withContext(Dispatchers.Main) {
                        discoveryStatus.value = "LOCAL TIMEOUT // AUTO-SWITCHING TO CLOUD NODE..."
                    }
                    connectToDeployedBackend()
                } else {
                    withContext(Dispatchers.Main) {
                        _connectionState.value = ConnectionState.BACKEND_UNREACHABLE
                    }
                }
            } catch (e: Exception) {
                Log.e("ConnectionManager", "Failed to connect to server: ${e.message}", e)
                if (!isCloud) {
                    // Local host failed -> auto switch internally to Deployed Cloud Node!
                    Log.i("ConnectionManager", "Local candidate error. Auto-switching to deployed cloud node...")
                    withContext(Dispatchers.Main) {
                        discoveryStatus.value = "LOCAL OFFLINE // AUTO-SWITCHING TO CLOUD NODE..."
                    }
                    connectToDeployedBackend()
                } else {
                    withContext(Dispatchers.Main) {
                        _connectionState.value = ConnectionState.ERROR
                    }
                }
            }
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
        networkCallback?.let { 
            try {
                connectivityManager?.unregisterNetworkCallback(it)
            } catch (e: Exception) {}
        }
    }
}

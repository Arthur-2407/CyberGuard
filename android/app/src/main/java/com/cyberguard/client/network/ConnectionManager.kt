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

    private fun quickCheckEndpoint(host: String, port: Int): Boolean {
        return try {
            val url = URL("http://$host:$port/health")
            val conn = url.openConnection() as HttpURLConnection
            conn.connectTimeout = 1800
            conn.readTimeout = 1800
            conn.requestMethod = "GET"
            conn.connect()
            val code = conn.responseCode
            conn.disconnect()
            code == 200
        } catch (e: Exception) {
            false
        }
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

        // Timeout mechanism: 12 seconds with progressive status updates
        discoveryJob?.cancel()
        discoveryJob = CoroutineScope(Dispatchers.Main).launch {
            delay(12000)
            if (_connectionState.value == ConnectionState.DISCOVERING) {
                Log.e("ConnectionManager", "Discovery timed out")
                _connectionState.value = ConnectionState.DISCOVERY_TIMEOUT
                stopDiscovery()
            }
        }

        // Parallel Subnet & Gateway Fast-Probe
        subnetProbeJob?.cancel()
        subnetProbeJob = CoroutineScope(Dispatchers.IO).launch {
            // Priority 1: Check last successfully connected host
            val prefs = context.getSharedPreferences("cyberguard_prefs", Context.MODE_PRIVATE)
            val lastHost = prefs.getString("last_host_ip", null)
            val lastPort = prefs.getInt("last_host_port", 3000)
            if (!lastHost.isNullOrBlank()) {
                discoveryStatus.value = "PROBING LAST KNOWN NODE: $lastHost:$lastPort..."
                if (quickCheckEndpoint(lastHost, lastPort)) {
                    withContext(Dispatchers.Main) {
                        if (_connectionState.value == ConnectionState.DISCOVERING) {
                            _connectionState.value = ConnectionState.NODE_FOUND
                            connectToServer(lastHost, lastPort)
                        }
                    }
                    return@launch
                }
            }

            // Priority 2: Check emulator / loopback hosts if in dev or simulator
            val emuCandidates = listOf("10.0.2.2", "127.0.0.1")
            for (emu in emuCandidates) {
                if (emu != lastHost && quickCheckEndpoint(emu, 3000)) {
                    withContext(Dispatchers.Main) {
                        if (_connectionState.value == ConnectionState.DISCOVERING) {
                            _connectionState.value = ConnectionState.NODE_FOUND
                            connectToServer(emu, 3000)
                        }
                    }
                    return@launch
                }
            }

            // Priority 3: Check default gateway IP (e.g. 192.168.137.1)
            val gw = getDetectedGatewayOrHostIp()
            if (!gw.isNullOrBlank() && gw != lastHost && !emuCandidates.contains(gw)) {
                discoveryStatus.value = "PROBING GATEWAY HOST: $gw:3000..."
                if (quickCheckEndpoint(gw, 3000)) {
                    withContext(Dispatchers.Main) {
                        if (_connectionState.value == ConnectionState.DISCOVERING) {
                            _connectionState.value = ConnectionState.NODE_FOUND
                            connectToServer(gw, 3000)
                        }
                    }
                    return@launch
                }
            }

            // Priority 4: Probe local subnet priority host indices
            val localIp = getLocalIpAddress()
            if (!localIp.isNullOrBlank()) {
                val prefix = localIp.substringBeforeLast(".")
                discoveryStatus.value = "SCANNING SUBNET $prefix.0/24..."
                val prioritySuffixes = listOf(1, 2, 3, 100, 101, 102, 103, 104, 105, 50, 254)
                for (suffix in prioritySuffixes) {
                    if (_connectionState.value != ConnectionState.DISCOVERING) return@launch
                    val candidate = "$prefix.$suffix"
                    if (candidate != localIp && quickCheckEndpoint(candidate, 3000)) {
                        withContext(Dispatchers.Main) {
                            if (_connectionState.value == ConnectionState.DISCOVERING) {
                                _connectionState.value = ConnectionState.NODE_FOUND
                                connectToServer(candidate, 3000)
                            }
                        }
                        return@launch
                    }
                }
            }
            discoveryStatus.value = "AWAITING BROADCAST BEACON..."
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

    fun connectManually(host: String, port: Int) {
        stopDiscovery()
        connectToServer(host, port)
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

    private fun connectToServer(host: String, port: Int) {
        if (_connectionState.value == ConnectionState.CONNECTED) return
        
        discoveryJob?.cancel()
        subnetProbeJob?.cancel()
        _connectionState.value = ConnectionState.VALIDATING
        
        val url = "http://$host:$port/"
        
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val httpUrl = URL("${url}health")
                val connection = httpUrl.openConnection() as HttpURLConnection
                connection.connectTimeout = 3000
                connection.readTimeout = 3000
                connection.requestMethod = "GET"
                connection.connect()
                
                val responseCode = connection.responseCode
                if (responseCode == 200) {
                    withContext(Dispatchers.Main) {
                        _serverUrl.value = url
                        val retrofit = Retrofit.Builder()
                            .baseUrl(url)
                            .client(okHttpClient)
                            .addConverterFactory(GsonConverterFactory.create())
                            .build()
                        
                        api = retrofit.create(CyberGuardApi::class.java)
                        _connectionState.value = ConnectionState.CONNECTED
                        
                        // Persist successful host in preferences for instant subsequent reconnects
                        val prefs = context.getSharedPreferences("cyberguard_prefs", Context.MODE_PRIVATE)
                        prefs.edit().putString("last_host_ip", host).putInt("last_host_port", port).apply()

                        stopDiscovery()
                    }
                } else {
                    withContext(Dispatchers.Main) {
                        Log.e("ConnectionManager", "Health check failed with code $responseCode")
                        _connectionState.value = ConnectionState.BACKEND_UNHEALTHY
                    }
                }
                connection.disconnect()
            } catch (e: java.net.ConnectException) {
                Log.e("ConnectionManager", "Backend unreachable (Connection Refused)", e)
                withContext(Dispatchers.Main) {
                    _connectionState.value = ConnectionState.BACKEND_UNREACHABLE
                }
            } catch (e: java.net.SocketTimeoutException) {
                Log.e("ConnectionManager", "Backend unreachable (Timeout)", e)
                withContext(Dispatchers.Main) {
                    _connectionState.value = ConnectionState.BACKEND_UNREACHABLE
                }
            } catch (e: Exception) {
                Log.e("ConnectionManager", "Failed to connect to server", e)
                withContext(Dispatchers.Main) {
                    _connectionState.value = ConnectionState.ERROR
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

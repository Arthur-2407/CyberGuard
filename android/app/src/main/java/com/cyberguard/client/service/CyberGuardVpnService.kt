package com.cyberguard.client.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.*
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import com.cyberguard.client.MainActivity
import com.cyberguard.client.model.CallMonitorRepository
import com.cyberguard.client.model.InterceptedDomainEvent
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.SocketTimeoutException
import java.nio.ByteBuffer

/**
 * CyberGuardVpnService — Transparent Local DNS Domain Filtering Service.
 *
 * Capabilities & Boundary Guarantees:
 * - Operates strictly via Android's supported VpnService API with explicit user consent.
 * - Enforces DNS-level domain filtering against CyberGuard's verified phishing and malicious indicator matrix.
 * - Does NOT intercept or decrypt TLS/HTTPS traffic or install custom CA certificates (truthful DNS-level boundary).
 * - Routes local DNS lookups locally: cleanly synthesizes NXDOMAIN/sinkhole for blocked malicious domains.
 * - Transmits zero personal browsing content, form data, or credentials to external servers.
 * - Recovers safely across network handoffs; terminates cleanly when user stops protection.
 * - Complies with Android 14+ foreground service specifications (FOREGROUND_SERVICE_SPECIAL_USE).
 */
class CyberGuardVpnService : VpnService() {

    companion object {
        private const val TAG = "CyberGuardVpn"
        private const val NOTIFICATION_CHANNEL_ID = "cyberguard_vpn_status_channel"
        private const val NOTIFICATION_ID = 91101
        const val VPN_DNS_PORT = 53
        const val SINKHOLE_IP = "127.0.0.1"

        const val ACTION_START_VPN = "com.cyberguard.client.START_VPN"
        const val ACTION_STOP_VPN = "com.cyberguard.client.STOP_VPN"

        fun start(context: Context) {
            val intent = Intent(context, CyberGuardVpnService::class.java).apply {
                action = ACTION_START_VPN
            }
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    context.startForegroundService(intent)
                } else {
                    context.startService(intent)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to initiate VPN service start: ${e.message}", e)
            }
        }

        fun stop(context: Context) {
            val intent = Intent(context, CyberGuardVpnService::class.java).apply {
                action = ACTION_STOP_VPN
            }
            try {
                context.startService(intent)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to initiate VPN service stop: ${e.message}", e)
            }
        }
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    @Volatile
    private var isRunning = false
    private var vpnJob: Job? = null
    private val vpnScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action
        if (action == ACTION_STOP_VPN) {
            stopVpn()
            return START_NOT_STICKY
        }

        try {
            createNotificationChannel()
            val notification = buildForegroundNotification()
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startForeground(
                    NOTIFICATION_ID,
                    notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
                )
            } else {
                startForeground(NOTIFICATION_ID, notification)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to enter foreground mode: ${e.message}", e)
            stopVpn()
            return START_NOT_STICKY
        }

        startVpn()
        // Use START_NOT_STICKY to guarantee the system does not recreate the service
        // without explicit user activity intent after an unexpected termination.
        return START_NOT_STICKY
    }

    override fun onRevoke() {
        Log.i(TAG, "CyberGuard VPN permission revoked by user or system.")
        stopVpn()
        super.onRevoke()
    }

    private fun updateUnderlyingNetworks(cm: ConnectivityManager?) {
        try {
            val physicalNetworks = mutableListOf<Network>()
            cm?.allNetworks?.forEach { net ->
                val caps = cm.getNetworkCapabilities(net) ?: return@forEach
                if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                    !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                ) {
                    physicalNetworks.add(net)
                }
            }
            if (physicalNetworks.isNotEmpty()) {
                setUnderlyingNetworks(physicalNetworks.toTypedArray())
                Log.d(TAG, "Synchronized ${physicalNetworks.size} underlying physical network(s) with VPN interface.")
            } else {
                setUnderlyingNetworks(null)
            }
        } catch (e: Exception) {
            Log.d(TAG, "Underlying networks notice: ${e.message}")
        }
    }

    private fun registerNetworkMonitor() {
        try {
            val cm = applicationContext.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            updateUnderlyingNetworks(cm)

            val request = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .build()

            networkCallback = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    updateUnderlyingNetworks(cm)
                }
                override fun onLost(network: Network) {
                    updateUnderlyingNetworks(cm)
                }
                override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                    updateUnderlyingNetworks(cm)
                }
                override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
                    updateUnderlyingNetworks(cm)
                }
            }
            cm?.registerNetworkCallback(request, networkCallback!!)
        } catch (e: Exception) {
            Log.w(TAG, "Network monitor registration notice: ${e.message}")
        }
    }

    private fun startVpn() {
        if (isRunning) return
        isRunning = true

        val repo = CallMonitorRepository.getInstance(applicationContext)
        repo.setVpnShieldArmed(true)
        registerNetworkMonitor()

        vpnJob?.cancel()
        vpnJob = vpnScope.launch {
            try {
                // Configure virtual network interface for transparent local domain filtering
                val builder = Builder()
                    .setSession("CyberGuard Local Domain Shield")
                    .addAddress("10.0.0.2", 32)
                    .addDnsServer("10.0.0.2") // Direct device DNS queries to virtual interface
                    .addRoute("10.0.0.2", 32)  // Route DNS queries destined to 10.0.0.2 into TUN
                    .setMtu(1500)

                // Critical: Disallow CyberGuard app itself so its own API, health-checks,
                // and streaming uplinks route directly over the physical network.
                try {
                    builder.addDisallowedApplication(applicationContext.packageName)
                    Log.i(TAG, "Exempted ${applicationContext.packageName} from VPN routing.")
                } catch (pkgEx: Exception) {
                    Log.w(TAG, "Disallowed application configuration notice: ${pkgEx.message}")
                }

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    builder.setMetered(false)
                }

                vpnInterface = builder.establish()
                if (vpnInterface == null) {
                    Log.e(TAG, "Failed to establish VPN interface descriptor. User consent required.")
                    withContext(Dispatchers.Main) {
                        stopVpn()
                    }
                    return@launch
                }

                Log.i(TAG, "CyberGuard Local Domain Shield active. Intercepting DNS queries for malicious domains.")
                processPackets(vpnInterface!!)
            } catch (e: Exception) {
                Log.e(TAG, "Error establishing VPN interface: ${e.message}", e)
                withContext(Dispatchers.Main) {
                    stopVpn()
                }
            }
        }
    }

    private suspend fun processPackets(descriptor: ParcelFileDescriptor) = withContext(Dispatchers.IO) {
        val inputStream = FileInputStream(descriptor.fileDescriptor)
        val outputStream = FileOutputStream(descriptor.fileDescriptor)
        val packet = ByteBuffer.allocate(32767)

        val repo = CallMonitorRepository.getInstance(applicationContext)

        while (isRunning && isActive) {
            try {
                val length = inputStream.read(packet.array())
                if (length > 0) {
                    val rawData = packet.array()

                    // Handle TCP probes (e.g. Android Private DNS DoT on port 853 or TCP DNS on port 53)
                    val protocol = rawData[9].toInt() and 0xFF
                    if (protocol == 6 && length >= 28) {
                        val ipHeaderLen = (rawData[0].toInt() and 0x0F) * 4
                        if (length >= ipHeaderLen + 4) {
                            val dstPort = ((rawData[ipHeaderLen + 2].toInt() and 0xFF) shl 8) or
                                    (rawData[ipHeaderLen + 3].toInt() and 0xFF)
                            if (dstPort == 853 || dstPort == 53) {
                                val rst = buildTcpRst(rawData, length)
                                if (rst != null) {
                                    synchronized(outputStream) {
                                        outputStream.write(rst)
                                        outputStream.flush()
                                    }
                                }
                            }
                        }
                        packet.clear()
                        continue
                    }

                    val queriedDomain = parseDnsQueryDomain(rawData, length)
                    if (queriedDomain != null) {
                        if (repo.isDomainBlocked(queriedDomain)) {
                            Log.w(TAG, "[SHIELD ENFORCEMENT] Blocked malicious domain: $queriedDomain")
                            repo.recordInterceptedDomain(
                                InterceptedDomainEvent(
                                    domain = queriedDomain,
                                    reason = "Matched verified threat intelligence indicator in local CyberGuard matrix",
                                    actionTaken = "DNS_SINKHOLE_BLOCKED"
                                )
                            )
                            notifyBlockedThreat(queriedDomain)

                            // Synthesize local sinkhole response (127.0.0.1 A-record)
                            val response = buildSyntheticDnsResponse(rawData, length, SINKHOLE_IP)
                            if (response != null) {
                                synchronized(outputStream) {
                                    outputStream.write(response)
                                    outputStream.flush()
                                }
                            }
                        } else {
                            // Forward legitimate DNS query to upstream resolver via protected socket & DoH fallback
                            val packetCopy = rawData.copyOf(length)
                            vpnScope.launch(Dispatchers.IO) {
                                forwardDnsQuery(
                                    requestPacket = packetCopy,
                                    requestLength = length,
                                    outputStream = outputStream
                                )
                            }
                        }
                    }
                    packet.clear()
                }
            } catch (e: IOException) {
                if (!isRunning) break
                Log.d(TAG, "VPN packet read notice: ${e.message}")
                delay(50)
            } catch (e: Exception) {
                if (!isRunning) break
                Log.w(TAG, "VPN packet processing notice: ${e.message}")
                delay(50)
            }
        }
    }

    /**
     * Forwards an allowed DNS query to upstream DNS resolvers through a protected DatagramSocket.
     * If cellular carriers block UDP port 53, seamlessly falls back to RFC 8484 DNS-over-HTTPS (DoH).
     */
    fun getActiveDnsServers(): List<InetAddress> {
        val servers = mutableListOf<InetAddress>()
        try {
            val cm = applicationContext.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            cm?.allNetworks?.forEach { net ->
                val caps = cm.getNetworkCapabilities(net) ?: return@forEach
                if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                    !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                ) {
                    val lp = cm.getLinkProperties(net)
                    lp?.dnsServers?.forEach { dns ->
                        val host = dns.hostAddress
                        if (!host.isNullOrBlank() && host != "10.0.0.2" && host != "127.0.0.1") {
                            servers.add(dns)
                        }
                    }
                }
            }
        } catch (e: Exception) {
            Log.d(TAG, "Active DNS discovery notice: ${e.message}")
        }
        listOf("1.1.1.1", "8.8.8.8", "1.0.0.1", "8.8.4.4").forEach { ip ->
            try { servers.add(InetAddress.getByName(ip)) } catch (_: Exception) {}
        }
        return servers.distinct()
    }

    private fun forwardDnsQuery(
        requestPacket: ByteArray,
        requestLength: Int,
        outputStream: FileOutputStream
    ) {
        val ipHeaderLen = (requestPacket[0].toInt() and 0x0F) * 4
        val udpHeaderOffset = ipHeaderLen
        val dnsPayloadOffset = udpHeaderOffset + 8
        val dnsPayloadLength = requestLength - dnsPayloadOffset

        if (dnsPayloadLength <= 12) return

        val srcIp = requestPacket.copyOfRange(12, 16)
        val dstIp = requestPacket.copyOfRange(16, 20)
        val srcPort = ((requestPacket[udpHeaderOffset].toInt() and 0xFF) shl 8) or
                (requestPacket[udpHeaderOffset + 1].toInt() and 0xFF)
        val dstPort = ((requestPacket[udpHeaderOffset + 2].toInt() and 0xFF) shl 8) or
                (requestPacket[udpHeaderOffset + 3].toInt() and 0xFF)

        val dnsPayload = requestPacket.copyOfRange(dnsPayloadOffset, requestLength)
        val upstreamIps = getActiveDnsServers()
        var resolved = false

        var socket: DatagramSocket? = null
        try {
            socket = DatagramSocket()
            protect(socket) // CRITICAL: Protect socket so query bypasses the TUN interface
            socket.soTimeout = 900

            for (upstreamAddr in upstreamIps) {
                try {
                    val outPacket = DatagramPacket(dnsPayload, dnsPayload.size, upstreamAddr, VPN_DNS_PORT)
                    socket.send(outPacket)

                    val inBuffer = ByteArray(4096)
                    val inPacket = DatagramPacket(inBuffer, inBuffer.size)
                    socket.receive(inPacket)

                    if (inPacket.length > 12) {
                        val responsePacket = wrapDnsResponse(
                            clientIp = srcIp,
                            clientPort = srcPort,
                            dnsServerIp = dstIp,
                            dnsServerPort = dstPort,
                            dnsPayload = inPacket.data,
                            dnsPayloadLength = inPacket.length
                        )
                        synchronized(outputStream) {
                            outputStream.write(responsePacket)
                            outputStream.flush()
                        }
                        resolved = true
                        return
                    }
                } catch (_: SocketTimeoutException) {
                    continue
                } catch (_: Exception) {
                    continue
                }
            }
        } catch (e: Exception) {
            Log.d(TAG, "UDP forwarding notice: ${e.message}")
        } finally {
            try { socket?.close() } catch (_: Exception) {}
        }

        // Resilient RFC 8484 DNS-over-HTTPS fallback if carrier blocks UDP port 53
        if (!resolved) {
            try {
                val dohResponse = forwardDnsOverHttps(dnsPayload)
                if (dohResponse != null && dohResponse.size > 12) {
                    val responsePacket = wrapDnsResponse(
                        clientIp = srcIp,
                        clientPort = srcPort,
                        dnsServerIp = dstIp,
                        dnsServerPort = dstPort,
                        dnsPayload = dohResponse,
                        dnsPayloadLength = dohResponse.size
                    )
                    synchronized(outputStream) {
                        outputStream.write(responsePacket)
                        outputStream.flush()
                    }
                }
            } catch (dohEx: Exception) {
                Log.d(TAG, "DoH fallback notice: ${dohEx.message}")
            }
        }
    }

    private fun forwardDnsOverHttps(dnsPayload: ByteArray): ByteArray? {
        val dohEndpoints = listOf("https://1.1.1.1/dns-query", "https://dns.google/dns-query")
        for (endpoint in dohEndpoints) {
            try {
                val url = java.net.URL(endpoint)
                val conn = url.openConnection() as java.net.HttpURLConnection
                conn.requestMethod = "POST"
                conn.connectTimeout = 2000
                conn.readTimeout = 2000
                conn.doOutput = true
                conn.setRequestProperty("Content-Type", "application/dns-message")
                conn.setRequestProperty("Accept", "application/dns-message")
                conn.outputStream.use { os ->
                    os.write(dnsPayload)
                    os.flush()
                }
                if (conn.responseCode == 200) {
                    val bytes = conn.inputStream.use { it.readBytes() }
                    conn.disconnect()
                    if (bytes.size > 12) return bytes
                }
                conn.disconnect()
            } catch (_: Exception) {
                continue
            }
        }
        return null
    }

    /**
     * Builds a synthetic IPv4 + UDP + DNS response packet (e.g. Sinkhole 127.0.0.1 or NXDOMAIN).
     */
    fun buildSyntheticDnsResponse(
        data: ByteArray,
        length: Int,
        sinkholeIp: String = SINKHOLE_IP,
        nxdomain: Boolean = false
    ): ByteArray? {
        if (length < 28) return null

        try {
            val ipHeaderLen = (data[0].toInt() and 0x0F) * 4
            val udpOffset = ipHeaderLen
            val dnsOffset = udpOffset + 8

            if (length < dnsOffset + 12) return null

            val srcIp = data.copyOfRange(12, 16)
            val dstIp = data.copyOfRange(16, 20)
            val srcPort = ((data[udpOffset].toInt() and 0xFF) shl 8) or (data[udpOffset + 1].toInt() and 0xFF)
            val dstPort = ((data[udpOffset + 2].toInt() and 0xFF) shl 8) or (data[udpOffset + 3].toInt() and 0xFF)

            val txId0 = data[dnsOffset]
            val txId1 = data[dnsOffset + 1]

            // Determine length of Question section
            var pointer = dnsOffset + 12
            while (pointer < length) {
                val labelLen = data[pointer].toInt() and 0xFF
                if (labelLen == 0) {
                    pointer += 1 // skip null terminator
                    break
                }
                pointer += 1 + labelLen
            }
            pointer += 4 // past QTYPE (2) + QCLASS (2)
            if (pointer > length) return null

            val qLen = pointer - (dnsOffset + 12)
            val questionBytes = data.copyOfRange(dnsOffset + 12, pointer)

            // DNS Header: Flags, QDCOUNT=1, ANCOUNT=(1 if sinkhole else 0), NSCOUNT=0, ARCOUNT=0
            val flags = if (nxdomain) 0x8183 else 0x8180
            val ancount = if (nxdomain) 0 else 1

            val dnsHeader = byteArrayOf(
                txId0, txId1,
                ((flags shr 8) and 0xFF).toByte(), (flags and 0xFF).toByte(),
                0x00.toByte(), 0x01.toByte(), // QDCOUNT = 1
                ((ancount shr 8) and 0xFF).toByte(), (ancount and 0xFF).toByte(),
                0x00.toByte(), 0x00.toByte(), // NSCOUNT = 0
                0x00.toByte(), 0x00.toByte()  // ARCOUNT = 0
            )

            val dnsPayload: ByteArray
            if (!nxdomain) {
                val ipParts = sinkholeIp.split(".")
                val ipBytes = ByteArray(4) { i -> ipParts.getOrNull(i)?.toIntOrNull()?.toByte() ?: 0 }

                // Answer RR: pointer 0xC00C (to QNAME at offset 12), TYPE A (1), CLASS IN (1), TTL 60, RDLENGTH 4, RDATA
                val answer = byteArrayOf(
                    0xC0.toByte(), 0x0C.toByte(),
                    0x00.toByte(), 0x01.toByte(),
                    0x00.toByte(), 0x01.toByte(),
                    0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x3C.toByte(),
                    0x00.toByte(), 0x04.toByte()
                ) + ipBytes
                dnsPayload = dnsHeader + questionBytes + answer
            } else {
                dnsPayload = dnsHeader + questionBytes
            }

            return wrapDnsResponse(
                clientIp = srcIp,
                clientPort = srcPort,
                dnsServerIp = dstIp,
                dnsServerPort = dstPort,
                dnsPayload = dnsPayload,
                dnsPayloadLength = dnsPayload.size
            )
        } catch (_: Exception) {
            return null
        }
    }

    /**
     * Wraps raw DNS payload inside standard IPv4 and UDP response headers.
     */
    fun wrapDnsResponse(
        clientIp: ByteArray,
        clientPort: Int,
        dnsServerIp: ByteArray,
        dnsServerPort: Int,
        dnsPayload: ByteArray,
        dnsPayloadLength: Int
    ): ByteArray {
        val udpLen = 8 + dnsPayloadLength
        val ipLen = 20 + udpLen

        val ipHeader = ByteArray(20)
        ipHeader[0] = 0x45.toByte() // IPv4, IHL = 5 (20 bytes)
        ipHeader[1] = 0x00.toByte() // DSCP/ECN
        ipHeader[2] = ((ipLen shr 8) and 0xFF).toByte()
        ipHeader[3] = (ipLen and 0xFF).toByte()
        ipHeader[4] = 0x12.toByte() // Identification
        ipHeader[5] = 0x34.toByte()
        ipHeader[6] = 0x40.toByte() // Flags: Don't fragment
        ipHeader[7] = 0x00.toByte()
        ipHeader[8] = 64.toByte()   // TTL
        ipHeader[9] = 17.toByte()   // Protocol UDP
        ipHeader[10] = 0x00.toByte()
        ipHeader[11] = 0x00.toByte()

        // Swap IPs: Source is DNS server, Destination is client
        System.arraycopy(dnsServerIp, 0, ipHeader, 12, 4)
        System.arraycopy(clientIp, 0, ipHeader, 16, 4)

        // Compute IPv4 header checksum
        val checksum = computeIpChecksum(ipHeader, 0, 20)
        ipHeader[10] = ((checksum shr 8) and 0xFF).toByte()
        ipHeader[11] = (checksum and 0xFF).toByte()

        val udpHeader = ByteArray(8)
        udpHeader[0] = ((dnsServerPort shr 8) and 0xFF).toByte()
        udpHeader[1] = (dnsServerPort and 0xFF).toByte()
        udpHeader[2] = ((clientPort shr 8) and 0xFF).toByte()
        udpHeader[3] = (clientPort and 0xFF).toByte()
        udpHeader[4] = ((udpLen shr 8) and 0xFF).toByte()
        udpHeader[5] = (udpLen and 0xFF).toByte()
        udpHeader[6] = 0x00.toByte() // UDP checksum is optional in IPv4
        udpHeader[7] = 0x00.toByte()

        val fullPacket = ByteArray(ipLen)
        System.arraycopy(ipHeader, 0, fullPacket, 0, 20)
        System.arraycopy(udpHeader, 0, fullPacket, 20, 8)
        System.arraycopy(dnsPayload, 0, fullPacket, 28, dnsPayloadLength)

        return fullPacket
    }

    /**
     * Computes the RFC 791 16-bit one's complement Internet Checksum for IPv4 headers.
     */
    fun computeIpChecksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0
        var i = offset
        while (i < offset + length) {
            val word = ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            sum += word
            i += 2
        }
        while ((sum shr 16) > 0) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        return sum.inv() and 0xFFFF
    }

    /**
     * Parse standard DNS Question section from UDP packet to extract target domain name.
     */
    fun parseDnsQueryDomain(data: ByteArray, length: Int): String? {
        if (length < 28) return null // Minimum IPv4 + UDP header size

        try {
            // Check IP Version
            val version = (data[0].toInt() shr 4) and 0x0F
            if (version != 4) return null

            val ipHeaderLen = (data[0].toInt() and 0x0F) * 4
            val protocol = data[9].toInt() and 0xFF
            if (protocol != 17) return null // UDP protocol

            val udpHeaderOffset = ipHeaderLen
            if (length < udpHeaderOffset + 8) return null

            val dstPort = ((data[udpHeaderOffset + 2].toInt() and 0xFF) shl 8) or
                    (data[udpHeaderOffset + 3].toInt() and 0xFF)

            // Inspect DNS queries targeting destination port 53
            if (dstPort != VPN_DNS_PORT) return null

            val dnsPayloadOffset = udpHeaderOffset + 8
            if (length < dnsPayloadOffset + 12) return null

            // DNS Header: QDCOUNT (question count)
            val qdCount = ((data[dnsPayloadOffset + 4].toInt() and 0xFF) shl 8) or
                    (data[dnsPayloadOffset + 5].toInt() and 0xFF)
            if (qdCount < 1) return null

            // Read QNAME labels
            var pointer = dnsPayloadOffset + 12
            val domainBuilder = StringBuilder()

            while (pointer < length) {
                val labelLen = data[pointer].toInt() and 0xFF
                if (labelLen == 0) break // End of QNAME

                // RFC 1035 pointer compression check
                if ((labelLen and 0xC0) == 0xC0) {
                    break
                }

                pointer++
                if (pointer + labelLen > length) return null

                if (domainBuilder.isNotEmpty()) {
                    domainBuilder.append(".")
                }

                val label = String(data, pointer, labelLen, Charsets.US_ASCII)
                domainBuilder.append(label)
                pointer += labelLen
            }

            val domain = domainBuilder.toString().lowercase().trim()
            return if (domain.isNotEmpty()) domain else null
        } catch (_: Exception) {
            return null
        }
    }

    private fun stopVpn() {
        isRunning = false
        vpnJob?.cancel()
        vpnJob = null

        networkCallback?.let {
            try {
                val cm = applicationContext.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
                cm?.unregisterNetworkCallback(it)
            } catch (e: Exception) {
                Log.d(TAG, "Unregister network callback notice: ${e.message}")
            }
            networkCallback = null
        }

        try {
            vpnInterface?.close()
            vpnInterface = null
        } catch (e: Exception) {
            Log.d(TAG, "Interface close notice: ${e.message}")
        }

        val repo = CallMonitorRepository.getInstance(applicationContext)
        repo.setVpnShieldArmed(false)

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                stopForeground(STOP_FOREGROUND_REMOVE)
            } else {
                @Suppress("DEPRECATION")
                stopForeground(true)
            }
        } catch (e: Exception) {
            Log.d(TAG, "Stop foreground notice: ${e.message}")
        }
        stopSelf()
        Log.i(TAG, "CyberGuard Local Domain Shield stopped.")
    }

    /**
     * Synthesizes a valid TCP RST | ACK packet to immediately reject TCP probes (port 853 DoT or port 53).
     * Prevents Android Private DNS probes from stalling internet access.
     */
    fun buildTcpRst(data: ByteArray, length: Int): ByteArray? {
        if (length < 28) return null
        try {
            val version = (data[0].toInt() shr 4) and 0x0F
            if (version != 4) return null
            val ipHeaderLen = (data[0].toInt() and 0x0F) * 4
            if (length < ipHeaderLen + 20) return null

            val srcIp = data.copyOfRange(12, 16)
            val dstIp = data.copyOfRange(16, 20)
            val srcPort = ((data[ipHeaderLen].toInt() and 0xFF) shl 8) or (data[ipHeaderLen + 1].toInt() and 0xFF)
            val dstPort = ((data[ipHeaderLen + 2].toInt() and 0xFF) shl 8) or (data[ipHeaderLen + 3].toInt() and 0xFF)
            val seqNum = ((data[ipHeaderLen + 4].toLong() and 0xFF) shl 24) or
                    ((data[ipHeaderLen + 5].toLong() and 0xFF) shl 16) or
                    ((data[ipHeaderLen + 6].toLong() and 0xFF) shl 8) or
                    (data[ipHeaderLen + 7].toLong() and 0xFF)

            val totalLen = 40 // 20 IP + 20 TCP
            val out = ByteArray(totalLen)

            // IPv4 Header
            out[0] = 0x45.toByte()
            out[1] = 0x00.toByte()
            out[2] = 0x00.toByte()
            out[3] = 40.toByte()
            out[4] = 0x00.toByte()
            out[5] = 0x00.toByte()
            out[6] = 0x40.toByte()
            out[7] = 0x00.toByte()
            out[8] = 64.toByte()   // TTL
            out[9] = 6.toByte()    // Protocol 6 = TCP
            System.arraycopy(dstIp, 0, out, 12, 4) // Swap IPs: server -> client
            System.arraycopy(srcIp, 0, out, 16, 4)
            val ipChecksum = computeIpChecksum(out, 0, 20)
            out[10] = ((ipChecksum shr 8) and 0xFF).toByte()
            out[11] = (ipChecksum and 0xFF).toByte()

            // TCP Header (offset 20)
            out[20] = ((dstPort shr 8) and 0xFF).toByte()
            out[21] = (dstPort and 0xFF).toByte()
            out[22] = ((srcPort shr 8) and 0xFF).toByte()
            out[23] = (srcPort and 0xFF).toByte()

            // Sequence number = 0
            out[24] = 0; out[25] = 0; out[26] = 0; out[27] = 0
            // Acknowledgment number = incoming seq + 1
            val ackNum = (seqNum + 1) and 0xFFFFFFFFL
            out[28] = ((ackNum shr 24) and 0xFF).toByte()
            out[29] = ((ackNum shr 16) and 0xFF).toByte()
            out[30] = ((ackNum shr 8) and 0xFF).toByte()
            out[31] = (ackNum and 0xFF).toByte()

            out[32] = 0x50.toByte() // Data offset 5 (20 bytes)
            out[33] = 0x14.toByte() // Flags: RST | ACK
            out[34] = 0x00.toByte() // Window 0
            out[35] = 0x00.toByte()

            // Compute TCP checksum with pseudo-header
            var sum = 0
            sum += ((dstIp[0].toInt() and 0xFF) shl 8) or (dstIp[1].toInt() and 0xFF)
            sum += ((dstIp[2].toInt() and 0xFF) shl 8) or (dstIp[3].toInt() and 0xFF)
            sum += ((srcIp[0].toInt() and 0xFF) shl 8) or (srcIp[1].toInt() and 0xFF)
            sum += ((srcIp[2].toInt() and 0xFF) shl 8) or (srcIp[3].toInt() and 0xFF)
            sum += 6 // Protocol TCP
            sum += 20 // TCP Length

            var i = 20
            while (i < 40) {
                if (i != 36) { // skip checksum field itself
                    val word = ((out[i].toInt() and 0xFF) shl 8) or (out[i + 1].toInt() and 0xFF)
                    sum += word
                }
                i += 2
            }
            while ((sum shr 16) > 0) {
                sum = (sum and 0xFFFF) + (sum shr 16)
            }
            val tcpChecksum = sum.inv() and 0xFFFF
            out[36] = ((tcpChecksum shr 8) and 0xFF).toByte()
            out[37] = (tcpChecksum and 0xFF).toByte()

            return out
        } catch (_: Exception) {
            return null
        }
    }

    override fun onDestroy() {
        stopVpn()
        vpnScope.cancel()
        super.onDestroy()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                "CyberGuard Real-Time Protection",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Status of real-time website and domain filtering shield"
                setShowBadge(false)
            }
            val nm = getSystemService(NotificationManager::class.java)
            nm?.createNotificationChannel(channel)
        }
    }

    private fun buildForegroundNotification(): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or (if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) PendingIntent.FLAG_IMMUTABLE else 0)
        )

        return NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle("CyberGuard Domain Shield Active")
            .setContentText("DNS domain filtering active. Zero tracking of encrypted web payload.")
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    private fun notifyBlockedThreat(domain: String) {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager ?: return
        val notif = NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle("Malicious Domain Intercepted")
            .setContentText("CyberGuard blocked connection to: $domain")
            .setStyle(
                NotificationCompat.BigTextStyle()
                    .bigText("Attempted connection to '$domain' was intercepted and neutralized. Matched verified phishing threat matrix.")
            )
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .build()
        nm.notify(domain.hashCode(), notif)
    }
}

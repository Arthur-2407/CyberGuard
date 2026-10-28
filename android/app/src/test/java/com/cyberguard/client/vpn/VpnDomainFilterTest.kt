package com.cyberguard.client.vpn

import com.cyberguard.client.service.CyberGuardVpnService
import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayOutputStream

/**
 * Unit verification tests for CyberGuard Android VPN Local Domain Filtering.
 */
class VpnDomainFilterTest {

    private val vpnService = CyberGuardVpnService()

    /**
     * Helper to construct a synthetic IPv4 + UDP DNS query packet targeting port 53.
     */
    private fun createSyntheticDnsQueryPacket(
        domain: String,
        srcIp: ByteArray = byteArrayOf(10, 0, 0, 2),
        dstIp: ByteArray = byteArrayOf(1, 1, 1, 1),
        srcPort: Int = 49153,
        dstPort: Int = 53
    ): ByteArray {
        val out = ByteArrayOutputStream()

        // 1. IPv4 Header (20 bytes)
        out.write(0x45) // Version 4, IHL 5 (20 bytes)
        out.write(0x00) // DSCP/ECN
        val totalLength = 20 + 8 + 12 + domain.length + 2 + 4
        out.write((totalLength shr 8) and 0xFF)
        out.write(totalLength and 0xFF)
        out.write(0x12); out.write(0x34) // Identification
        out.write(0x40); out.write(0x00) // Flags: Don't fragment
        out.write(64)   // TTL
        out.write(17)   // Protocol 17 = UDP
        out.write(0x00); out.write(0x00) // Header checksum (mocked)
        out.write(srcIp) // Source IP
        out.write(dstIp) // Destination IP

        // 2. UDP Header (8 bytes)
        out.write((srcPort shr 8) and 0xFF)
        out.write(srcPort and 0xFF)
        out.write((dstPort shr 8) and 0xFF)
        out.write(dstPort and 0xFF)
        val udpLength = 8 + 12 + domain.length + 2 + 4
        out.write((udpLength shr 8) and 0xFF)
        out.write(udpLength and 0xFF)
        out.write(0x00); out.write(0x00) // UDP Checksum

        // 3. DNS Header (12 bytes)
        out.write(0xAB); out.write(0xCD) // Transaction ID
        out.write(0x01); out.write(0x00) // Flags: Standard query
        out.write(0x00); out.write(0x01) // QDCOUNT = 1
        out.write(0x00); out.write(0x00) // ANCOUNT = 0
        out.write(0x00); out.write(0x00) // NSCOUNT = 0
        out.write(0x00); out.write(0x00) // ARCOUNT = 0

        // 4. DNS Question: QNAME
        for (label in domain.split(".")) {
            out.write(label.length)
            out.write(label.toByteArray(Charsets.US_ASCII))
        }
        out.write(0x00) // Zero label terminator

        // QTYPE (1 = A Record) & QCLASS (1 = IN)
        out.write(0x00); out.write(0x01)
        out.write(0x00); out.write(0x01)

        return out.toByteArray()
    }

    @Test
    fun testParseStandardDnsQuery() {
        val packet = createSyntheticDnsQueryPacket("malware.wicar.org")
        val parsedDomain = vpnService.parseDnsQueryDomain(packet, packet.size)

        assertNotNull(parsedDomain)
        assertEquals("malware.wicar.org", parsedDomain)
    }

    @Test
    fun testParseSubdomainAndCaseNormalization() {
        val packet = createSyntheticDnsQueryPacket("SECURE-PHISHING.SUB.TESTSAFEBROWSING.APPSPOT.COM")
        val parsedDomain = vpnService.parseDnsQueryDomain(packet, packet.size)

        assertNotNull(parsedDomain)
        assertEquals("secure-phishing.sub.testsafebrowsing.appspot.com", parsedDomain)
    }

    @Test
    fun testIgnoreNonDnsUdpTraffic() {
        val packet = createSyntheticDnsQueryPacket("example.com")
        // Alter destination port from 53 to 8080 (offset 20 + 2, 3)
        packet[22] = 0x1F.toByte()
        packet[23] = 0x90.toByte()

        val parsedDomain = vpnService.parseDnsQueryDomain(packet, packet.size)
        assertNull("Non-port 53 packet should be ignored", parsedDomain)
    }

    @Test
    fun testIgnoreNonUdpTraffic() {
        val packet = createSyntheticDnsQueryPacket("example.com")
        // Alter protocol from 17 (UDP) to 6 (TCP) at IP header offset 9
        packet[9] = 6.toByte()

        val parsedDomain = vpnService.parseDnsQueryDomain(packet, packet.size)
        assertNull("TCP packet should be ignored by UDP DNS parser", parsedDomain)
    }

    @Test
    fun testTruncatedPacketReturnsNullSafely() {
        val packet = byteArrayOf(0x45, 0x00, 0x00, 0x14) // Only 4 bytes
        val parsedDomain = vpnService.parseDnsQueryDomain(packet, packet.size)
        assertNull(parsedDomain)
    }

    @Test
    fun testBuildSyntheticSinkholeDnsResponse() {
        val srcIp = byteArrayOf(10, 0, 0, 2)
        val dstIp = byteArrayOf(1, 1, 1, 1)
        val srcPort = 49153
        val dstPort = 53

        val queryPacket = createSyntheticDnsQueryPacket(
            domain = "malware.wicar.org",
            srcIp = srcIp,
            dstIp = dstIp,
            srcPort = srcPort,
            dstPort = dstPort
        )

        val responsePacket = vpnService.buildSyntheticDnsResponse(
            data = queryPacket,
            length = queryPacket.size,
            sinkholeIp = "127.0.0.1",
            nxdomain = false
        )

        assertNotNull("Response packet should be synthesized", responsePacket)
        val resp = responsePacket!!

        // Verify IP Header swapped Source and Destination
        assertEquals(dstIp[0], resp[12])
        assertEquals(dstIp[1], resp[13])
        assertEquals(dstIp[2], resp[14])
        assertEquals(dstIp[3], resp[15])

        assertEquals(srcIp[0], resp[16])
        assertEquals(srcIp[1], resp[17])
        assertEquals(srcIp[2], resp[18])
        assertEquals(srcIp[3], resp[19])

        // Verify UDP Header swapped Ports (Source Port = 53, Dest Port = 49153)
        val respSrcPort = ((resp[20].toInt() and 0xFF) shl 8) or (resp[21].toInt() and 0xFF)
        val respDstPort = ((resp[22].toInt() and 0xFF) shl 8) or (resp[23].toInt() and 0xFF)
        assertEquals(53, respSrcPort)
        assertEquals(srcPort, respDstPort)

        // Verify DNS Header
        val txId = ((resp[28].toInt() and 0xFF) shl 8) or (resp[29].toInt() and 0xFF)
        assertEquals(0xABCD, txId)

        val flags = ((resp[30].toInt() and 0xFF) shl 8) or (resp[31].toInt() and 0xFF)
        assertEquals("Flags should be standard response 0x8180", 0x8180, flags)

        val qdCount = ((resp[32].toInt() and 0xFF) shl 8) or (resp[33].toInt() and 0xFF)
        val anCount = ((resp[34].toInt() and 0xFF) shl 8) or (resp[35].toInt() and 0xFF)
        assertEquals(1, qdCount)
        assertEquals(1, anCount)

        // Verify Answer contains sinkhole IP 127.0.0.1
        val last4Bytes = resp.copyOfRange(resp.size - 4, resp.size)
        assertArrayEquals(byteArrayOf(127, 0, 0, 1), last4Bytes)
    }

    @Test
    fun testBuildSyntheticNxdomainResponse() {
        val queryPacket = createSyntheticDnsQueryPacket("testsafebrowsing.appspot.com")

        val responsePacket = vpnService.buildSyntheticDnsResponse(
            data = queryPacket,
            length = queryPacket.size,
            nxdomain = true
        )

        assertNotNull(responsePacket)
        val resp = responsePacket!!

        val flags = ((resp[30].toInt() and 0xFF) shl 8) or (resp[31].toInt() and 0xFF)
        assertEquals("Flags should indicate NXDOMAIN (0x8183)", 0x8183, flags)

        val anCount = ((resp[34].toInt() and 0xFF) shl 8) or (resp[35].toInt() and 0xFF)
        assertEquals("NXDOMAIN should have 0 answers", 0, anCount)
    }

    @Test
    fun testComputeIpChecksumCorrectness() {
        // Known IPv4 header sample with zeroed checksum field
        val header = byteArrayOf(
            0x45.toByte(), 0x00.toByte(), 0x00.toByte(), 0x3C.toByte(),
            0x1C.toByte(), 0x46.toByte(), 0x40.toByte(), 0x00.toByte(),
            0x40.toByte(), 0x06.toByte(), 0x00.toByte(), 0x00.toByte(), // Checksum at offset 10-11
            0xAC.toByte(), 0x10.toByte(), 0x0A.toByte(), 0x63.toByte(),
            0xAC.toByte(), 0x10.toByte(), 0x0A.toByte(), 0x0C.toByte()
        )

        val computed = vpnService.computeIpChecksum(header, 0, 20)
        assertEquals(0xB1E6, computed)

        // Verifying that inserting computed checksum produces 0 upon re-summing
        header[10] = ((computed shr 8) and 0xFF).toByte()
        header[11] = (computed and 0xFF).toByte()
        val verify = vpnService.computeIpChecksum(header, 0, 20)
        assertEquals(0x0000, verify)
    }

    @Test
    fun testBuildTcpRstForPrivateDnsProbe() {
        val srcIp = byteArrayOf(10, 0, 0, 2)
        val dstIp = byteArrayOf(10, 0, 0, 2)
        val srcPort = 54321
        val dstPort = 853 // Android Private DNS DoT port

        val tcpSyn = ByteArray(40)
        tcpSyn[0] = 0x45.toByte()
        tcpSyn[1] = 0x00.toByte()
        tcpSyn[2] = 0x00.toByte()
        tcpSyn[3] = 40.toByte()
        tcpSyn[8] = 64.toByte()
        tcpSyn[9] = 6.toByte() // TCP
        System.arraycopy(srcIp, 0, tcpSyn, 12, 4)
        System.arraycopy(dstIp, 0, tcpSyn, 16, 4)

        tcpSyn[20] = ((srcPort shr 8) and 0xFF).toByte()
        tcpSyn[21] = (srcPort and 0xFF).toByte()
        tcpSyn[22] = ((dstPort shr 8) and 0xFF).toByte()
        tcpSyn[23] = (dstPort and 0xFF).toByte()
        tcpSyn[24] = 0x00; tcpSyn[25] = 0x01; tcpSyn[26] = 0x02; tcpSyn[27] = 0x03 // Seq = 0x00010203
        tcpSyn[32] = 0x50.toByte()
        tcpSyn[33] = 0x02.toByte() // SYN

        val rst = vpnService.buildTcpRst(tcpSyn, tcpSyn.size)
        assertNotNull("TCP RST packet should be built", rst)
        val res = rst!!

        assertEquals("IP protocol must be TCP (6)", 6.toByte(), res[9])
        val resSrcPort = ((res[20].toInt() and 0xFF) shl 8) or (res[21].toInt() and 0xFF)
        val resDstPort = ((res[22].toInt() and 0xFF) shl 8) or (res[23].toInt() and 0xFF)
        assertEquals("Source port must be 853", dstPort, resSrcPort)
        assertEquals("Dest port must be client port 54321", srcPort, resDstPort)

        // Flags should be RST | ACK (0x14)
        assertEquals("TCP flags must be RST | ACK (0x14)", 0x14.toByte(), res[33])

        // Verify Ack number = incoming Seq + 1
        val ackNum = ((res[28].toLong() and 0xFF) shl 24) or
                ((res[29].toLong() and 0xFF) shl 16) or
                ((res[30].toLong() and 0xFF) shl 8) or
                (res[31].toLong() and 0xFF)
        assertEquals(0x00010204L, ackNum)
    }
}

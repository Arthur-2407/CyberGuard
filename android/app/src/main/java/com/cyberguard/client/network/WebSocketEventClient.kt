package com.cyberguard.client.network

import android.util.Log
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import okhttp3.*
import okio.ByteString
import org.json.JSONObject

sealed class WsEvent {
    object Connected : WsEvent()
    object Disconnected : WsEvent()
    data class RiskUpdate(
        val riskScore: Double, 
        val alertLevel: String,
        val voiceClassification: String = "ANALYZING",
        val detectionScore: Double = 0.0,
        val rms: Double = 0.0,
        val activeDetector: String? = null
    ) : WsEvent()
    data class StatusUpdate(
        val status: String,
        val detail: String = "",
        val rms: Double = 0.0,
        val activeDetector: String? = null
    ) : WsEvent()
    data class SessionStarted(
        val sessionId: String,
        val detectorReady: Boolean,
        val activeDetector: String? = null
    ) : WsEvent()
    data class Error(val status: String, val message: String) : WsEvent()
    data class UnknownMessage(val text: String) : WsEvent()
}

class WebSocketEventClient(
    private val client: OkHttpClient,
    private val serverUrl: String
) {
    private var webSocket: WebSocket? = null
    
    private val _isConnected = MutableStateFlow(false)
    val isConnected: StateFlow<Boolean> = _isConnected
    
    // Use SharedFlow for events so rapid messages aren't dropped
    private val _events = MutableSharedFlow<WsEvent>(extraBufferCapacity = 64)
    val events: SharedFlow<WsEvent> = _events
    
    val connectionError = MutableStateFlow<String?>(null)
    private val pendingMessages = java.util.concurrent.ConcurrentLinkedQueue<String>()
    
    fun connect() {
        connectionError.value = null
        val cleanUrl = serverUrl.trimEnd('/')
        val wsUrl = when {
            cleanUrl.startsWith("https://") -> cleanUrl.replace("https://", "wss://") + "/ws/stream"
            cleanUrl.startsWith("http://") -> cleanUrl.replace("http://", "ws://") + "/ws/stream"
            cleanUrl.startsWith("wss://") || cleanUrl.startsWith("ws://") -> "$cleanUrl/ws/stream"
            else -> "ws://$cleanUrl/ws/stream"
        }
        val request = Request.Builder().url(wsUrl).build()
        
        webSocket = client.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                _isConnected.value = true
                connectionError.value = null
                _events.tryEmit(WsEvent.Connected)
                Log.d("WebSocket", "Connected to $wsUrl")
                
                // Flush pending control messages
                while (!pendingMessages.isEmpty()) {
                    pendingMessages.poll()?.let {
                        webSocket.send(it)
                    }
                }
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                try {
                    val json = JSONObject(text)
                    when (json.optString("type")) {
                        "risk_update" -> {
                            val risk = json.optDouble("risk_score", 0.0)
                            val level = json.optString("alert_level", "SAFE")
                            val classification = json.optString("voice_classification", if (risk < 0.5) "GENUINE_VOICE" else "CLONED_VOICE")
                            val detScore = json.optDouble("detection_score", risk)
                            val rms = json.optDouble("rms", 0.0)
                            val activeDet = json.optString("active_detector").takeIf { it.isNotBlank() }
                            _events.tryEmit(WsEvent.RiskUpdate(risk, level, classification, detScore, rms, activeDet))
                        }
                        "security_alert" -> {
                            val alertObj = json.optJSONObject("alert")
                            val risk = alertObj?.optDouble("risk_score", 0.0) ?: json.optDouble("risk_score", 0.0)
                            val level = alertObj?.optString("alert_level", "SAFE") ?: json.optString("alert_level", "SAFE")
                            val classification = alertObj?.optString("voice_classification") ?: json.optString("voice_classification", if (risk < 0.5) "GENUINE_VOICE" else "CLONED_VOICE")
                            val detScore = alertObj?.optDouble("detection_score", risk) ?: json.optDouble("detection_score", risk)
                            val activeDet = json.optString("active_detector").takeIf { it.isNotBlank() }
                            _events.tryEmit(WsEvent.RiskUpdate(risk, level, classification, detScore, 0.0, activeDet))
                        }
                        "session_start" -> {
                            val activeDet = json.optString("active_detector").takeIf { it.isNotBlank() }
                            _events.tryEmit(WsEvent.SessionStarted(
                                json.optString("session_id"),
                                json.optBoolean("detector_ready", false),
                                activeDet
                            ))
                        }
                        "status_update" -> {
                            val status = json.optString("status")
                            val detail = json.optString("detail", "")
                            val rms = json.optDouble("rms", 0.0)
                            val activeDet = json.optString("active_detector").takeIf { it.isNotBlank() }
                            _events.tryEmit(WsEvent.StatusUpdate(status, detail, rms, activeDet))
                        }
                        "error" -> {
                            val status = json.optString("status", "ERROR")
                            val msg = json.optString("message", "Unknown error")
                            _events.tryEmit(WsEvent.Error(status, msg))
                        }
                        else -> {
                            _events.tryEmit(WsEvent.UnknownMessage(text))
                        }
                    }
                } catch (e: Exception) {
                    _events.tryEmit(WsEvent.UnknownMessage(text))
                }
            }

            override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                // Not expected from server usually, but handled if needed
            }

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                webSocket.close(1000, null)
                _isConnected.value = false
                _events.tryEmit(WsEvent.Disconnected)
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                Log.e("WebSocket", "Error: ${t.message}", t)
                _isConnected.value = false
                connectionError.value = t.message ?: "Connection failed"
                _events.tryEmit(WsEvent.Error("CONNECTION_FAILED", t.message ?: "Connection failed"))
                _events.tryEmit(WsEvent.Disconnected)
            }
        })
    }
    
    fun sendControlMessage(type: String, metadata: Map<String, String> = emptyMap()) {
        val json = JSONObject()
        json.put("type", type)
        metadata.forEach { (k, v) -> json.put(k, v) }
        val msg = json.toString()
        if (_isConnected.value && webSocket != null) {
            webSocket?.send(msg)
        } else {
            pendingMessages.offer(msg)
        }
    }
    
    fun sendAudio(bytes: ByteArray) {
        webSocket?.send(ByteString.of(*bytes))
    }
    
    fun disconnect() {
        pendingMessages.clear()
        webSocket?.close(1000, "User disconnect")
        webSocket = null
        _isConnected.value = false
        _events.tryEmit(WsEvent.Disconnected)
    }
}

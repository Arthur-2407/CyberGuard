package com.cyberguard.client.network

import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import okhttp3.*
import okio.ByteString
import org.json.JSONObject

class WebSocketClient(
    private val client: OkHttpClient,
    private val serverUrl: String
) {
    private var webSocket: WebSocket? = null
    
    private val _isConnected = MutableStateFlow(false)
    val isConnected: StateFlow<Boolean> = _isConnected
    
    private val _lastMessage = MutableStateFlow<String?>(null)
    private val _messageFlow = kotlinx.coroutines.flow.MutableSharedFlow<String>(extraBufferCapacity = 64)
    val messageFlow: kotlinx.coroutines.flow.SharedFlow<String> = _messageFlow

    val connectionError = MutableStateFlow<String?>(null)
    
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
                Log.d("WebSocket", "Connected to $wsUrl")
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                _lastMessage.value = text
                _messageFlow.tryEmit(text)
            }

            override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                // Not expected from server usually, but handled if needed
            }

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                webSocket.close(1000, null)
                _isConnected.value = false
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                Log.e("WebSocket", "Error: ${t.message}", t)
                _isConnected.value = false
                connectionError.value = t.message ?: "Connection failed"
            }
        })
    }
    
    fun sendText(text: String) {
        webSocket?.send(text)
    }
    
    fun sendAudio(bytes: ByteArray) {
        webSocket?.send(ByteString.of(*bytes))
    }
    
    fun disconnect() {
        webSocket?.close(1000, "User disconnect")
        webSocket = null
        _isConnected.value = false
    }
}

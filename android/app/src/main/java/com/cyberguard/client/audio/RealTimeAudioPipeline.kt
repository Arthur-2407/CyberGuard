package com.cyberguard.client.audio

import android.media.AudioFormat
import android.media.AudioRecord
import android.media.MediaRecorder
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.delay

enum class AudioSourceType {
    MIC,
    VOICE_COMMUNICATION // Acoustic fallback for calls
}

class RealTimeAudioPipeline(
    private val sourceType: AudioSourceType,
    private val onAudioData: (ByteArray) -> Unit,
    private val onError: (String) -> Unit = {},
    private val onRmsUpdate: ((Double) -> Unit)? = null
) {
    private var audioRecord: AudioRecord? = null
    private var isRecording = false
    private var recordingJob: Job? = null
    
    var framesCaptured: Long = 0
        private set

    var activeSourceDescription: String = sourceType.name
        private set

    fun start() {
        if (isRecording) return

        val sourcesToTry = mutableListOf<Int>()
        if (sourceType == AudioSourceType.VOICE_COMMUNICATION) {
            sourcesToTry.add(MediaRecorder.AudioSource.VOICE_COMMUNICATION)
            sourcesToTry.add(MediaRecorder.AudioSource.VOICE_RECOGNITION)
            sourcesToTry.add(MediaRecorder.AudioSource.MIC)
        } else {
            sourcesToTry.add(MediaRecorder.AudioSource.MIC)
            sourcesToTry.add(MediaRecorder.AudioSource.VOICE_RECOGNITION)
        }

        var lastException: Exception? = null
        for (source in sourcesToTry) {
            try {
                startInternal(source)
                activeSourceDescription = when (source) {
                    MediaRecorder.AudioSource.VOICE_COMMUNICATION -> "VOICE_COMMUNICATION (DUPLEX AEC)"
                    MediaRecorder.AudioSource.VOICE_RECOGNITION -> "VOICE_RECOGNITION"
                    MediaRecorder.AudioSource.MIC -> "MIC"
                    else -> "AUDIO_SOURCE_$source"
                }
                Log.i("RealTimeAudioPipeline", "RealTimeAudioPipeline started successfully with source: $activeSourceDescription")
                return
            } catch (e: Exception) {
                Log.w("RealTimeAudioPipeline", "AudioSource $source failed: ${e.message}. Trying next...")
                lastException = e
            }
        }

        isRecording = false
        throw lastException ?: IllegalStateException("All audio sources failed to initialize.")
    }

    private fun startInternal(source: Int) {
        val bufferSize = AudioRecord.getMinBufferSize(
            16000,
            AudioFormat.CHANNEL_IN_MONO,
            AudioFormat.ENCODING_PCM_16BIT
        )
        if (bufferSize <= 0) throw IllegalStateException("Invalid buffer size: $bufferSize")

        audioRecord = AudioRecord(
            source,
            16000,
            AudioFormat.CHANNEL_IN_MONO,
            AudioFormat.ENCODING_PCM_16BIT,
            bufferSize * 2
        )

        if (audioRecord?.state != AudioRecord.STATE_INITIALIZED) {
            throw IllegalStateException("AudioRecord initialization failed (state = ${audioRecord?.state}). Source=$source")
        }

        audioRecord?.startRecording()
        if (audioRecord?.recordingState != AudioRecord.RECORDSTATE_RECORDING) {
            throw IllegalStateException("AudioRecord failed to start recording.")
        }
        isRecording = true
        framesCaptured = 0
    }

    suspend fun streamData() = coroutineScope {
        recordingJob = launch(Dispatchers.IO) {
            val bufferSize = AudioRecord.getMinBufferSize(
                16000,
                AudioFormat.CHANNEL_IN_MONO,
                AudioFormat.ENCODING_PCM_16BIT
            )
            val buffer = ByteArray(bufferSize)
            var zeroByteCount = 0
            val zeroByteThreshold = 50 // roughly 1 second of consecutive 0-byte reads
            var hasTriedMicFallback = (sourceType == AudioSourceType.MIC)
            
            while (isActive && isRecording) {
                val tCapture = System.nanoTime()
                val read = audioRecord?.read(buffer, 0, buffer.size) ?: 0
                val tReady = System.nanoTime()
                
                if (read > 0) {
                    zeroByteCount = 0
                    framesCaptured++
                    val dataCopy = buffer.copyOf(read)
                    onAudioData(dataCopy)

                    // Compute RMS level for UI audio activity meter
                    val shortCount = read / 2
                    if (shortCount > 0 && onRmsUpdate != null) {
                        var sum = 0.0
                        for (i in 0 until shortCount) {
                            val bLo = buffer[i * 2].toInt() and 0xFF
                            val bHi = buffer[i * 2 + 1].toInt()
                            val sample = ((bHi shl 8) or bLo).toShort()
                            val norm = sample / 32768.0
                            sum += norm * norm
                        }
                        val rms = Math.sqrt(sum / shortCount)
                        onRmsUpdate?.invoke(rms)
                    }
                } else {
                    zeroByteCount++
                    if (zeroByteCount > zeroByteThreshold) {
                        if (!hasTriedMicFallback) {
                            Log.w("RealTimeAudioPipeline", "Consecutive zero reads. Switching to MIC fallback...")
                            hasTriedMicFallback = true
                            zeroByteCount = 0
                            try {
                                audioRecord?.stop()
                                audioRecord?.release()
                                audioRecord = null
                                startInternal(MediaRecorder.AudioSource.MIC)
                                activeSourceDescription = "MIC (DYNAMIC FALLBACK)"
                                continue
                            } catch (fallbackEx: Exception) {
                                Log.e("RealTimeAudioPipeline", "Dynamic MIC fallback failed: ${fallbackEx.message}")
                            }
                        }
                        Log.e("RealTimeAudioPipeline", "Consecutive zero or negative reads. Capture failed.")
                        onError("Audio source unavailable (read $read bytes). Hardware blocked?")
                        break
                    }
                    delay(20) // prevent tight loop if read returns 0 instantly
                }
                
                val tSend = System.nanoTime()
                val capToReady = (tReady - tCapture) / 1_000_000.0
                val readyToSend = (tSend - tReady) / 1_000_000.0
                Log.d("CyberGuardLatency", "Audio Chunk [size=$read]: capture->ready=${capToReady}ms, ready->send=${readyToSend}ms")
            }
        }
    }

    fun stop() {
        isRecording = false
        recordingJob?.cancel()
        recordingJob = null
        try {
            audioRecord?.stop()
        } catch (e: Exception) {}
        audioRecord?.release()
        audioRecord = null
    }
}

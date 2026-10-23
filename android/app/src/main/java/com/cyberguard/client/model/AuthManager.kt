package com.cyberguard.client.model

import android.content.Context
import android.content.SharedPreferences
import com.cyberguard.client.network.UserResponse
import com.google.gson.Gson
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

interface AuthTokenProvider {
    val authToken: StateFlow<String?>
}

class AuthManager private constructor(context: Context) : AuthTokenProvider {

    private val prefs: SharedPreferences = context.applicationContext.getSharedPreferences(
        PREFS_NAME,
        Context.MODE_PRIVATE
    )
    private val gson = Gson()

    private val _authToken = MutableStateFlow<String?>(null)
    override val authToken: StateFlow<String?> = _authToken.asStateFlow()

    private val _currentUser = MutableStateFlow<UserResponse?>(null)
    val currentUser: StateFlow<UserResponse?> = _currentUser.asStateFlow()

    val isLoggedIn: Boolean
        get() = !_authToken.value.isNullOrBlank()

    init {
        val savedToken = prefs.getString(KEY_TOKEN, null)
        val savedUserJson = prefs.getString(KEY_USER_JSON, null)
        if (!savedToken.isNullOrBlank() && !savedUserJson.isNullOrBlank()) {
            try {
                val user = gson.fromJson(savedUserJson, UserResponse::class.java)
                _authToken.value = savedToken
                _currentUser.value = user
            } catch (e: Exception) {
                clearSession()
            }
        }
    }

    fun saveSession(token: String, user: UserResponse) {
        _authToken.value = token
        _currentUser.value = user
        prefs.edit()
            .putString(KEY_TOKEN, token)
            .putString(KEY_USER_JSON, gson.toJson(user))
            .apply()
    }

    fun updateUser(user: UserResponse) {
        _currentUser.value = user
        prefs.edit()
            .putString(KEY_USER_JSON, gson.toJson(user))
            .apply()
    }

    fun clearSession() {
        _authToken.value = null
        _currentUser.value = null
        prefs.edit()
            .remove(KEY_TOKEN)
            .remove(KEY_USER_JSON)
            .apply()
    }

    companion object {
        private const val PREFS_NAME = "cyberguard_auth_prefs"
        private const val KEY_TOKEN = "auth_session_token"
        private const val KEY_USER_JSON = "auth_user_json"

        @Volatile
        private var instance: AuthManager? = null

        fun getInstance(context: Context): AuthManager {
            return instance ?: synchronized(this) {
                instance ?: AuthManager(context.applicationContext).also { instance = it }
            }
        }
    }
}

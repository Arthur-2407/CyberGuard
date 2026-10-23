package com.cyberguard.client.telecom

import java.util.regex.Pattern

/**
 * Normalized phone number structure conforming to ITU-T E.164 specifications.
 */
data class NormalizedPhoneNumber(
    val raw: String,
    val e164: String,
    val national: String,
    val countryCode: String?,
    val isValid: Boolean,
    val isRestricted: Boolean,
    val isShortCode: Boolean,
    val rejectionReason: String? = null
)

/**
 * Standards-compliant, privacy-conscious phone number normalizer.
 * Provides deterministic E.164 canonicalization for carrier & reputation database queries.
 */
object PhoneNumberNormalizer {

    private val RESTRICTED_PATTERN = Pattern.compile(
        "^(unknown.*|restricted.*|private.*|blocked.*|anonymous.*|caller id blocked.*|-1|-2)$",
        Pattern.CASE_INSENSITIVE
    )

    private val DIGITS_AND_PLUS_ONLY = Pattern.compile("[^0-9+]")

    /**
     * Normalizes a phone number into an ITU-T E.164 format.
     *
     * @param rawNumber Input string from Call.Details.handle or caller ID
     * @param defaultRegion Default ISO 3166-1 alpha-2 country code (defaults to "IN" for India)
     */
    fun normalize(rawNumber: String?, defaultRegion: String = "IN"): NormalizedPhoneNumber {
        if (rawNumber.isNullOrBlank()) {
            return NormalizedPhoneNumber(
                raw = "",
                e164 = "",
                national = "",
                countryCode = null,
                isValid = false,
                isRestricted = true,
                isShortCode = false,
                rejectionReason = "RESTRICTED_OR_EMPTY_NUMBER"
            )
        }

        val trimmed = rawNumber.trim()

        // 1. Check for anonymous / restricted caller ID
        if (RESTRICTED_PATTERN.matcher(trimmed).matches()) {
            return NormalizedPhoneNumber(
                raw = trimmed,
                e164 = "",
                national = "",
                countryCode = null,
                isValid = false,
                isRestricted = true,
                isShortCode = false,
                rejectionReason = "CALLER_ID_RESTRICTED"
            )
        }

        // 2. Strip non-digit characters except leading '+'
        var stripped = DIGITS_AND_PLUS_ONLY.matcher(trimmed).replaceAll("")
        if (stripped.startsWith("+")) {
            stripped = "+" + stripped.substring(1).replace("+", "")
        } else {
            stripped = stripped.replace("+", "")
        }

        if (stripped.isEmpty()) {
            return NormalizedPhoneNumber(
                raw = trimmed,
                e164 = "",
                national = "",
                countryCode = null,
                isValid = false,
                isRestricted = false,
                isShortCode = false,
                rejectionReason = "NO_DIGITS_FOUND"
            )
        }

        // 3. Short-code detection (3 to 6 digits, e.g. Emergency 100/112/911, Banking SMS/IVR codes)
        if (!stripped.startsWith("+") && stripped.length in 3..6) {
            return NormalizedPhoneNumber(
                raw = trimmed,
                e164 = stripped,
                national = stripped,
                countryCode = null,
                isValid = true,
                isRestricted = false,
                isShortCode = true,
                rejectionReason = null
            )
        }

        // 4. International prefix resolution
        var e164Candidate: String
        var countryCode: String? = null
        var national: String = stripped

        if (stripped.startsWith("+")) {
            val digitsOnly = stripped.substring(1)
            e164Candidate = stripped

            // Infer country code
            when {
                digitsOnly.startsWith("91") && digitsOnly.length == 12 -> {
                    countryCode = "91"
                    national = digitsOnly.substring(2)
                }
                digitsOnly.startsWith("1") && digitsOnly.length == 11 -> {
                    countryCode = "1"
                    national = digitsOnly.substring(1)
                }
                digitsOnly.startsWith("44") && digitsOnly.length in 11..12 -> {
                    countryCode = "44"
                    national = digitsOnly.substring(2)
                }
                else -> {
                    countryCode = digitsOnly.take(3)
                    national = digitsOnly.drop(3)
                }
            }
        } else if (stripped.startsWith("00")) {
            // "00" International dial prefix
            val withoutPrefix = stripped.substring(2)
            e164Candidate = "+$withoutPrefix"
            countryCode = withoutPrefix.take(2)
            national = withoutPrefix.drop(2)
        } else {
            // Domestic number normalization according to defaultRegion
            when (defaultRegion.uppercase()) {
                "IN" -> {
                    when {
                        // 10-digit standard Indian mobile / landline
                        stripped.length == 10 && stripped[0] in '6'..'9' -> {
                            countryCode = "91"
                            national = stripped
                            e164Candidate = "+91$stripped"
                        }
                        // 11-digit leading 0 (e.g. 09876543210)
                        stripped.length == 11 && stripped.startsWith("0") && stripped[1] in '6'..'9' -> {
                            countryCode = "91"
                            national = stripped.substring(1)
                            e164Candidate = "+91" + stripped.substring(1)
                        }
                        // Already includes 91 without plus (12 digits)
                        stripped.length == 12 && stripped.startsWith("91") -> {
                            countryCode = "91"
                            national = stripped.substring(2)
                            e164Candidate = "+$stripped"
                        }
                        else -> {
                            e164Candidate = "+91$stripped"
                            countryCode = "91"
                        }
                    }
                }
                "US", "CA" -> {
                    when {
                        stripped.length == 10 -> {
                            countryCode = "1"
                            national = stripped
                            e164Candidate = "+1$stripped"
                        }
                        stripped.length == 11 && stripped.startsWith("1") -> {
                            countryCode = "1"
                            national = stripped.substring(1)
                            e164Candidate = "+$stripped"
                        }
                        else -> {
                            e164Candidate = "+1$stripped"
                            countryCode = "1"
                        }
                    }
                }
                else -> {
                    e164Candidate = "+$stripped"
                }
            }
        }

        // 5. Length verification according to ITU-T E.164 (max 15 digits excluding '+', min 7)
        val digitsCount = e164Candidate.filter { it.isDigit() }.length
        val isValid = digitsCount in 7..15

        return NormalizedPhoneNumber(
            raw = trimmed,
            e164 = if (isValid) e164Candidate else stripped,
            national = national,
            countryCode = countryCode,
            isValid = isValid,
            isRestricted = false,
            isShortCode = false,
            rejectionReason = if (!isValid) "INVALID_DIGIT_LENGTH ($digitsCount digits)" else null
        )
    }
}

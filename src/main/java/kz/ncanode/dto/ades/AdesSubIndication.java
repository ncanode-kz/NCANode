package kz.ncanode.dto.ades;

/**
 * Суб-индикация проверки AdES (подмножество ETSI EN 319 102-1, совместимое с движком NCALayer).
 */
public enum AdesSubIndication {
    /** Сертификат подписанта не найден. */
    NO_SIGNING_CERTIFICATE_FOUND,
    /** Значение подписи не проверяется. */
    SIG_CRYPTO_FAILURE,
    /** Хеш сертификата в SigningCertificateV2 не совпадает. */
    CERT_HASH_MISMATCH,
    /** Метка времени подписи не прошла проверку. */
    TIMESTAMP_INVALID,
    /** Сертификат вне срока действия на доказанное время подписи, метка времени не помогает. */
    OUT_OF_BOUNDS_NO_POE,
    /** Не построена цепочка до доверенного корня. */
    CHAIN_INCOMPLETE,
    /** Сертификат отозван до доказанного времени подписи. */
    CERT_REVOKED,
    /** Сертификат отозван, метка времени не доказывает, что подпись раньше отзыва. */
    REVOKED_NO_POE,
    /** Нет данных отзыва, покрывающих время подписи. */
    REVOCATION_DATA_MISSING,
    /** Формат подписи некорректен. */
    FORMAT_FAILURE
}

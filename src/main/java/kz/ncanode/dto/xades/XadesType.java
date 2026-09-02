package kz.ncanode.dto.xades;

/**
 * Профиль (уровень) XAdES-подписи по ETSI EN 319 132.
 *
 * <p>Формат соответствует движку {@code kz.gov.pki.ades} из NCALayer: exclusive-c14n,
 * пространство имён {@code http://uri.etsi.org/01903/v1.3.2#}, {@code SigningCertificateV2}.
 */
public enum XadesType {
    /** Базовая подпись: SigningTime + SigningCertificateV2. */
    XADES_BES,

    /** BES + доверенная метка времени TSA на {@code ds:SignatureValue}. */
    XADES_T,

    /** T + вшитые цепочка сертификатов и данные отзыва (пока не реализовано). */
    XADES_LT,

    /** LT + архивные метки времени (пока не реализовано). */
    XADES_LTA
}

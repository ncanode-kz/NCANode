package kz.ncanode.dto.ades;

/**
 * Уровень (профиль) AdES-подписи по ETSI (baseline B/T/LT/LTA). Общий для XAdES, CAdES, JAdES.
 *
 * <ul>
 *   <li><b>B</b>  — базовая подпись (SigningCertificateV2 + время подписи).</li>
 *   <li><b>T</b>  — B + доверенная метка времени TSA на значении подписи.</li>
 *   <li><b>LT</b> — T + вшитые цепочка сертификатов и данные отзыва (OCSP/CRL) на момент метки времени.</li>
 *   <li><b>LTA</b>— LT + архивные метки времени.</li>
 * </ul>
 */
public enum AdesLevel {
    B,
    T,
    LT,
    LTA;

    public boolean isAtLeast(AdesLevel other) {
        return ordinal() >= other.ordinal();
    }
}

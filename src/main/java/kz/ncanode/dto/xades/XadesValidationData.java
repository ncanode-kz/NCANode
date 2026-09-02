package kz.ncanode.dto.xades;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Материал для вшивания в XAdES-LT: цепочка сертификатов и данные отзыва
 * на момент метки времени подписи.
 *
 * @param certificates полная цепочка (подписант + УЦ + корень) и сертификаты TSA
 * @param crls         DER-кодированные CRL
 * @param ocsps        DER-кодированные {@code OCSPResponse}
 */
public record XadesValidationData(
    List<X509Certificate> certificates,
    List<byte[]> crls,
    List<byte[]> ocsps
) {
    public boolean hasRevocation() {
        return !crls.isEmpty() || !ocsps.isEmpty();
    }
}

package kz.ncanode.dto.jws;

import kz.ncanode.dto.certificate.CertificateInfo;
import lombok.Builder;
import lombok.Data;
import lombok.extern.jackson.Jacksonized;

import java.util.Map;

@Jacksonized
@Data
@Builder
public class JwsSignerInfo {
    /** Подпись этого подписанта валидна. */
    private boolean valid;
    /** Разобранный protected-заголовок. */
    private Map<String, Object> header;
    /** Сертификат подписанта (из x5c). */
    private CertificateInfo certificate;
}

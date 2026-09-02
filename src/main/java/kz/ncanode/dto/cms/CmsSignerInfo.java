package kz.ncanode.dto.cms;

import com.fasterxml.jackson.annotation.JsonInclude;
import kz.ncanode.dto.ades.AdesLevel;
import kz.ncanode.dto.ades.AdesSubIndication;
import kz.ncanode.dto.ades.AdesValidationStatus;
import kz.ncanode.dto.certificate.CertificateInfo;
import kz.ncanode.dto.tsp.TspInfo;
import lombok.Builder;
import lombok.Data;
import lombok.Singular;
import lombok.extern.jackson.Jacksonized;

import java.util.Date;
import java.util.List;

@Jacksonized
@Data
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CmsSignerInfo {
    @Singular
    private List<CertificateInfo> certificates;
    private TspInfo tsp;

    /** Определённый профиль подписи: {@code B} / {@code T} / {@code LT} / {@code LTA}. */
    private AdesLevel adesLevel;

    /** Доказанное время подписи (genTime валидной метки времени, либо момент проверки). */
    private Date bestSignatureTime;

    /** Итоговый статус проверки подписанта. */
    private AdesValidationStatus status;

    /** Суб-индикация при {@code INVALID} / {@code INDETERMINATE}. */
    private AdesSubIndication subIndication;

    /** Пояснение к статусу. */
    private String message;
}

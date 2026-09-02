package kz.ncanode.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import kz.ncanode.dto.ades.AdesLevel;
import kz.ncanode.dto.ades.AdesSubIndication;
import kz.ncanode.dto.ades.AdesValidationStatus;
import kz.ncanode.dto.certificate.CertificateInfo;
import kz.ncanode.dto.tsp.TspInfo;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.experimental.SuperBuilder;
import lombok.extern.jackson.Jacksonized;

import java.util.Date;
import java.util.List;

@Jacksonized
@EqualsAndHashCode(callSuper = true)
@Data
@SuperBuilder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class VerificationResponse extends StatusResponse {
    public boolean valid;
    public List<CertificateInfo> signers;

    /** Профиль XAdES-подписи ({@code B}/{@code T}/{@code LT}/{@code LTA}); {@code null} для не-XAdES. */
    private AdesLevel adesLevel;

    /** Метка времени подписи XAdES-T и выше. */
    private TspInfo signatureTimestamp;

    /** Доказанное время подписи. */
    private Date bestSignatureTime;

    /** Итоговый статус проверки XAdES-подписи. */
    private AdesValidationStatus adesStatus;

    /** Суб-индикация при {@code INVALID} / {@code INDETERMINATE}. */
    private AdesSubIndication adesSubIndication;
}

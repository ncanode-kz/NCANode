package kz.ncanode.dto.pdf;

import com.fasterxml.jackson.annotation.JsonInclude;
import kz.ncanode.dto.ades.AdesLevel;
import kz.ncanode.dto.ades.AdesSubIndication;
import kz.ncanode.dto.ades.AdesValidationStatus;
import kz.ncanode.dto.certificate.CertificateInfo;
import kz.ncanode.dto.tsp.TspInfo;
import lombok.Builder;
import lombok.Data;
import lombok.extern.jackson.Jacksonized;

import java.util.Date;

@Jacksonized
@Data
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class PdfSignerInfo {
	private boolean valid;
	private String reason;
	private String location;
	private String contactInfo;
	private Date signDate;
	private CertificateInfo certificate;
	private String signatureAlgorithm;
	private String digestAlgorithm;

	/** Профиль подписи: {@code B} / {@code T} / {@code LT} / {@code LTA}. */
	private AdesLevel adesLevel;

	/** Метка времени подписи (PAdES-T и выше). */
	private TspInfo tsp;

	/** Доказанное время подписи. */
	private Date bestSignatureTime;

	/** Итоговый статус проверки. */
	private AdesValidationStatus status;

	/** Суб-индикация при {@code INVALID} / {@code INDETERMINATE}. */
	private AdesSubIndication subIndication;
}

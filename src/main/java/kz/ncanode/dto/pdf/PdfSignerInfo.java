package kz.ncanode.dto.pdf;

import kz.ncanode.dto.certificate.CertificateInfo;
import lombok.Builder;
import lombok.Data;
import lombok.extern.jackson.Jacksonized;

import java.util.Date;

@Jacksonized
@Data
@Builder
public class PdfSignerInfo {
	private boolean valid;
	private String reason;
	private String location;
	private String contactInfo;
	private Date signDate;
	private CertificateInfo certificate;
	private String signatureAlgorithm;
	private String digestAlgorithm;
}

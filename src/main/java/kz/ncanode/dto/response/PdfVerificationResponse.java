package kz.ncanode.dto.response;

import kz.ncanode.dto.pdf.PdfSignerInfo;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.experimental.SuperBuilder;
import lombok.extern.jackson.Jacksonized;

import java.util.List;

@Jacksonized
@EqualsAndHashCode(callSuper = true)
@Data
@SuperBuilder
public class PdfVerificationResponse extends StatusResponse {
	private boolean valid;
	private List<PdfSignerInfo> signers;
}

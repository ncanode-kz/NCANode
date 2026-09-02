package kz.ncanode.dto.request;

import kz.ncanode.dto.ades.AdesLevel;
import kz.ncanode.dto.tsp.TsaPolicy;
import lombok.Data;

import jakarta.validation.constraints.NotEmpty;
import java.util.List;

@Data
public class PdfSignRequest {

	@NotEmpty
	private String pdf;

	@NotEmpty
	private List<PdfSigner> signers;

	private boolean withTsp = false;

	private TsaPolicy tsaPolicy;

	/**
	 * Уровень PAdES ({@code B}/{@code T}/{@code LT}/{@code LTA}). {@code null} — обычная подпись
	 * (при этом действует флаг {@code withTsp}).
	 */
	private AdesLevel padesLevel;

	@Data
	public static class PdfSigner {
		private String reason;
		private String location;
		private String contactInfo;

		@NotEmpty
		private SignerRequest signer;
	}
}

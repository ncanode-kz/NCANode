package kz.ncanode.dto.request;

import kz.ncanode.dto.ades.AdesLevel;
import kz.ncanode.dto.tsp.TsaPolicy;
import lombok.Builder;
import lombok.Data;
import lombok.extern.jackson.Jacksonized;

import jakarta.validation.constraints.NotEmpty;
import java.util.List;

@Jacksonized
@Data
@Builder
public class XmlSignRequest {
    @NotEmpty
    private String xml;

    @NotEmpty
    private List<SignerRequest> signers;

    private boolean clearSignatures;

    @Builder.Default
    private boolean trimXml = false;

    /**
     * Уровень XAdES ({@code B}/{@code T}/{@code LT}/{@code LTA}). {@code null} — обычный XMLDSIG
     * (поведение по умолчанию).
     */
    private AdesLevel xadesLevel;

    /**
     * Политика TSA для XAdES-T и выше.
     */
    @Builder.Default
    private TsaPolicy tsaPolicy = TsaPolicy.TSA_GOST2015_POLICY;
}

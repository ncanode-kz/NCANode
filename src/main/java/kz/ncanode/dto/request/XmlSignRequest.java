package kz.ncanode.dto.request;

import kz.ncanode.dto.tsp.TsaPolicy;
import kz.ncanode.dto.xades.XadesType;
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
     * Тип подписи. {@code null} — обычный XMLDSIG (поведение по умолчанию);
     * иначе строится XAdES соответствующего уровня.
     */
    private XadesType xadesType;

    /**
     * Политика TSA для XAdES-T и выше.
     */
    @Builder.Default
    private TsaPolicy tsaPolicy = TsaPolicy.TSA_GOST2015_POLICY;
}

package kz.ncanode.dto.request;

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
}

package kz.ncanode.dto.request;

import lombok.Builder;
import lombok.Data;
import lombok.extern.jackson.Jacksonized;

import jakarta.validation.constraints.NotEmpty;

@Jacksonized
@Data
@Builder
public class WsseSignRequest {
    @NotEmpty
    private String xml;

    @NotEmpty
    private String key;

    @NotEmpty
    private String password;

    private String keyAlias;

    @Builder.Default
    private boolean trimXml = false;
}

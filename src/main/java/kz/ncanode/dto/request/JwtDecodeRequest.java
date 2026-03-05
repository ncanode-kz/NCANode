package kz.ncanode.dto.request;

import lombok.Builder;
import lombok.Data;
import lombok.extern.jackson.Jacksonized;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;

@Jacksonized
@Data
@Builder
public class JwtDecodeRequest {

    @NotNull
    private String jwt;

    @NotEmpty
    private String key;
}

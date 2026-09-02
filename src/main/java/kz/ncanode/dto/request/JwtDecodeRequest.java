package kz.ncanode.dto.request;

import lombok.Builder;
import lombok.Data;
import lombok.extern.jackson.Jacksonized;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

@Jacksonized
@Data
@Builder
public class JwtDecodeRequest {

    @NotNull
    private String jwt;

    @NotEmpty
    private String key;
}

package kz.ncanode.dto.response;

import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.experimental.SuperBuilder;
import lombok.extern.jackson.Jacksonized;

import java.util.Map;

@Jacksonized
@EqualsAndHashCode(callSuper = true)
@Data
@SuperBuilder
public class JwtDecodeResponse extends StatusResponse {
    private boolean valid;
    private Jwt jwt;

    @Jacksonized
    @Data
    @Builder
    public static class Jwt {
        private Map<String, String> header;
        private Map<String, Object> payload;
    }
}

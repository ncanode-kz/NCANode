package kz.ncanode.dto.request;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import lombok.Builder;
import lombok.Data;
import lombok.extern.jackson.Jacksonized;

import javax.validation.Valid;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import java.util.LinkedHashMap;
import java.util.Map;

@Jacksonized
@Data
@Builder
public class JwtEncodeRequest {

    @NotNull
    @Valid
    private JwtRequest jwt;

    @NotEmpty
    private String key;

    @NotEmpty
    private String password;

    private String keyAlias;

    @Jacksonized
    @Data
    @Builder
    public static class JwtRequest {
        @NotNull
        @Valid
        private JwtHeader header;

        @NotNull
        @Valid
        private JwtPayload payload;
    }

    @Jacksonized
    @Data
    @Builder
    public static class JwtHeader {
        @NotEmpty
        private String alg;

        @NotEmpty
        private String typ;
    }

    @Data
    public static class JwtPayload {
        private final Map<String, Object> claims = new LinkedHashMap<>();

        @JsonAnySetter
        public void setClaim(String key, Object value) {
            claims.put(key, value);
        }

        @JsonAnyGetter
        public Map<String, Object> getClaims() {
            return claims;
        }
    }
}

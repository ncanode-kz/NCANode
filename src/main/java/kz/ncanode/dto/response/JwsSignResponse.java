package kz.ncanode.dto.response;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.experimental.SuperBuilder;
import lombok.extern.jackson.Jacksonized;

@Jacksonized
@EqualsAndHashCode(callSuper = true)
@Data
@SuperBuilder
public class JwsSignResponse extends StatusResponse {
    /** JWS в формате JSON Serialization. */
    private JsonNode jws;
}

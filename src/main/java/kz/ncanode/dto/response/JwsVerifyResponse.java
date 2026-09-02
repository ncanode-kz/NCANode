package kz.ncanode.dto.response;

import com.fasterxml.jackson.databind.JsonNode;
import kz.ncanode.dto.jws.JwsSignerInfo;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.experimental.SuperBuilder;
import lombok.extern.jackson.Jacksonized;

import java.util.List;

@Jacksonized
@EqualsAndHashCode(callSuper = true)
@Data
@SuperBuilder
public class JwsVerifyResponse extends StatusResponse {
    /** Все подписи валидны. */
    private boolean valid;
    private List<JwsSignerInfo> signers;
    /** Декодированный payload (null для detached без переданного payload). */
    private JsonNode payload;
}

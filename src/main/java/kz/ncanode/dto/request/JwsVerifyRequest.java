package kz.ncanode.dto.request;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.experimental.SuperBuilder;
import lombok.extern.jackson.Jacksonized;

import jakarta.validation.constraints.NotNull;

/**
 * Запрос на проверку JWS (JSON Serialization).
 * Сертификаты подписантов берутся из заголовка {@code x5c} каждой подписи.
 */
@Jacksonized
@EqualsAndHashCode(callSuper = true)
@Data
@SuperBuilder
public class JwsVerifyRequest extends VerifyRequest {

    /** JWS в формате JSON Serialization (общий или flattened синтаксис). */
    @NotNull
    private JsonNode jws;

    /** Payload для detached JWS (тот же JSON, что подписывали). */
    private JsonNode payload;
}

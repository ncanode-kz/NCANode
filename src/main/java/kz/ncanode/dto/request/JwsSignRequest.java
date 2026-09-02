package kz.ncanode.dto.request;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.Builder;
import lombok.Data;
import lombok.extern.jackson.Jacksonized;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import java.util.List;

/**
 * Запрос на подпись произвольного JSON в формате JWS (RFC 7515, JSON Serialization).
 * <p>
 * Используется и для {@code /jws/sign}, и для {@code /jws/sign/add} — во втором случае
 * задаётся {@link #jws} (существующий JWS, к которому добавляются подписанты).
 */
@Jacksonized
@Data
@Builder
public class JwsSignRequest {

    /** Существующий JWS (JSON Serialization) для /jws/sign/add. */
    private JsonNode jws;

    /**
     * Подписываемые данные — произвольный JSON: объект, массив или скаляр.
     * Обязателен для /jws/sign; для /jws/sign/add нужен только если исходный JWS detached.
     */
    private JsonNode payload;

    /** Не включать payload в результат (detached). */
    private boolean detached;

    /** Значение заголовка typ. Если не задано — "JWT". */
    private String typ;

    @NotEmpty
    @Valid
    private List<JwsSignerRequest> signers;
}

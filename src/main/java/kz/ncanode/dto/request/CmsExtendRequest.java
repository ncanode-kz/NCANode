package kz.ncanode.dto.request;

import kz.ncanode.dto.ades.AdesLevel;
import kz.ncanode.dto.tsp.TsaPolicy;
import lombok.Data;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

/**
 * Достройка готовой CAdES-подписи до более высокого профиля (B → T → LT → LTA).
 */
@Data
public class CmsExtendRequest {

    @NotEmpty
    private String cms;

    /** Исходные данные — обязательны для detached CMS. */
    private String data;

    @NotNull
    private AdesLevel cadesLevel;

    private TsaPolicy tsaPolicy;
}

package kz.ncanode.dto.request;

import kz.ncanode.dto.ades.AdesLevel;
import kz.ncanode.dto.tsp.TsaPolicy;
import lombok.Data;

import jakarta.validation.constraints.NotEmpty;
import java.util.List;

@Data
public class CmsCreateRequest {
    private String cms;
    private String data;

    @NotEmpty
    private List<SignerRequest> signers;

    private boolean withTsp = false;

    private TsaPolicy tsaPolicy;

    private boolean detached = false;

    /**
     * Уровень CAdES ({@code B}/{@code T}/{@code LT}/{@code LTA}). {@code null} — обычный CMS
     * (при этом действует флаг {@code withTsp}). Поддерживается только на {@code /cms/sign}.
     */
    private AdesLevel cadesLevel;
}

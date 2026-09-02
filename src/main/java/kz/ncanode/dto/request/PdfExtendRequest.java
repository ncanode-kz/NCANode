package kz.ncanode.dto.request;

import kz.ncanode.dto.ades.AdesLevel;
import kz.ncanode.dto.tsp.TsaPolicy;
import lombok.Data;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

/**
 * Достройка подписанного PDF до PAdES-LT / LTA ({@code /DSS}, {@code /DocTimeStamp}).
 */
@Data
public class PdfExtendRequest {

    @NotEmpty
    private String pdf;

    @NotNull
    private AdesLevel padesLevel;

    private TsaPolicy tsaPolicy;
}

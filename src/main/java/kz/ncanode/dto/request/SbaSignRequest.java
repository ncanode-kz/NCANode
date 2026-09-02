package kz.ncanode.dto.request;

import kz.ncanode.dto.tsp.TsaPolicy;
import lombok.Data;

import jakarta.validation.constraints.NotEmpty;

@Data
public class SbaSignRequest {

    @NotEmpty
    private String data;

    private SignerRequest signer;

    private TsaPolicy tsaPolicy;
}

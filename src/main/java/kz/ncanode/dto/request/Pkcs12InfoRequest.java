package kz.ncanode.dto.request;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.experimental.SuperBuilder;
import lombok.extern.jackson.Jacksonized;

import jakarta.validation.constraints.NotEmpty;
import java.util.List;

@Jacksonized
@EqualsAndHashCode(callSuper = true)
@Data
@SuperBuilder
public class Pkcs12InfoRequest extends VerifyRequest {
    @NotEmpty
    private List<SignerRequest> keys;
}

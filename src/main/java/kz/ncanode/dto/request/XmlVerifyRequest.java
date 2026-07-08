package kz.ncanode.dto.request;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.experimental.SuperBuilder;
import lombok.extern.jackson.Jacksonized;

import jakarta.validation.constraints.NotEmpty;

@Jacksonized
@EqualsAndHashCode(callSuper = true)
@Data
@SuperBuilder
public class XmlVerifyRequest extends VerifyRequest {
    @NotEmpty
    private String xml;
}

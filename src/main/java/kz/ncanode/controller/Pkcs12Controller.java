package kz.ncanode.controller;

import kz.ncanode.dto.request.Pkcs12InfoRequest;
import kz.ncanode.dto.response.Pkcs12AliasesResponse;
import kz.ncanode.dto.response.VerificationResponse;
import kz.ncanode.service.CertificateService;
import kz.ncanode.wrapper.KalkanWrapper;
import kz.ncanode.wrapper.KeyStoreWrapper;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.validation.Valid;

import io.swagger.v3.oas.annotations.tags.Tag;

@Tag(name = "Pkcs12", description = "Методы для работы с Pkcs12")
@RestController
@RequestMapping("pkcs12")
@RequiredArgsConstructor
public class Pkcs12Controller {
    private final CertificateService certificateService;
    private final KalkanWrapper kalkanWrapper;

    @PostMapping("/info")
    public ResponseEntity<VerificationResponse> info(@Valid @RequestBody Pkcs12InfoRequest request) {
        return ResponseEntity.ok(certificateService.verifyCerts(request));
    }

    @PostMapping("/aliases")
    public ResponseEntity<Pkcs12AliasesResponse> aliases(@Valid @RequestBody Pkcs12InfoRequest request) {
        return ResponseEntity.ok(Pkcs12AliasesResponse.builder()
            .aliases(kalkanWrapper.read(request.getKeys()).stream()
                .map(KeyStoreWrapper::getAliases).toList())
            .build()
        );
    }
}

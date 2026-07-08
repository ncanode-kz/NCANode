package kz.ncanode.controller;

import kz.ncanode.dto.certificate.CertificateRevocation;
import kz.ncanode.dto.request.SbaVerifyRequest;
import kz.ncanode.dto.request.X509InfoRequest;
import kz.ncanode.dto.response.VerificationResponse;
import kz.ncanode.service.CertificateService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.validation.Valid;

import io.swagger.v3.oas.annotations.tags.Tag;

@Tag(name = "X509", description = "Методы для работы с x509")
@RestController
@RequestMapping("x509")
@RequiredArgsConstructor
public class X509Controller {
    private final CertificateService certificateService;

    @PostMapping("/info")
    public ResponseEntity<VerificationResponse> verify(@Valid @RequestBody X509InfoRequest x509InfoRequest) {
        return ResponseEntity.ok(certificateService.info(x509InfoRequest.getCerts(),
            x509InfoRequest.getRevocationCheck().contains(CertificateRevocation.OCSP),
            x509InfoRequest.getRevocationCheck().contains(CertificateRevocation.CRL)
        ));
    }
    @PostMapping("/verify")
    public ResponseEntity<VerificationResponse> verify(@Valid @RequestBody SbaVerifyRequest sbaVerifyRequest) {
        return ResponseEntity.ok(certificateService.verify(sbaVerifyRequest.getCertificate(),sbaVerifyRequest.getSignature(),sbaVerifyRequest.getData(),
            sbaVerifyRequest.getRevocationCheck().contains(CertificateRevocation.OCSP),
            sbaVerifyRequest.getRevocationCheck().contains(CertificateRevocation.CRL)
        ));
    }
}

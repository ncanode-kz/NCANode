package kz.ncanode.controller;

import kz.ncanode.dto.certificate.CertificateRevocation;
import kz.ncanode.dto.request.XmlSignRequest;
import kz.ncanode.dto.request.XmlVerifyRequest;
import kz.ncanode.dto.response.VerificationResponse;
import kz.ncanode.dto.response.XmlSignResponse;
import kz.ncanode.service.XmlService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.validation.Valid;

import io.swagger.v3.oas.annotations.tags.Tag;

@Tag(name = "XML", description = "Методы для работы с XML")
@RestController
@RequestMapping("xml")
@RequiredArgsConstructor
public class XmlController {
    private final XmlService xmlService;

    @PostMapping("/sign")
    public ResponseEntity<XmlSignResponse> sign(@Valid @RequestBody XmlSignRequest xmlSignRequest) {
        return ResponseEntity.ok(xmlService.sign(xmlSignRequest));
    }

    @PostMapping("/verify")
    public ResponseEntity<VerificationResponse> verify(@Valid @RequestBody XmlVerifyRequest xmlVerifyRequest) {
        return ResponseEntity.ok(xmlService.verify(xmlVerifyRequest.getXml(),
            xmlVerifyRequest.getRevocationCheck().contains(CertificateRevocation.OCSP),
            xmlVerifyRequest.getRevocationCheck().contains(CertificateRevocation.CRL)
        ));
    }
}

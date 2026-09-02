package kz.ncanode.controller;

import kz.ncanode.dto.certificate.CertificateRevocation;
import kz.ncanode.dto.request.WsseSignRequest;
import kz.ncanode.dto.request.XmlVerifyRequest;
import kz.ncanode.dto.response.VerificationResponse;
import kz.ncanode.dto.response.XmlSignResponse;
import kz.ncanode.service.WsseService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.validation.Valid;

import io.swagger.v3.oas.annotations.tags.Tag;

@Tag(name = "WSSE", description = "Методы для работы с WSSE")
@RestController
@RequestMapping("wsse")
@RequiredArgsConstructor
public class WsseController {

    private final WsseService wsseService;

    @PostMapping("/sign")
    public ResponseEntity<XmlSignResponse> sign(@Valid @RequestBody WsseSignRequest wsseSignRequest) {
        return ResponseEntity.ok(wsseService.sign(wsseSignRequest));
    }

    @PostMapping("/verify")
    public ResponseEntity<VerificationResponse> verify(@Valid @RequestBody XmlVerifyRequest xmlVerifyRequest) {
        return ResponseEntity.ok(wsseService.verify(xmlVerifyRequest.getXml(),
            xmlVerifyRequest.getRevocationCheck().contains(CertificateRevocation.OCSP),
            xmlVerifyRequest.getRevocationCheck().contains(CertificateRevocation.CRL)
        ));
    }
}

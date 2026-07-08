package kz.ncanode.controller;

import kz.ncanode.dto.certificate.CertificateRevocation;
import kz.ncanode.dto.request.CmsCreateRequest;
import kz.ncanode.dto.request.CmsVerifyRequest;
import kz.ncanode.dto.response.CmsDataResponse;
import kz.ncanode.dto.response.CmsResponse;
import kz.ncanode.dto.response.CmsVerificationResponse;
import kz.ncanode.service.CmsService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.validation.Valid;

import io.swagger.v3.oas.annotations.tags.Tag;

@Tag(name = "CMS", description = "Методы для работы с CMS")
@RestController
@RequestMapping("cms")
@RequiredArgsConstructor
public class CmsController {
    public final CmsService cmsService;

    @PostMapping("/sign")
    public ResponseEntity<CmsResponse> sign(@Valid @RequestBody CmsCreateRequest cmsCreateRequest) {
        return ResponseEntity.ok(cmsService.create(cmsCreateRequest));
    }

    @PostMapping("/sign/add")
    public ResponseEntity<CmsResponse> signAdd(@Valid @RequestBody CmsCreateRequest cmsCreateRequest) {
        return ResponseEntity.ok(cmsService.addSigners(cmsCreateRequest));
    }

    @PostMapping("/verify")
    public ResponseEntity<CmsVerificationResponse> verify(@Valid @RequestBody CmsVerifyRequest cmsVerifyRequest) {
        return ResponseEntity.ok(cmsService.verify(cmsVerifyRequest.getCms(),
            cmsVerifyRequest.getData(),
            cmsVerifyRequest.getRevocationCheck().contains(CertificateRevocation.OCSP),
            cmsVerifyRequest.getRevocationCheck().contains(CertificateRevocation.CRL)
        ));
    }

    @PostMapping("/extract")
    public ResponseEntity<CmsDataResponse> extract(@Valid @RequestBody CmsVerifyRequest cmsVerifyRequest) {
        return ResponseEntity.ok(cmsService.extract(cmsVerifyRequest.getCms()));
    }
}

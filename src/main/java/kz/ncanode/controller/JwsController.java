package kz.ncanode.controller;

import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import kz.ncanode.dto.request.JwsSignRequest;
import kz.ncanode.dto.request.JwsVerifyRequest;
import kz.ncanode.dto.response.JwsSignResponse;
import kz.ncanode.dto.response.JwsVerifyResponse;
import kz.ncanode.service.JwsService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "JWS", description = "Подпись и проверка произвольного JSON в формате JWS")
@RestController
@RequestMapping("jws")
@RequiredArgsConstructor
public class JwsController {
    private final JwsService jwsService;

    @PostMapping("/sign")
    public ResponseEntity<JwsSignResponse> sign(@Valid @RequestBody JwsSignRequest request) {
        return ResponseEntity.ok(jwsService.sign(request));
    }

    @PostMapping("/sign/add")
    public ResponseEntity<JwsSignResponse> signAdd(@Valid @RequestBody JwsSignRequest request) {
        return ResponseEntity.ok(jwsService.addSigners(request));
    }

    @PostMapping("/verify")
    public ResponseEntity<JwsVerifyResponse> verify(@Valid @RequestBody JwsVerifyRequest request) {
        return ResponseEntity.ok(jwsService.verify(request));
    }
}

package kz.ncanode.controller;

import kz.ncanode.dto.request.JwtDecodeRequest;
import kz.ncanode.dto.request.JwtEncodeRequest;
import kz.ncanode.dto.response.JwtDecodeResponse;
import kz.ncanode.dto.response.JwtEncodeResponse;
import kz.ncanode.service.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

import io.swagger.v3.oas.annotations.tags.Tag;

@Tag(name = "JWT", description = "Методы для работы с JWT")
@RestController
@RequestMapping("JWT")
@RequiredArgsConstructor
public class JwtController {
    private final JwtService jwtService;

    @PostMapping("/encode")
    public ResponseEntity<JwtEncodeResponse> encode(@Valid @RequestBody JwtEncodeRequest jwtEncodeRequest) {
        return ResponseEntity.ok(jwtService.encode(jwtEncodeRequest));
    }

    @PostMapping("/decode")
    public ResponseEntity<JwtDecodeResponse> decode(@Valid @RequestBody JwtDecodeRequest jwtDecodeRequest) {
        return ResponseEntity.ok(jwtService.decode(jwtDecodeRequest));
    }
}

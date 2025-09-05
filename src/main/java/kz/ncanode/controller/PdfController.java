package kz.ncanode.controller;

import kz.ncanode.dto.request.PdfSignRequest;
import kz.ncanode.dto.request.PdfVerifyRequest;
import kz.ncanode.dto.response.PdfSignResponse;
import kz.ncanode.dto.response.PdfVerificationResponse;
import kz.ncanode.service.PdfService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

import io.swagger.v3.oas.annotations.tags.Tag;

@Tag(name = "PDF", description = "Методы для работы с PDF")
@RestController
@RequestMapping("pdf")
@RequiredArgsConstructor
public class PdfController {

	private final PdfService pdfService;

	@PostMapping("/sign")
	public ResponseEntity<PdfSignResponse> sign(@Valid @RequestBody PdfSignRequest pdfSignRequest) {
		return ResponseEntity.ok(pdfService.sign(pdfSignRequest));
	}

	@PostMapping("/verify")
	public ResponseEntity<PdfVerificationResponse> verify(@Valid @RequestBody PdfVerifyRequest pdfVerifyRequest) {
		return ResponseEntity.ok(pdfService.verify(pdfVerifyRequest));
	}
}

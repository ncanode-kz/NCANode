package kz.ncanode.unit.service

import kz.ncanode.common.WithTestData
import kz.ncanode.dto.certificate.CertificateRevocation
import kz.ncanode.dto.crl.CrlResult
import kz.ncanode.dto.crl.CrlStatus
import kz.ncanode.dto.ocsp.OcspResult
import kz.ncanode.dto.ocsp.OcspStatus
import kz.ncanode.dto.request.PdfSignRequest
import kz.ncanode.dto.request.PdfVerifyRequest
import kz.ncanode.dto.request.SignerRequest
import kz.ncanode.exception.NoSignaturesFoundException
import kz.ncanode.exception.ServerException
import kz.ncanode.service.CertificateService
import kz.ncanode.service.PdfService
import kz.ncanode.service.TspService
import kz.ncanode.wrapper.CertificateWrapper
import org.apache.pdfbox.pdmodel.PDDocument
import org.apache.pdfbox.pdmodel.PDPage
import org.mockito.invocation.InvocationOnMock
import org.mockito.stubbing.Answer
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.boot.test.mock.mockito.SpyBean
import spock.lang.Unroll
import spock.lang.Specification

import static org.mockito.ArgumentMatchers.any
import static org.mockito.ArgumentMatchers.anyBoolean
import static org.mockito.Mockito.doAnswer
import static org.mockito.Mockito.mock
import static org.mockito.Mockito.when

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class PdfServiceTest extends Specification implements WithTestData {

    @Autowired
    PdfService pdfService

    @MockBean
    CertificateService certificateService

    @SpyBean
    TspService tspService

    @Unroll("#caseName")
    def "test pdf signing"() {
        given:
        def request = buildSignRequest(signerKeys)

        when:
        def response = pdfService.sign(request)
        def signedBytes = Base64.decoder.decode(response.pdf)
        def document = PDDocument.load(new ByteArrayInputStream(signedBytes))

        then:
        response != null
        response.pdf != null

        and: 'check signatures quantity'
        document.getSignatureDictionaries().size() == signerKeys.size()

        cleanup:
        document?.close()

        where:
        caseName           | signerKeys
        'one signer 2004'  | [[KEY_INDIVIDUAL_VALID_SIGN_2004, KEY_INDIVIDUAL_VALID_SIGN_2004_PASSWORD]]
        'one signer 2015'  | [[KEY_INDIVIDUAL_VALID_2015, KEY_INDIVIDUAL_VALID_2015_PASSWORD]]
        'two signers'      | [[KEY_INDIVIDUAL_VALID_SIGN_2004, KEY_INDIVIDUAL_VALID_SIGN_2004_PASSWORD],
                              [KEY_INDIVIDUAL_VALID_2015, KEY_INDIVIDUAL_VALID_2015_PASSWORD]]
    }

    def "test pdf signing with tsp"() {
        given: 'tsp service returns signer untouched'
        doAnswer({ InvocationOnMock inv -> inv.getArgument(0) })
            .when(tspService).addTspToSigner(any(), any(), any())

        def request = buildSignRequest([[KEY_INDIVIDUAL_VALID_SIGN_2004, KEY_INDIVIDUAL_VALID_SIGN_2004_PASSWORD]])
        request.setWithTsp(true)

        when:
        def response = pdfService.sign(request)
        def document = PDDocument.load(new ByteArrayInputStream(Base64.decoder.decode(response.pdf)))

        then:
        response.pdf != null
        document.getSignatureDictionaries().size() == 1

        cleanup:
        document?.close()
    }

    def "test pdf signing with invalid key"() {
        given:
        def request = buildSignRequest([[KEY_INVALID, KEY_INVALID_PASSWORD]])

        when:
        pdfService.sign(request)

        then:
        thrown(ServerException)
    }

    def "test pdf signing with invalid pdf"() {
        given:
        def request = buildSignRequest([[KEY_INDIVIDUAL_VALID_SIGN_2004, KEY_INDIVIDUAL_VALID_SIGN_2004_PASSWORD]])
        request.setPdf(Base64.encoder.encodeToString('not a pdf'.bytes))

        when:
        pdfService.sign(request)

        then:
        thrown(ServerException)
    }

    @Unroll("#caseName")
    def "test pdf verification"() {
        given: 'sign pdf'
        def signedPdf = pdfService.sign(buildSignRequest([[KEY_INDIVIDUAL_VALID_SIGN_2004, KEY_INDIVIDUAL_VALID_SIGN_2004_PASSWORD]])).pdf

        and: 'mock certificate validation'
        def issuerCert = hasIssuer ? mockIssuerCertificate(true) : null
        when(certificateService.getCurrentDate()).thenReturn(buildValidDate())
        when(certificateService.attachValidationData(any(), anyBoolean(), anyBoolean()))
            .thenAnswer(new CertificateServiceAnswer(issuerCert))

        def request = PdfVerifyRequest.builder()
            .pdf(signedPdf)
            .revocationCheck(revocationCheck)
            .build()

        when:
        def response = pdfService.verify(request)

        then:
        response != null
        response.signers.size() == 1

        and:
        response.valid == expectedValid
        response.signers[0].certificate != null

        where:
        caseName             | hasIssuer | revocationCheck                                                || expectedValid
        'valid signer'       | true      | Set.of()                                                       || true
        'valid ocsp and crl' | true      | Set.of(CertificateRevocation.OCSP, CertificateRevocation.CRL)  || true
        'invalid issuer'     | false     | Set.of()                                                       || false
    }

    @Unroll("#file")
    def "verify the reference PAdES fixtures (exercises the /DSS revocation reader)"() {
        given:
        def issuer = mockIssuerCertificate(true)
        when(certificateService.getCurrentDate())
            .thenReturn(Date.from(java.time.Instant.parse('2026-09-02T11:00:00Z')))
        when(certificateService.attachValidationData(any(), anyBoolean(), anyBoolean()))
            .thenAnswer(new CertificateServiceAnswer(issuer))

        def request = PdfVerifyRequest.builder()
            .pdf(Base64.encoder.encodeToString(
                org.springframework.util.ResourceUtils.getFile("classpath:pades/${file}").bytes))
            .build()

        when:
        def response = pdfService.verify(request)

        then:
        response != null
        response.signers.size() == 1
        response.signers[0].certificate != null

        where:
        file << ['sample-signed-b.pdf', 'sample-signed-t.pdf',
                 'sample-signed-lt.pdf', 'sample-signed-lta.pdf']
    }

    def "test pdf verification without signatures"() {
        given:
        def request = PdfVerifyRequest.builder()
            .pdf(Base64.encoder.encodeToString(createTestPdf()))
            .build()

        when:
        pdfService.verify(request)

        then:
        thrown(NoSignaturesFoundException)
    }

    def "test pdf verification with invalid pdf"() {
        given:
        def request = PdfVerifyRequest.builder()
            .pdf(Base64.encoder.encodeToString('not a pdf'.bytes))
            .build()

        when:
        pdfService.verify(request)

        then:
        thrown(ServerException)
    }

    private static byte[] createTestPdf() {
        def document = new PDDocument()
        document.addPage(new PDPage())
        def out = new ByteArrayOutputStream()
        document.save(out)
        document.close()
        return out.toByteArray()
    }

    private static PdfSignRequest buildSignRequest(List<List<String>> signerKeys) {
        def request = new PdfSignRequest()
        request.setPdf(Base64.encoder.encodeToString(createTestPdf()))
        request.setSigners(signerKeys.collect { key ->
            def signer = new PdfSignRequest.PdfSigner()
            signer.setReason('test reason')
            signer.setLocation('Almaty')
            signer.setContactInfo('test@example.com')
            signer.setSigner(SignerRequest.builder().key(key[0]).password(key[1]).build())
            return signer
        })
        return request
    }

    // Дата в пределах срока действия KEY_INDIVIDUAL_VALID_SIGN_2004 (2021-01-18 .. 2022-01-18).
    private static Date buildValidDate() {
        Date.from(java.time.Instant.parse("2021-07-01T00:00:00Z"))
    }

    private CertificateWrapper mockIssuerCertificate(boolean dateValid) {
        def cert = mock(CertificateWrapper)
        when(cert.isDateValid(any())).thenReturn(dateValid)
        return cert
    }

    private OcspStatus mockOcspStatus() {
        def status = mock(OcspStatus)
        when(status.getResult()).thenReturn(OcspResult.ACTIVE)
        when(status.isActive()).thenReturn(true)
        return status
    }

    private CrlStatus mockCrlStatus() {
        def status = mock(CrlStatus)
        when(status.getResult()).thenReturn(CrlResult.ACTIVE)
        return status
    }

    protected class CertificateServiceAnswer implements Answer<Void> {

        private CertificateWrapper issuerCert

        CertificateServiceAnswer(CertificateWrapper issuerCert) {
            this.issuerCert = issuerCert
        }

        @Override
        Void answer(InvocationOnMock invocation) throws Throwable {
            CertificateWrapper cert = invocation.getArgument(0, CertificateWrapper)
            boolean withOcsp = invocation.getArgument(1, Boolean)
            boolean withCrl = invocation.getArgument(2, Boolean)

            cert.setIssuerCertificate(issuerCert)
            cert.setOcspStatus(withOcsp ? [mockOcspStatus()] : null)
            cert.setCrlStatus(withCrl ? mockCrlStatus() : null)
            return null
        }
    }
}

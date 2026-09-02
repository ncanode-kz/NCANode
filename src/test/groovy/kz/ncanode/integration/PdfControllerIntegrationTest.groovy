package kz.ncanode.integration

import com.fasterxml.jackson.databind.ObjectMapper
import kz.ncanode.common.IntegrationSpecification
import kz.ncanode.controller.PdfController
import kz.ncanode.dto.request.PdfSignRequest
import kz.ncanode.dto.request.PdfVerifyRequest
import kz.ncanode.dto.request.SignerRequest
import kz.ncanode.dto.response.PdfSignResponse
import kz.ncanode.dto.response.PdfVerificationResponse
import kz.ncanode.service.PdfService
import org.apache.pdfbox.pdmodel.PDDocument
import org.apache.pdfbox.pdmodel.PDPage
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class PdfControllerIntegrationTest extends IntegrationSpecification {

    private final static String URI_SIGN = "/pdf/sign"
    private final static String URI_VERIFY = "/pdf/verify"

    @Autowired
    PdfService pdfService

    def setup() {
        configureMockMvc(new PdfController(pdfService))
    }

    private static String samplePdf() {
        def document = new PDDocument()
        document.addPage(new PDPage())
        def out = new ByteArrayOutputStream()
        document.save(out)
        document.close()
        Base64.encoder.encodeToString(out.toByteArray())
    }

    def "sign then verify a pdf through the controller"() {
        given:
        def signRequest = new PdfSignRequest()
        signRequest.pdf = samplePdf()
        def signer = new PdfSignRequest.PdfSigner()
        signer.signer = SignerRequest.builder()
            .key(KEY_INDIVIDUAL_VALID_SIGN_2004)
            .password(KEY_INDIVIDUAL_VALID_SIGN_2004_PASSWORD)
            .build()
        signRequest.signers = [signer]

        when:
        def signed = doPostQuery(URI_SIGN, new ObjectMapper().writeValueAsString(signRequest), 200, PdfSignResponse)

        then:
        signed.pdf != null

        when:
        def verifyRequest = PdfVerifyRequest.builder().pdf(signed.pdf).build()
        def verified = doPostQuery(URI_VERIFY, new ObjectMapper().writeValueAsString(verifyRequest), 200, PdfVerificationResponse)

        then:
        verified != null
        verified.signers.size() == 1
    }
}

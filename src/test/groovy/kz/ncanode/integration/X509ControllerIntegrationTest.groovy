package kz.ncanode.integration

import com.fasterxml.jackson.databind.ObjectMapper
import kz.ncanode.common.IntegrationSpecification
import kz.ncanode.controller.X509Controller
import kz.ncanode.dto.request.SbaSignRequest
import kz.ncanode.dto.request.SbaVerifyRequest
import kz.ncanode.dto.request.SignerRequest
import kz.ncanode.dto.request.X509InfoRequest
import kz.ncanode.dto.response.SbaSignResponse
import kz.ncanode.dto.response.VerificationResponse
import kz.ncanode.service.CertificateService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class X509ControllerIntegrationTest extends IntegrationSpecification {

    // URI
    private final static String URI_INFO = "/x509/info"
    private final static String URI_SIGN = "/x509/sign"
    private final static String URI_VERIFY = "/x509/verify"

    @Autowired
    CertificateService certificateService

    def setup() {
        configureMockMvc(new X509Controller(certificateService))
    }

    def "test x509 sign then verify"() {
        given:
        def signRequest = new SbaSignRequest()
        signRequest.data = 'payload-to-sign'
        signRequest.signer = SignerRequest.builder()
            .key(KEY_INDIVIDUAL_VALID_2015)
            .password(KEY_INDIVIDUAL_VALID_2015_PASSWORD)
            .build()

        when:
        def signed = doPostQuery(URI_SIGN, new ObjectMapper().writeValueAsString(signRequest), 200, SbaSignResponse)

        then:
        signed.certificate != null
        signed.signature != null

        when:
        def verifyRequest = SbaVerifyRequest.builder()
            .certificate(signed.certificate)
            .signature(signed.signature)
            .data('payload-to-sign')
            .build()
        def verified = doPostQuery(URI_VERIFY, new ObjectMapper().writeValueAsString(verifyRequest), 200, VerificationResponse)

        then:
        verified.signers.size() == 1
    }

    def "test x509 verify with an invalid certificate"() {
        given:
        def verifyRequest = SbaVerifyRequest.builder()
            .certificate('YXNkYXNk')
            .signature('YXNk')
            .data('x')
            .build()

        when:
        def verified = doPostQuery(URI_VERIFY, new ObjectMapper().writeValueAsString(verifyRequest), 200, VerificationResponse)

        then:
        !verified.valid
        verified.message == '[0]: Invalid certificate given.'
    }

    def "test x509 info"() {
        given:
        def request = X509InfoRequest.builder()
            .certs([CERT_INDIVIDUAL])
            .build()

        def requestJson = new ObjectMapper().writeValueAsString(request)

        when:
        def response = doPostQuery(URI_INFO, requestJson, 200, VerificationResponse)

        then:
        response != null
        response.signers.size() == 1
        !response.valid
    }
}

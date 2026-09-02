package kz.ncanode.integration

import com.fasterxml.jackson.databind.ObjectMapper
import kz.ncanode.common.IntegrationSpecification
import kz.ncanode.controller.JwsController
import kz.ncanode.dto.request.JwsSignRequest
import kz.ncanode.dto.request.JwsSignerRequest
import kz.ncanode.dto.request.JwsVerifyRequest
import kz.ncanode.dto.response.JwsSignResponse
import kz.ncanode.dto.response.JwsVerifyResponse
import kz.ncanode.service.CertificateService
import kz.ncanode.service.JwsService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.mock.mockito.MockBean

import static org.mockito.Mockito.when

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class JwsControllerIntegrationTest extends IntegrationSpecification {

    private final static String URI_SIGN     = "/jws/sign"
    private final static String URI_SIGN_ADD = "/jws/sign/add"
    private final static String URI_VERIFY   = "/jws/verify"

    @Autowired
    JwsService jwsService

    @Autowired
    ObjectMapper mapper

    @MockBean
    CertificateService certificateService

    def setup() {
        when(certificateService.getCurrentDate()).thenReturn(new Date())
        configureMockMvc(new JwsController(jwsService))
    }

    private JwsSignerRequest signer() {
        JwsSignerRequest.builder()
            .alg("GG2015")
            .key(KEY_INDIVIDUAL_VALID_2015)
            .password(KEY_INDIVIDUAL_VALID_2015_PASSWORD)
            .build()
    }

    def "POST /jws/sign then /jws/verify"() {
        given:
        def signJson = mapper.writeValueAsString(JwsSignRequest.builder()
            .payload(mapper.valueToTree([sub: "int-test"]))
            .signers([signer()])
            .build())

        when:
        def signResponse = doPostQuery(URI_SIGN, signJson, 200, JwsSignResponse)

        then:
        signResponse.jws.get("signatures").size() == 1

        when:
        def verifyJson = mapper.writeValueAsString(JwsVerifyRequest.builder()
            .jws(signResponse.jws)
            .build())
        def verifyResponse = doPostQuery(URI_VERIFY, verifyJson, 200, JwsVerifyResponse)

        then:
        verifyResponse.valid
        verifyResponse.signers.size() == 1
    }

    def "POST /jws/sign/add appends a signer"() {
        given:
        def first = doPostQuery(URI_SIGN, mapper.writeValueAsString(JwsSignRequest.builder()
            .payload(mapper.valueToTree([msg: "add"]))
            .signers([signer()])
            .build()), 200, JwsSignResponse)

        when:
        def addJson = mapper.writeValueAsString(JwsSignRequest.builder()
            .jws(first.jws)
            .signers([signer()])
            .build())
        def second = doPostQuery(URI_SIGN_ADD, addJson, 200, JwsSignResponse)

        then:
        second.jws.get("signatures").size() == 2
    }
}

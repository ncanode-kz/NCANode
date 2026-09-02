package kz.ncanode.integration

import com.fasterxml.jackson.databind.ObjectMapper
import kz.ncanode.common.IntegrationSpecification
import kz.ncanode.controller.JwtController
import kz.ncanode.dto.request.JwtDecodeRequest
import kz.ncanode.dto.request.JwtEncodeRequest
import kz.ncanode.dto.response.JwtDecodeResponse
import kz.ncanode.dto.response.JwtEncodeResponse
import kz.ncanode.service.CertificateService
import kz.ncanode.service.JwtService
import kz.ncanode.wrapper.KalkanWrapper
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.mock.mockito.MockBean

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class JwtControllerIntegrationTest extends IntegrationSpecification {

    private final static String URI_ENCODE = "/jwt/encode"
    private final static String URI_DECODE = "/jwt/decode"

    @Autowired
    JwtService jwtService

    @Autowired
    KalkanWrapper kalkanWrapper

    @MockBean
    CertificateService certificateService

    def setup() {
        configureMockMvc(new JwtController(jwtService))
    }

    def "POST /jwt/encode then /jwt/decode"() {
        given:
        def payload = new JwtEncodeRequest.JwtPayload()
        payload.setClaim("sub", "int-test")

        def encodeJson = new ObjectMapper().writeValueAsString(JwtEncodeRequest.builder()
            .jwt(JwtEncodeRequest.JwtRequest.builder()
                .header(JwtEncodeRequest.JwtHeader.builder().alg("GG2015").typ("JWT").build())
                .payload(payload)
                .build())
            .key(KEY_INDIVIDUAL_VALID_2015)
            .password(KEY_INDIVIDUAL_VALID_2015_PASSWORD)
            .build())

        when:
        def encodeResponse = doPostQuery(URI_ENCODE, encodeJson, 200, JwtEncodeResponse)

        then:
        encodeResponse.jwt.split('\\.').length == 3

        when:
        def keystore = kalkanWrapper.read(KEY_INDIVIDUAL_VALID_2015, null, KEY_INDIVIDUAL_VALID_2015_PASSWORD)
        def certBase64 = Base64.encoder.encodeToString(keystore.getCertificate().getX509Certificate().getEncoded())
        def decodeJson = new ObjectMapper().writeValueAsString(JwtDecodeRequest.builder()
            .jwt(encodeResponse.jwt)
            .key(certBase64)
            .build())
        def decodeResponse = doPostQuery(URI_DECODE, decodeJson, 200, JwtDecodeResponse)

        then:
        decodeResponse.valid
        decodeResponse.jwt.payload.get("sub") == "int-test"
    }
}

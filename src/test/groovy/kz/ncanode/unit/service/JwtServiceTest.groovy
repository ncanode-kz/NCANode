package kz.ncanode.unit.service

import kz.ncanode.common.WithTestData
import kz.ncanode.dto.request.JwtDecodeRequest
import kz.ncanode.dto.request.JwtEncodeRequest
import kz.ncanode.exception.ClientException
import kz.ncanode.service.CertificateService
import kz.ncanode.service.JwtService
import kz.ncanode.wrapper.KalkanWrapper
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.mock.mockito.MockBean
import spock.lang.Specification

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class JwtServiceTest extends Specification implements WithTestData {

    @Autowired
    JwtService jwtService

    @Autowired
    KalkanWrapper kalkanWrapper

    @MockBean
    CertificateService certificateService

    def "test jwt encode with GOST 2015 key"() {
        given:
        def payload = new JwtEncodeRequest.JwtPayload()
        payload.setClaim("sub", "test_subject")
        payload.setClaim("iss", "ncanode")

        def header = JwtEncodeRequest.JwtHeader.builder()
            .alg("GG2015")
            .typ("JWT")
            .build()

        def jwtRequest = JwtEncodeRequest.JwtRequest.builder()
            .header(header)
            .payload(payload)
            .build()

        def request = JwtEncodeRequest.builder()
            .jwt(jwtRequest)
            .key(KEY_INDIVIDUAL_VALID_2015)
            .password(KEY_INDIVIDUAL_VALID_2015_PASSWORD)
            .build()

        when:
        def response = jwtService.encode(request)

        then:
        response != null
        response.jwt != null
        !response.jwt.isEmpty()

        and: 'JWT has 3 parts'
        response.jwt.split('\\.').length == 3
    }

    def "test jwt encode and decode roundtrip"() {
        given: 'encode a JWT'
        def payload = new JwtEncodeRequest.JwtPayload()
        payload.setClaim("sub", "roundtrip_test")
        payload.setClaim("data", "some_value")

        def header = JwtEncodeRequest.JwtHeader.builder()
            .alg("GG2015")
            .typ("JWT")
            .build()

        def jwtRequest = JwtEncodeRequest.JwtRequest.builder()
            .header(header)
            .payload(payload)
            .build()

        def encodeRequest = JwtEncodeRequest.builder()
            .jwt(jwtRequest)
            .key(KEY_INDIVIDUAL_VALID_2015)
            .password(KEY_INDIVIDUAL_VALID_2015_PASSWORD)
            .build()

        def encodeResponse = jwtService.encode(encodeRequest)

        and: 'extract certificate from the same key for verification'
        def keystore = kalkanWrapper.read(KEY_INDIVIDUAL_VALID_2015, null, KEY_INDIVIDUAL_VALID_2015_PASSWORD)
        def certBase64 = Base64.encoder.encodeToString(keystore.getCertificate().getX509Certificate().getEncoded())

        def decodeRequest = JwtDecodeRequest.builder()
            .jwt(encodeResponse.jwt)
            .key(certBase64)
            .build()

        when:
        def decodeResponse = jwtService.decode(decodeRequest)

        then:
        decodeResponse != null
        decodeResponse.valid == true
        decodeResponse.jwt != null
        decodeResponse.jwt.header.get("alg") == "GG2015"
        decodeResponse.jwt.header.get("typ") == "JWT"
        decodeResponse.jwt.payload.get("sub") == "roundtrip_test"
        decodeResponse.jwt.payload.get("data") == "some_value"
    }

    def "test jwt decode with wrong key returns valid=false"() {
        given: 'encode with 2015 key'
        def payload = new JwtEncodeRequest.JwtPayload()
        payload.setClaim("sub", "test")

        def header = JwtEncodeRequest.JwtHeader.builder()
            .alg("GG2015")
            .typ("JWT")
            .build()

        def jwtRequest = JwtEncodeRequest.JwtRequest.builder()
            .header(header)
            .payload(payload)
            .build()

        def encodeRequest = JwtEncodeRequest.builder()
            .jwt(jwtRequest)
            .key(KEY_INDIVIDUAL_VALID_2015)
            .password(KEY_INDIVIDUAL_VALID_2015_PASSWORD)
            .build()

        def encodeResponse = jwtService.encode(encodeRequest)

        and: 'decode with NCA CA certificate (different key)'
        def decodeRequest = JwtDecodeRequest.builder()
            .jwt(encodeResponse.jwt)
            .key(NCA_2015_CERT)
            .build()

        when:
        def decodeResponse = jwtService.decode(decodeRequest)

        then:
        decodeResponse != null
        decodeResponse.valid == false
        decodeResponse.jwt != null
    }

    def "test jwt encode with unsupported algorithm throws exception"() {
        given:
        def payload = new JwtEncodeRequest.JwtPayload()
        payload.setClaim("sub", "test")

        def header = JwtEncodeRequest.JwtHeader.builder()
            .alg("UNSUPPORTED")
            .typ("JWT")
            .build()

        def jwtRequest = JwtEncodeRequest.JwtRequest.builder()
            .header(header)
            .payload(payload)
            .build()

        def request = JwtEncodeRequest.builder()
            .jwt(jwtRequest)
            .key(KEY_INDIVIDUAL_VALID_2015)
            .password(KEY_INDIVIDUAL_VALID_2015_PASSWORD)
            .build()

        when:
        jwtService.encode(request)

        then:
        thrown(Exception)
    }

    def "test jwt decode with invalid jwt string throws exception"() {
        given:
        def decodeRequest = JwtDecodeRequest.builder()
            .jwt("not-a-valid-jwt")
            .key(NCA_2015_CERT)
            .build()

        when:
        jwtService.decode(decodeRequest)

        then:
        thrown(ClientException)
    }

    def "test jwt encode with multiple claims preserves all claims"() {
        given:
        def payload = new JwtEncodeRequest.JwtPayload()
        payload.setClaim("cbin", "012345678909")
        payload.setClaim("mcheck", "DS")

        def header = JwtEncodeRequest.JwtHeader.builder()
            .alg("GG2015")
            .typ("JWT")
            .build()

        def jwtRequest = JwtEncodeRequest.JwtRequest.builder()
            .header(header)
            .payload(payload)
            .build()

        def encodeRequest = JwtEncodeRequest.builder()
            .jwt(jwtRequest)
            .key(KEY_INDIVIDUAL_VALID_2015)
            .password(KEY_INDIVIDUAL_VALID_2015_PASSWORD)
            .build()

        def encodeResponse = jwtService.encode(encodeRequest)

        and:
        def keystore = kalkanWrapper.read(KEY_INDIVIDUAL_VALID_2015, null, KEY_INDIVIDUAL_VALID_2015_PASSWORD)
        def certBase64 = Base64.encoder.encodeToString(keystore.getCertificate().getX509Certificate().getEncoded())

        def decodeRequest = JwtDecodeRequest.builder()
            .jwt(encodeResponse.jwt)
            .key(certBase64)
            .build()

        when:
        def decodeResponse = jwtService.decode(decodeRequest)

        then:
        decodeResponse.valid == true
        decodeResponse.jwt.payload.get("cbin") == "012345678909"
        decodeResponse.jwt.payload.get("mcheck") == "DS"
    }
}

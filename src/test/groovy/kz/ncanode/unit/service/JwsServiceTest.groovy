package kz.ncanode.unit.service

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ObjectNode
import kz.ncanode.common.WithTestData
import kz.ncanode.dto.request.JwsSignRequest
import kz.ncanode.dto.request.JwsSignerRequest
import kz.ncanode.dto.request.JwsVerifyRequest
import kz.ncanode.exception.ClientException
import kz.ncanode.service.CertificateService
import kz.ncanode.service.JwsService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.mock.mockito.MockBean
import spock.lang.Specification

import static org.mockito.Mockito.when

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class JwsServiceTest extends Specification implements WithTestData {

    @Autowired
    JwsService jwsService

    @Autowired
    ObjectMapper mapper

    @MockBean
    CertificateService certificateService

    def setup() {
        when(certificateService.getCurrentDate()).thenReturn(new Date())
    }

    private JwsSignerRequest signer2015(String alg = "GG2015") {
        JwsSignerRequest.builder()
            .alg(alg)
            .key(KEY_INDIVIDUAL_VALID_2015)
            .password(KEY_INDIVIDUAL_VALID_2015_PASSWORD)
            .build()
    }

    // KEY_INDIVIDUAL_VALID_SIGN_2004 — RSA-ключ старого образца
    private JwsSignerRequest signerRsa() {
        JwsSignerRequest.builder()
            .alg("RS256")
            .key(KEY_INDIVIDUAL_VALID_SIGN_2004)
            .password(KEY_INDIVIDUAL_VALID_SIGN_2004_PASSWORD)
            .build()
    }

    def "sign object payload produces JSON serialization with one signature"() {
        given:
        def request = JwsSignRequest.builder()
            .payload(mapper.valueToTree([sub: "test", nested: [a: 1]]))
            .signers([signer2015()])
            .build()

        when:
        def response = jwsService.sign(request)

        then:
        response.jws.has("payload")
        response.jws.get("signatures").size() == 1
        response.jws.get("signatures").get(0).has("protected")
        response.jws.get("signatures").get(0).has("signature")
    }

    def "sign + verify roundtrip for #desc payload"() {
        given:
        def signResponse = jwsService.sign(JwsSignRequest.builder()
            .payload(mapper.valueToTree(payload))
            .signers([signer2015()])
            .build())

        when:
        def verifyResponse = jwsService.verify(JwsVerifyRequest.builder()
            .jws(signResponse.jws)
            .build())

        then:
        verifyResponse.valid
        verifyResponse.signers.size() == 1
        verifyResponse.signers.get(0).valid
        verifyResponse.signers.get(0).certificate != null
        verifyResponse.payload == mapper.valueToTree(payload)

        where:
        desc      | payload
        "object"  | [doc: [id: 42], items: ["a", "b"]]
        "array"   | [1, 2, [x: "y"]]
        "scalar"  | "just a string"
        "number"  | 12345
    }

    def "multi-signature sign then verify all"() {
        given:
        def signResponse = jwsService.sign(JwsSignRequest.builder()
            .payload(mapper.valueToTree([msg: "multi"]))
            .signers([signer2015(), signerRsa()])
            .build())

        when:
        def verifyResponse = jwsService.verify(JwsVerifyRequest.builder()
            .jws(signResponse.jws)
            .build())

        then:
        verifyResponse.signers.size() == 2
        verifyResponse.valid
        verifyResponse.signers.every { it.valid }
    }

    def "sign/add appends a signer to existing JWS"() {
        given:
        def first = jwsService.sign(JwsSignRequest.builder()
            .payload(mapper.valueToTree([msg: "add"]))
            .signers([signer2015()])
            .build())

        when:
        def second = jwsService.addSigners(JwsSignRequest.builder()
            .jws(first.jws)
            .signers([signerRsa()])
            .build())

        then:
        second.jws.get("signatures").size() == 2

        and:
        def verifyResponse = jwsService.verify(JwsVerifyRequest.builder().jws(second.jws).build())
        verifyResponse.valid
        verifyResponse.signers.size() == 2
    }

    def "detached sign omits payload, verify needs it supplied"() {
        given:
        def payload = mapper.valueToTree([detached: true])
        def signResponse = jwsService.sign(JwsSignRequest.builder()
            .payload(payload)
            .detached(true)
            .signers([signer2015()])
            .build())

        expect: 'no embedded payload'
        !signResponse.jws.has("payload")

        when: 'verify with payload provided'
        def ok = jwsService.verify(JwsVerifyRequest.builder()
            .jws(signResponse.jws)
            .payload(payload)
            .build())

        then:
        ok.valid
        ok.payload == payload

        when: 'verify without payload'
        jwsService.verify(JwsVerifyRequest.builder().jws(signResponse.jws).build())

        then:
        thrown(ClientException)
    }

    def "detached sign/add then verify"() {
        given:
        def payload = mapper.valueToTree([x: 1])
        def first = jwsService.sign(JwsSignRequest.builder()
            .payload(payload).detached(true).signers([signer2015()]).build())

        when:
        def second = jwsService.addSigners(JwsSignRequest.builder()
            .jws(first.jws).payload(payload).signers([signerRsa()]).build())

        then:
        !second.jws.has("payload")
        def verifyResponse = jwsService.verify(JwsVerifyRequest.builder()
            .jws(second.jws).payload(payload).build())
        verifyResponse.valid
        verifyResponse.signers.size() == 2
    }

    def "tampered payload fails verification"() {
        given:
        def signResponse = jwsService.sign(JwsSignRequest.builder()
            .payload(mapper.valueToTree([amount: 100]))
            .signers([signer2015()])
            .build())

        and: 'swap the payload for a different one'
        def tampered = signResponse.jws.deepCopy() as ObjectNode
        tampered.put("payload", Base64.urlEncoder.withoutPadding().encodeToString('{"amount":999}'.bytes))

        when:
        def verifyResponse = jwsService.verify(JwsVerifyRequest.builder().jws(tampered).build())

        then:
        !verifyResponse.valid
        !verifyResponse.signers.get(0).valid
    }

    private ObjectNode flatten(ObjectNode jws) {
        def sig0 = jws.get("signatures").get(0)
        def flat = mapper.createObjectNode()
        flat.put("payload", jws.get("payload").asText())
        flat.set("protected", sig0.get("protected"))
        flat.set("signature", sig0.get("signature"))
        return flat
    }

    def "verify accepts flattened (single-signature) JWS"() {
        given:
        def signed = jwsService.sign(JwsSignRequest.builder()
            .payload(mapper.valueToTree([flat: true]))
            .signers([signer2015()])
            .build())

        when:
        def verifyResponse = jwsService.verify(JwsVerifyRequest.builder()
            .jws(flatten(signed.jws as ObjectNode))
            .build())

        then:
        verifyResponse.valid
        verifyResponse.signers.size() == 1
    }

    def "sign/add normalizes a flattened JWS before appending"() {
        given:
        def signed = jwsService.sign(JwsSignRequest.builder()
            .payload(mapper.valueToTree([flat: true]))
            .signers([signer2015()])
            .build())

        when:
        def result = jwsService.addSigners(JwsSignRequest.builder()
            .jws(flatten(signed.jws as ObjectNode))
            .signers([signerRsa()])
            .build())

        then:
        result.jws.get("signatures").size() == 2
        jwsService.verify(JwsVerifyRequest.builder().jws(result.jws).build()).valid
    }

    def "verify fails when protected header has no x5c"() {
        given:
        def signed = jwsService.sign(JwsSignRequest.builder()
            .payload(mapper.valueToTree([a: 1]))
            .signers([signer2015()])
            .build())

        and: 'strip x5c from the protected header'
        def tampered = signed.jws.deepCopy() as ObjectNode
        def sig0 = tampered.get("signatures").get(0) as ObjectNode
        def header = mapper.readTree(Base64.urlDecoder.decode(sig0.get("protected").asText())) as ObjectNode
        header.remove("x5c")
        sig0.put("protected", Base64.urlEncoder.withoutPadding().encodeToString(mapper.writeValueAsBytes(header)))

        when:
        jwsService.verify(JwsVerifyRequest.builder().jws(tampered).build())

        then:
        thrown(ClientException)
    }

    def "verify with revocation check and no validation data marks signer invalid"() {
        given:
        def signed = jwsService.sign(JwsSignRequest.builder()
            .payload(mapper.valueToTree([a: 1]))
            .signers([signer2015()])
            .build())

        when:
        def verifyResponse = jwsService.verify(JwsVerifyRequest.builder()
            .jws(signed.jws)
            .revocationCheck([kz.ncanode.dto.certificate.CertificateRevocation.OCSP] as Set)
            .build())

        then:
        !verifyResponse.valid
        !verifyResponse.signers.get(0).valid
    }

    def "verify with malformed jws throws ClientException"() {
        when:
        jwsService.verify(JwsVerifyRequest.builder().jws(mapper.valueToTree([foo: "bar"])).build())

        then:
        thrown(ClientException)
    }

    def "sign without payload throws ClientException"() {
        when:
        jwsService.sign(JwsSignRequest.builder().signers([signer2015()]).build())

        then:
        thrown(ClientException)
    }

    def "sign with wrong key password throws ClientException"() {
        when:
        jwsService.sign(JwsSignRequest.builder()
            .payload(mapper.valueToTree([a: 1]))
            .signers([JwsSignerRequest.builder()
                .alg("GG2015")
                .key(KEY_INDIVIDUAL_VALID_2015)
                .password("wrong-password")
                .build()])
            .build())

        then:
        thrown(ClientException)
    }

    def "sign/add without jws throws ClientException"() {
        when:
        jwsService.addSigners(JwsSignRequest.builder().signers([signer2015()]).build())

        then:
        thrown(ClientException)
    }

    def "sign/add on detached JWS without payload throws ClientException"() {
        given:
        def signed = jwsService.sign(JwsSignRequest.builder()
            .payload(mapper.valueToTree([a: 1])).detached(true).signers([signer2015()]).build())

        when:
        jwsService.addSigners(JwsSignRequest.builder().jws(signed.jws).signers([signerRsa()]).build())

        then:
        thrown(ClientException)
    }

    def "verify JWS with empty signatures throws ClientException"() {
        given:
        def jws = mapper.createObjectNode()
        jws.put("payload", Base64.urlEncoder.withoutPadding().encodeToString('{}'.bytes))
        jws.set("signatures", mapper.createArrayNode())

        when:
        jwsService.verify(JwsVerifyRequest.builder().jws(jws).build())

        then:
        thrown(ClientException)
    }

    def "sign with unsupported algorithm throws exception"() {
        when:
        jwsService.sign(JwsSignRequest.builder()
            .payload(mapper.valueToTree([a: 1]))
            .signers([signer2015("XX999")])
            .build())

        then:
        thrown(Exception)
    }
}

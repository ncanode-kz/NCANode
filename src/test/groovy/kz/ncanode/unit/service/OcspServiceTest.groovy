package kz.ncanode.unit.service

import kz.ncanode.common.WithTestData
import kz.ncanode.dto.ocsp.OcspResult
import kz.ncanode.service.OcspService
import kz.ncanode.wrapper.CertificateWrapper
import kz.ncanode.wrapper.KalkanWrapper
import org.apache.http.client.methods.HttpUriRequest
import org.apache.http.impl.client.CloseableHttpClient
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.boot.test.mock.mockito.SpyBean
import org.springframework.util.ResourceUtils
import spock.lang.Specification
import spock.lang.Unroll

import static org.mockito.ArgumentMatchers.any
import static org.mockito.Mockito.doReturn

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class OcspServiceTest extends Specification implements WithTestData {
    private static File OCSP_RESPONSE_CEO_2015_REVOKED = ResourceUtils.getFile("classpath:ocsp/ocsp_response_ceo_2015_revoked.bin")
    private static byte[] OCSP_RESPONSE_CEO_2015_REVOKED_NONCE = [21, 123, 40, -3, 26, -57, 118, 30]

    private static File OCSP_RESPONSE_CEO_SIGN_2004_REVOKED = ResourceUtils.getFile("classpath:ocsp/ocsp_response_ceo_sign_2004_revoked.bin")
    private static byte[] OCSP_RESPONSE_CEO_SIGN_2004_REVOKED_NONCE = [-117, 107, -97, 16, 13, 107, 0, 5]

    private static File OCSP_RESPONSE_INDIVIDUAL_2015 = ResourceUtils.getFile("classpath:ocsp/ocsp_response_individual_2015.bin")
    private static byte[] OCSP_RESPONSE_INDIVIDUAL_2015_NONCE = [-28, 8, -1, -73, -112, -125, 74, -14]

    private static File OCSP_RESPONSE_INDIVIDUAL_SIGN_2004 = ResourceUtils.getFile("classpath:ocsp/ocsp_response_individual_sign_2004.bin")
    private static byte[] OCSP_RESPONSE_INDIVIDUAL_SIGN_2004_NONCE = [-75, -27, -55, -75, 82, -53, -54, -60]

    private static byte[] OCSP_INVALID_NONCE = [-1, 2, -3, 4, -5, 6, -7, 8]

    @Autowired
    KalkanWrapper kalkanWrapper

    @SpyBean
    OcspService ocspService

    @MockBean
    CloseableHttpClient client

    @Unroll("#caseName")
    def "check ocsp verifying"() {
        given:
        def ocspInputStream = new FileInputStream(ocspResponseFile)
        doReturn(createMockedResponse(ocspInputStream)).when(client).execute(any(HttpUriRequest))
        doReturn(ocspNonce).when(ocspService).generateOcspNonce()

        def key = kalkanWrapper.read(keyFile, null, password)
        def nca = CertificateWrapper.fromBase64(ca)

        when:
        def ocspStatus = ocspService.verify(key.getCertificate(), nca.orElseThrow())

        then:
        ocspStatus != null
        ocspStatus.size() == 1

        and:
        ocspStatus[0].result == result

        cleanup:
        ocspInputStream.close()

        where:
        caseName                | keyFile                        | password                                | ca                 | ocspResponseFile                    | ocspNonce                                 || result
        'ceo 2015 cert revoked' | KEY_CEO_REVOKED_2015           | KEY_INDIVIDUAL_VALID_2015_PASSWORD      | NCA_2015_CERT      | OCSP_RESPONSE_CEO_2015_REVOKED      | OCSP_RESPONSE_CEO_2015_REVOKED_NONCE      || OcspResult.REVOKED
        'ceo 2004 cert revoked' | KEY_CEO_SIGN_REVOKED_2004      | KEY_INDIVIDUAL_VALID_SIGN_2004_PASSWORD | NCA_2004_GOST_CERT | OCSP_RESPONSE_CEO_SIGN_2004_REVOKED | OCSP_RESPONSE_CEO_SIGN_2004_REVOKED_NONCE || OcspResult.REVOKED
        'individual 2004 sign'  | KEY_INDIVIDUAL_VALID_SIGN_2004 | KEY_INDIVIDUAL_VALID_SIGN_2004_PASSWORD | NCA_2004_RSA_CERT  | OCSP_RESPONSE_INDIVIDUAL_SIGN_2004  | OCSP_RESPONSE_INDIVIDUAL_SIGN_2004_NONCE  || OcspResult.ACTIVE
        'invalid nonce'         | KEY_INDIVIDUAL_VALID_2015      | KEY_INDIVIDUAL_VALID_2015_PASSWORD      | NCA_2015_CERT      | OCSP_RESPONSE_INDIVIDUAL_2015       | OCSP_INVALID_NONCE                        || OcspResult.UNKOWN
    }

    def "generateOcspNonce test"() {
        when:
        def nonce = ocspService.generateOcspNonce()

        then:
        noExceptionThrown()
        nonce != null
        nonce.size() == OCSP_RESPONSE_CEO_2015_REVOKED_NONCE.size()
    }

    def "verify returns UNKNOWN when the issuer certificate is missing"() {
        given:
        def key = kalkanWrapper.read(KEY_INDIVIDUAL_VALID_2015, null, KEY_INDIVIDUAL_VALID_2015_PASSWORD)

        when:
        def statuses = ocspService.verify(key.certificate, null)

        then:
        statuses.size() == 1
        statuses[0].result == OcspResult.UNKOWN
    }

    def "getRawResponses returns an empty list when the issuer is missing"() {
        given:
        def key = kalkanWrapper.read(KEY_INDIVIDUAL_VALID_2015, null, KEY_INDIVIDUAL_VALID_2015_PASSWORD)

        expect:
        ocspService.getRawResponses(key.certificate, null).isEmpty()
    }

    def "getRawResponses collects successful DER OCSP responses"() {
        given:
        def ocspInputStream = new FileInputStream(OCSP_RESPONSE_INDIVIDUAL_SIGN_2004)
        doReturn(createMockedResponse(ocspInputStream)).when(client).execute(any(HttpUriRequest))

        def key = kalkanWrapper.read(KEY_INDIVIDUAL_VALID_SIGN_2004, null, KEY_INDIVIDUAL_VALID_SIGN_2004_PASSWORD)
        def nca = CertificateWrapper.fromBase64(NCA_2004_RSA_CERT).orElseThrow()

        when:
        def responses = ocspService.getRawResponses(key.certificate, nca)

        then:
        responses.size() == 1
        new kz.gov.pki.kalkan.ocsp.OCSPResp(responses[0]).status == 0

        cleanup:
        ocspInputStream.close()
    }

    def "getRawResponses skips transport failures"() {
        given:
        doReturn(null).when(client).execute(any(HttpUriRequest))
        def key = kalkanWrapper.read(KEY_INDIVIDUAL_VALID_SIGN_2004, null, KEY_INDIVIDUAL_VALID_SIGN_2004_PASSWORD)
        def nca = CertificateWrapper.fromBase64(NCA_2004_RSA_CERT).orElseThrow()

        expect:
        ocspService.getRawResponses(key.certificate, nca).isEmpty()
    }
}

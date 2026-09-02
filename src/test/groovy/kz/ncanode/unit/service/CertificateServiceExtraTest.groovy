package kz.ncanode.unit.service

import kz.ncanode.common.WithTestData
import kz.ncanode.dto.certificate.CertificateRevocation
import kz.ncanode.dto.crl.CrlResult
import kz.ncanode.dto.crl.CrlStatus
import kz.ncanode.dto.ocsp.OcspResult
import kz.ncanode.dto.ocsp.OcspStatus
import kz.ncanode.dto.request.SbaSignRequest
import kz.ncanode.dto.request.SignerRequest
import kz.ncanode.exception.ClientException
import kz.ncanode.exception.ServerException
import kz.ncanode.service.CaService
import kz.ncanode.service.CertificateService
import kz.ncanode.service.CrlService
import kz.ncanode.service.OcspService
import kz.ncanode.wrapper.CertificateWrapper
import kz.ncanode.wrapper.KalkanWrapper
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.util.ResourceUtils
import spock.lang.Specification

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class CertificateServiceExtraTest extends Specification implements WithTestData {

    @Autowired
    KalkanWrapper kalkanWrapper

    CrlService crlService = Mock()
    OcspService ocspService = Mock()
    CaService caService = Mock()
    CertificateService service

    def setup() {
        service = new CertificateService(crlService, ocspService, caService, kalkanWrapper)
    }

    private CertificateWrapper signer2015() {
        kalkanWrapper.read(KEY_INDIVIDUAL_VALID_2015, null, KEY_INDIVIDUAL_VALID_2015_PASSWORD).certificate
    }

    private static CertificateWrapper root2015() {
        CertificateWrapper.fromFile(ResourceUtils.getFile('classpath:ca/nca_gost2015_test.cer')).get()
    }

    def "collectAdesValidationData embeds OCSP when available"() {
        given:
        def signer = signer2015()
        caService.buildChain(signer) >> [signer, root2015()]
        ocspService.getRawResponses(_, _) >> [[1, 2, 3] as byte[]]
        crlService.getEncodedCrlsFor(_) >> []

        when:
        def data = service.collectAdesValidationData(signer, [])

        then:
        data.ocsps.size() == 1
        data.certificates.size() == 2
    }

    def "collectAdesValidationData falls back to CRL when there is no OCSP"() {
        given:
        def signer = signer2015()
        caService.buildChain(signer) >> [signer, root2015()]
        ocspService.getRawResponses(_, _) >> []
        crlService.getEncodedCrlsFor(_) >> [[9, 9] as byte[]]

        when:
        def data = service.collectAdesValidationData(signer, [])

        then:
        data.ocsps.isEmpty()
        data.crls.size() == 1
    }

    def "collectAdesValidationData also collects CRLs for intermediate CAs and TSA certs"() {
        given:
        def signer = signer2015()
        def intermediate = root2015()   // not self-signed -> intermediate CA branch
        caService.buildChain(signer) >> [signer, intermediate]
        ocspService.getRawResponses(_, _) >> []
        crlService.getEncodedCrlsFor(_) >> [[7] as byte[]]

        when:
        def data = service.collectAdesValidationData(signer, [intermediate.x509Certificate])

        then:
        data.certificates.size() == 2      // signer + TSA cert deduped against chain
        data.crls.size() == 1
    }

    def "collectAdesValidationData throws when no revocation data is available"() {
        given:
        def signer = signer2015()
        caService.buildChain(signer) >> [signer, root2015()]
        ocspService.getRawResponses(_, _) >> []
        crlService.getEncodedCrlsFor(_) >> []

        when:
        service.collectAdesValidationData(signer, [])

        then:
        thrown(ClientException)
    }

    def "create signs data with an SBA request"() {
        given:
        def request = new SbaSignRequest()
        request.data = 'hello sba'
        request.signer = SignerRequest.builder()
            .key(KEY_INDIVIDUAL_VALID_SIGN_2004)
            .password(KEY_INDIVIDUAL_VALID_SIGN_2004_PASSWORD)
            .keyAlias(KEY_INDIVIDUAL_VALID_SIGN_2004_ALIAS)
            .build()

        when:
        def response = service.create(request)

        then:
        response.certificate != null
        response.signature != null
    }

    def "create throws ServerException for an unreadable key"() {
        given:
        def request = new SbaSignRequest()
        request.data = 'x'
        request.signer = SignerRequest.builder().key(KEY_INVALID).password(KEY_INVALID_PASSWORD).build()

        when:
        service.create(request)

        then:
        thrown(ServerException)
    }

    def "verify reports an invalid signature without an issuer"() {
        given:
        def signed = service.create(newRequest('payload'))
        caService.getRootCertificateFor(_) >> Optional.empty()

        when:
        def result = service.verify(signed.certificate, signed.signature, 'payload', false, false)

        then:
        !result.valid
        result.signers.size() == 1
    }

    def "verify with revocation checks attaches OCSP and CRL statuses"() {
        given:
        def signed = service.create(newRequest('payload'))
        def issuer = root2015()
        caService.getRootCertificateFor(_) >> Optional.of(issuer)
        ocspService.verify(_, _) >> [OcspStatus.builder().result(OcspResult.ACTIVE).build()]
        crlService.verify(_) >> CrlStatus.builder().result(CrlResult.ACTIVE).build()

        when:
        def result = service.verify(signed.certificate, signed.signature, 'payload', true, true)

        then:
        result.signers.size() == 1
        1 * ocspService.verify(_, _)
        1 * crlService.verify(_)
    }

    private static SbaSignRequest newRequest(String data) {
        def request = new SbaSignRequest()
        request.data = data
        request.signer = SignerRequest.builder()
            .key(KEY_INDIVIDUAL_VALID_2015)
            .password(KEY_INDIVIDUAL_VALID_2015_PASSWORD)
            .build()
        request
    }
}

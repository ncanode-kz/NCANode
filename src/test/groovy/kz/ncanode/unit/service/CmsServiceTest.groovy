package kz.ncanode.unit.service

import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData
import kz.ncanode.common.WithTestData
import kz.ncanode.dto.request.CmsCreateRequest
import kz.ncanode.dto.request.SignerRequest
import kz.ncanode.exception.ClientException
import kz.ncanode.dto.request.CmsExtendRequest
import kz.ncanode.dto.ades.AdesLevel
import kz.ncanode.exception.ServerException
import kz.ncanode.service.CertificateService
import kz.ncanode.service.CmsService
import kz.ncanode.service.TspService
import kz.ncanode.wrapper.CertificateWrapper
import org.mockito.invocation.InvocationOnMock
import org.mockito.stubbing.Answer
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.boot.test.mock.mockito.SpyBean
import spock.lang.Specification
import spock.lang.Unroll

import java.nio.charset.StandardCharsets

import static org.mockito.ArgumentMatchers.any
import static org.mockito.ArgumentMatchers.anyBoolean
import static org.mockito.Mockito.doAnswer
import static org.mockito.Mockito.mock
import static org.mockito.Mockito.when

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class CmsServiceTest extends Specification implements WithTestData {

    private final static String TEST_DATA = "test123"
    private final static String SIGNED_CMS = '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'
    private final static String SIGNED_DETACHED_CMS = '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'
    private final static String SIGNED_CMS_ONE_SIGNER = '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'

    @Autowired
    CmsService cmsService

    @MockBean
    CertificateService certificateService

    @SpyBean
    TspService tspService

    @Unroll("#caseName")
    def "test cms creating"() {
        given:
        def request = new CmsCreateRequest()
        request.setData(Base64.getEncoder().encodeToString(TEST_DATA.getBytes(StandardCharsets.UTF_8)))
        request.setSigners([
            new SignerRequest(KEY_INDIVIDUAL_VALID_SIGN_2004, KEY_INDIVIDUAL_VALID_SIGN_2004_PASSWORD, null, null),
            new SignerRequest(KEY_INDIVIDUAL_VALID_2015, KEY_INDIVIDUAL_VALID_2015_PASSWORD, null, null),
        ])
        request.setDetached(detached)

        when:
        def response = cmsService.create(request)
        def cms = new CMSSignedData(Base64.getDecoder().decode(response.cms))

        then:
        response != null
        cms != null

        and: 'check content in cms'
        checkOriginalData(cms, detached)

        and: 'check signers quantity'
        getSignersQuantity(cms) == request.getSigners().size()

        where:
        caseName   | detached
        'attached' | false
        'detached' | true
    }

    @Unroll("#caseName")
    def "add signture to existsing cms"() {
        given:
        def request = new CmsCreateRequest()
        request.setData(Base64.getEncoder().encodeToString(TEST_DATA.getBytes(StandardCharsets.UTF_8)))
        request.setCms(SIGNED_CMS_ONE_SIGNER)
        request.setSigners([
            new SignerRequest(KEY_INDIVIDUAL_VALID_2015, KEY_INDIVIDUAL_VALID_2015_PASSWORD, null, null),
        ])
        request.setDetached(detached)

        when:
        def response = cmsService.addSigners(request)
        def cms = new CMSSignedData(Base64.getDecoder().decode(response.cms))

        then:
        response != null

        and: 'check primary cms'
        getSignersQuantity(new CMSSignedData(Base64.getDecoder().decode(SIGNED_CMS_ONE_SIGNER))) == 1

        and: 'check cms with new signer'
        getSignersQuantity(cms) == 2


        where:
        caseName   | detached
        'attached' | false
        'detached' | true
    }

    @Unroll("#caseName")
    def "test cms verification"() {
        given:
        def validDate = buildValidDate()
        def issuerCert = mockIssuerCertificate(dateValid)

        when(certificateService.getCurrentDate()).thenReturn(validDate)
        when(certificateService.attachValidationData(any(), anyBoolean(), anyBoolean())).thenAnswer(new CertificateServiceAnswer(issuerCert))


        when:
        def response = cmsService.verify(cmsData, detachedData, false, false)

        then:
        response != null

        and:
        response.valid == expectedValid
        response.signers.size() == 2

        where:
        caseName   | cmsData             | detachedData                                                              | dateValid || expectedValid
        'attached' | SIGNED_CMS          | null                                                                      | true      || true
        'detached' | SIGNED_DETACHED_CMS | Base64.encoder.encodeToString(TEST_DATA.getBytes(StandardCharsets.UTF_8)) | true      || true
    }

    def "validate data extraction"() {
        when:
        def response = cmsService.extract(SIGNED_CMS)

        then:
        response.getData() == Base64.encoder.encodeToString(TEST_DATA.getBytes(StandardCharsets.UTF_8))
    }

    def "validate detached data extraction"() {
        when:
        def response = cmsService.extract(SIGNED_DETACHED_CMS)

        then:
        thrown(ClientException)
    }

    def "extract wraps a malformed CMS in a ServerException"() {
        when:
        cmsService.extract('bm90IGEgY21z')

        then:
        thrown(ServerException)
    }

    def "verify rejects a malformed CMS"() {
        when:
        cmsService.verify('bm90IGEgY21z', null, false, false)

        then:
        thrown(ClientException)
    }

    def "addSigners rejects a request without a CMS"() {
        given:
        def request = new CmsCreateRequest()
        request.setSigners([new SignerRequest(KEY_INDIVIDUAL_VALID_2015, KEY_INDIVIDUAL_VALID_2015_PASSWORD, null, null)])

        when:
        cmsService.addSigners(request)

        then:
        thrown(ClientException)
    }

    def "addSigners rejects a CAdES profile for co-signing"() {
        given:
        def request = new CmsCreateRequest()
        request.setCms(SIGNED_CMS_ONE_SIGNER)
        request.setCadesLevel(AdesLevel.T)
        request.setSigners([new SignerRequest(KEY_INDIVIDUAL_VALID_2015, KEY_INDIVIDUAL_VALID_2015_PASSWORD, null, null)])

        when:
        cmsService.addSigners(request)

        then:
        thrown(ClientException)
    }

    def "addSigners rejects a detached CMS without data"() {
        given:
        def request = new CmsCreateRequest()
        request.setCms(SIGNED_DETACHED_CMS)
        request.setDetached(true)
        request.setSigners([new SignerRequest(KEY_INDIVIDUAL_VALID_2015, KEY_INDIVIDUAL_VALID_2015_PASSWORD, null, null)])

        when:
        cmsService.addSigners(request)

        then:
        thrown(ClientException)
    }

    def "addSigners with TSP timestamps only the newly added signer"() {
        given: 'tsp returns the signer untouched so we do not hit the network'
        doAnswer({ InvocationOnMock inv -> inv.getArgument(0) })
            .when(tspService).addTspToSigner(any(), any(), any())

        def request = new CmsCreateRequest()
        request.setData(Base64.getEncoder().encodeToString(TEST_DATA.getBytes(StandardCharsets.UTF_8)))
        request.setCms(SIGNED_CMS_ONE_SIGNER)
        request.setWithTsp(true)
        request.setSigners([new SignerRequest(KEY_INDIVIDUAL_VALID_2015, KEY_INDIVIDUAL_VALID_2015_PASSWORD, null, null)])

        when:
        def response = cmsService.addSigners(request)

        then:
        getSignersQuantity(new CMSSignedData(Base64.decoder.decode(response.cms))) == 2
    }

    def "extend rejects a detached CMS without data"() {
        given:
        def request = new CmsExtendRequest(cms: SIGNED_DETACHED_CMS, cadesLevel: AdesLevel.T)

        when:
        cmsService.extend(request)

        then:
        thrown(ClientException)
    }

    def "create with TSP timestamps every signer"() {
        given:
        doAnswer({ InvocationOnMock inv -> inv.getArgument(0) })
            .when(tspService).addTspToSigner(any(), any(), any())

        def request = new CmsCreateRequest()
        request.setData(Base64.getEncoder().encodeToString(TEST_DATA.getBytes(StandardCharsets.UTF_8)))
        request.setWithTsp(true)
        request.setSigners([new SignerRequest(KEY_INDIVIDUAL_VALID_2015, KEY_INDIVIDUAL_VALID_2015_PASSWORD, null, null)])

        when:
        def response = cmsService.create(request)

        then:
        getSignersQuantity(new CMSSignedData(Base64.decoder.decode(response.cms))) == 1
    }

    def "create wraps a key failure in a ServerException"() {
        given:
        def request = new CmsCreateRequest()
        request.setData(Base64.getEncoder().encodeToString(TEST_DATA.getBytes(StandardCharsets.UTF_8)))
        request.setSigners([new SignerRequest(KEY_INVALID, KEY_INVALID_PASSWORD, null, null)])

        when:
        cmsService.create(request)

        then:
        thrown(ServerException)
    }

    def "extend accepts a detached CMS together with its data"() {
        given:
        def request = new CmsExtendRequest(
            cms: SIGNED_DETACHED_CMS,
            data: Base64.encoder.encodeToString(TEST_DATA.getBytes(StandardCharsets.UTF_8)),
            cadesLevel: AdesLevel.B)

        when:
        def response = cmsService.extend(request)

        then:
        new CMSSignedData(Base64.decoder.decode(response.cms)).signedContent == null
    }

    def "extend at level B returns the CMS unchanged"() {
        given:
        def request = new CmsExtendRequest(cms: SIGNED_CMS_ONE_SIGNER, cadesLevel: AdesLevel.B)

        when:
        def response = cmsService.extend(request)

        then:
        getSignersQuantity(new CMSSignedData(Base64.decoder.decode(response.cms))) == 1
    }

    private boolean checkOriginalData(CMSSignedData cms, boolean detached) {
        if (!detached) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            cms.getSignedContent().write(out);

            def originalData = out.toString(StandardCharsets.UTF_8)
            out.close()

            return originalData == TEST_DATA
        } else {
            return cms.getSignedContent() == null
        }
    }

    private int getSignersQuantity(CMSSignedData cms) {
        def it = cms.getSignerInfos().getSigners().iterator()
        def signersQuantity = 0
        while (it.hasNext()) {
            signersQuantity++;
            it.next()
        }

        return signersQuantity
    }

    private Date buildValidDate() {
        def date = mock(Date)
        when(date.after(any())).thenReturn(true)
        when(date.before(any())).thenReturn(true)
        return date
    }

    private CertificateWrapper mockIssuerCertificate(boolean dateValid) {
        def cert = mock(CertificateWrapper)
        when(cert.isDateValid(any())).thenReturn(dateValid)

        return cert
    }

    protected class CertificateServiceAnswer implements Answer<Void> {

        private CertificateWrapper issuerCert

        public CertificateServiceAnswer(CertificateWrapper issuerCert) {
            this.issuerCert = issuerCert
        }

        @Override
        Void answer(InvocationOnMock invocation) throws Throwable {
            CertificateWrapper cert = invocation.getArgument(0, CertificateWrapper)
            cert.setIssuerCertificate(issuerCert)
            return null
        }
    }
}

package kz.ncanode.unit.service

import kz.gov.pki.kalkan.asn1.pkcs.PKCSObjectIdentifiers
import kz.gov.pki.kalkan.jce.provider.KalkanProvider
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformation
import kz.gov.pki.kalkan.tsp.TimeStampToken
import kz.ncanode.common.WithTestData
import kz.ncanode.dto.ades.AdesLevel
import kz.ncanode.dto.ades.AdesValidationData
import kz.ncanode.dto.request.CmsCreateRequest
import kz.ncanode.dto.request.SignerRequest
import kz.ncanode.exception.ClientException
import kz.ncanode.service.CertificateService
import kz.ncanode.service.CmsService
import kz.ncanode.service.TspService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.boot.test.mock.mockito.SpyBean
import org.springframework.util.ResourceUtils
import spock.lang.Specification

import java.nio.charset.StandardCharsets
import java.security.cert.CertificateFactory

import static kz.ncanode.common.SignerRequestTestData.*
import static org.mockito.ArgumentMatchers.any
import static org.mockito.Mockito.when

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class CadesServiceTest extends Specification implements WithTestData {

    private final static String ID_AA_ETS_ARCHIVE_TIMESTAMP_V3 = '0.4.0.1733.2.4'

    @Autowired
    CmsService cmsService

    @MockBean
    CertificateService certificateService

    @SpyBean
    TspService tspService

    def "CAdES-B adds the SigningCertificateV2 signed attribute"() {
        when:
        def cms = sign(AdesLevel.B)
        def signer = firstSigner(cms)

        then: 'one signer, signed by the test certificate'
        cms.signerInfos.signers.size() == 1

        and: 'mandatory CAdES-B signed attribute present'
        signer.signedAttributes.get(PKCSObjectIdentifiers.id_aa_signingCertificateV2) != null

        and: 'no timestamp / no validation data at B level'
        signer.unsignedAttributes == null
        crlCount(cms) == 0
    }

    def "CAdES-T adds a signature timestamp"() {
        given:
        stubTimestamp()

        when:
        def cms = sign(AdesLevel.T)
        def signer = firstSigner(cms)

        then:
        signer.unsignedAttributes?.get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken) != null
        signer.unsignedAttributes.get(new kz.gov.pki.kalkan.asn1.DERObjectIdentifier(ID_AA_ETS_ARCHIVE_TIMESTAMP_V3)) == null
        crlCount(cms) == 0
    }

    def "CAdES-LT embeds the chain and revocation data into SignedData"() {
        given:
        stubTimestamp()
        when(certificateService.collectAdesValidationData(any(), any())).thenReturn(sampleValidationData())

        when:
        def cms = sign(AdesLevel.LT)

        then: 'certificate set grew beyond the signer, revocation embedded in SignedData.crls'
        cms.getCertificatesAndCRLs('Collection', KalkanProvider.PROVIDER_NAME).getCertificates(null).size() >= 2
        crlCount(cms) >= 1

        and: 'still T, not yet LTA'
        firstSigner(cms).unsignedAttributes.get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken) != null
        firstSigner(cms).unsignedAttributes.get(new kz.gov.pki.kalkan.asn1.DERObjectIdentifier(ID_AA_ETS_ARCHIVE_TIMESTAMP_V3)) == null
    }

    def "CAdES-LTA adds an archive-timestamp-v3 unsigned attribute"() {
        given:
        stubTimestamp()
        when(certificateService.collectAdesValidationData(any(), any())).thenReturn(sampleValidationData())

        when:
        def cms = sign(AdesLevel.LTA)

        then:
        firstSigner(cms).unsignedAttributes
            .get(new kz.gov.pki.kalkan.asn1.DERObjectIdentifier(ID_AA_ETS_ARCHIVE_TIMESTAMP_V3)) != null
    }

    def "CAdES profile is rejected on /cms/sign/add"() {
        given:
        def req = new CmsCreateRequest()
        req.cms = 'AA=='
        req.cadesLevel = AdesLevel.LT
        req.signers = [SIGNER_REQUEST_VALID_2015()]

        when:
        cmsService.addSigners(req)

        then:
        def e = thrown(ClientException)
        e.message.contains('CAdES')
    }

    // --- helpers ---

    private CMSSignedData sign(AdesLevel level) {
        def req = new CmsCreateRequest()
        req.data = Base64.encoder.encodeToString('cades test payload'.getBytes(StandardCharsets.UTF_8))
        req.signers = [SIGNER_REQUEST_VALID_2015()]
        req.cadesLevel = level
        new CMSSignedData(Base64.decoder.decode(cmsService.create(req).cms))
    }

    private void stubTimestamp() {
        def token = new TimeStampToken(new CMSSignedData(
            new FileInputStream(ResourceUtils.getFile('classpath:tsp/tsp_token.bin'))))
        // spy: только create() замокан, addTspToSigner / extractCertificates идут по-настоящему
        org.mockito.Mockito.doReturn(token).when(tspService).create(any(byte[]), any(String), any(String))
    }

    private static SignerInformation firstSigner(CMSSignedData cms) {
        cms.signerInfos.signers.iterator().next() as SignerInformation
    }

    private static int crlCount(CMSSignedData cms) {
        def contentInfo = kz.gov.pki.kalkan.asn1.cms.ContentInfo.getInstance(
            kz.gov.pki.kalkan.asn1.ASN1Object.fromByteArray(cms.encoded))
        def crls = kz.gov.pki.kalkan.asn1.cms.SignedData.getInstance(contentInfo.content).getCRLs()
        crls == null ? 0 : crls.size()
    }

    private static AdesValidationData sampleValidationData() {
        def cf = CertificateFactory.getInstance('X.509')
        def cert = cf.generateCertificate(
            new FileInputStream(ResourceUtils.getFile('classpath:ca/nca_gost2015_test.cer')))
        def crl = ResourceUtils.getFile('classpath:crl/nca_gost2022_test.crl').bytes
        def ocsp = ResourceUtils.getFile('classpath:ocsp/ocsp_response_individual_2015.bin').bytes
        new AdesValidationData([cert] as List, [crl] as List, [ocsp] as List)
    }
}

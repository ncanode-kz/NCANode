package kz.ncanode.unit.service

import groovy.xml.DOMBuilder
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData
import kz.gov.pki.kalkan.tsp.TimeStampToken
import kz.ncanode.common.WithTestData
import kz.ncanode.dto.request.XmlSignRequest
import kz.ncanode.dto.ades.AdesLevel
import kz.ncanode.dto.ades.AdesValidationData
import kz.ncanode.service.CertificateService
import kz.ncanode.service.TspService
import kz.ncanode.service.XmlService
import kz.ncanode.wrapper.XMLSignatureWrapper
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.util.ResourceUtils
import org.w3c.dom.Element
import spock.lang.Specification
import spock.lang.Unroll

import java.security.cert.CertificateFactory

import static kz.ncanode.common.SignerRequestTestData.*
import static org.mockito.ArgumentMatchers.any
import static org.mockito.Mockito.when

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class XadesServiceTest extends Specification implements WithTestData {

    private final static String XADES_NS = 'http://uri.etsi.org/01903/v1.3.2#'
    private final static String XADES141_NS = 'http://uri.etsi.org/01903/v1.4.1#'
    private final static String DS_NS = 'http://www.w3.org/2000/09/xmldsig#'
    private final static String XML = '<?xml version="1.0" encoding="UTF-8"?><document Id="doc-1"><body>test</body></document>'

    @Autowired
    private XmlService xmlService

    @MockBean
    private CertificateService certificateService

    @MockBean
    private TspService tspService

    @Unroll("#caseName")
    def "sign XAdES-BES"() {
        given:
        def request = XmlSignRequest.builder().xml(XML).xadesLevel(AdesLevel.B).signers([signer]).build()

        when:
        def signed = parse(xmlService.sign(request).xml)

        then: 'one enveloped signature'
        signed.getElementsByTagNameNS(DS_NS, 'Signature').length == 1

        and: 'two references — content and SignedProperties'
        def references = signed.getElementsByTagNameNS(DS_NS, 'Reference')
        references.length == 2
        (0..<references.length).collect { references.item(it).getAttribute('Type') }
            .contains('http://uri.etsi.org/01903#SignedProperties')

        and: 'XAdES qualifying properties present'
        signed.getElementsByTagNameNS(XADES_NS, 'QualifyingProperties').length == 1
        signed.getElementsByTagNameNS(XADES_NS, 'SigningCertificateV2').length == 1
        signed.getElementsByTagNameNS(XADES_NS, 'IssuerSerialV2').length == 1
        signed.getElementsByTagNameNS(XADES_NS, 'SigningTime').length == 1

        and: 'SignedProperties carries an Id referenced by the signature'
        def signedProps = signed.getElementsByTagNameNS(XADES_NS, 'SignedProperties').item(0)
        !signedProps.getAttribute('Id').isEmpty()

        and: 'exclusive c14n is used'
        signed.getElementsByTagNameNS(DS_NS, 'CanonicalizationMethod').item(0)
            .getAttribute('Algorithm') == 'http://www.w3.org/2001/10/xml-exc-c14n#'

        and: 'no timestamp at BES level'
        signed.getElementsByTagNameNS(XADES_NS, 'SignatureTimeStamp').length == 0

        and: 'signature verifies cryptographically (both references resolve)'
        verifies(signed)

        where:
        caseName          | signer
        'old key (2004)'  | SIGNER_REQUEST_VALID_2004()
        'new key (2015)'  | SIGNER_REQUEST_VALID_2015()
    }

    def "sign XAdES-T adds a signature timestamp"() {
        given:
        stubTimestamp()

        def request = XmlSignRequest.builder().xml(XML).xadesLevel(AdesLevel.T)
            .signers([SIGNER_REQUEST_VALID_2015()]).build()

        when:
        def signed = parse(xmlService.sign(request).xml)

        then:
        signed.getElementsByTagNameNS(XADES_NS, 'SignatureTimeStamp').length == 1

        and: 'timestamp lives in UnsignedSignatureProperties and carries an encapsulated token'
        signed.getElementsByTagNameNS(XADES_NS, 'UnsignedSignatureProperties').length == 1
        !signed.getElementsByTagNameNS(XADES_NS, 'EncapsulatedTimeStamp').item(0).textContent.isEmpty()

        and: 'no LT/LTA material'
        signed.getElementsByTagNameNS(XADES_NS, 'CertificateValues').length == 0
        signed.getElementsByTagNameNS(XADES141_NS, 'ArchiveTimeStamp').length == 0
    }

    def "sign XAdES-LT embeds certificate and revocation values"() {
        given:
        stubTimestamp()
        when(certificateService.collectAdesValidationData(any(), any())).thenReturn(sampleValidationData())

        def request = XmlSignRequest.builder().xml(XML).xadesLevel(AdesLevel.LT)
            .signers([SIGNER_REQUEST_VALID_2015()]).build()

        when:
        def signed = parse(xmlService.sign(request).xml)

        then: 'T + LT material'
        signed.getElementsByTagNameNS(XADES_NS, 'SignatureTimeStamp').length == 1
        signed.getElementsByTagNameNS(XADES_NS, 'CertificateValues').length == 1
        signed.getElementsByTagNameNS(XADES_NS, 'EncapsulatedX509Certificate').length == 1
        signed.getElementsByTagNameNS(XADES_NS, 'RevocationValues').length == 1
        signed.getElementsByTagNameNS(XADES_NS, 'EncapsulatedCRLValue').length == 1
        signed.getElementsByTagNameNS(XADES_NS, 'EncapsulatedOCSPValue').length == 1

        and: 'no archive timestamp at LT level'
        signed.getElementsByTagNameNS(XADES141_NS, 'ArchiveTimeStamp').length == 0
    }

    def "sign XAdES-LTA adds an archive timestamp"() {
        given:
        stubTimestamp()
        when(certificateService.collectAdesValidationData(any(), any())).thenReturn(sampleValidationData())

        def request = XmlSignRequest.builder().xml(XML).xadesLevel(AdesLevel.LTA)
            .signers([SIGNER_REQUEST_VALID_2015()]).build()

        when:
        def signed = parse(xmlService.sign(request).xml)

        then:
        signed.getElementsByTagNameNS(XADES_NS, 'CertificateValues').length == 1

        and: 'xades141:ArchiveTimeStamp with its own namespace and an encapsulated token'
        def archive = signed.getElementsByTagNameNS(XADES141_NS, 'ArchiveTimeStamp')
        archive.length == 1
        def encapsulated = (archive.item(0) as Element).getElementsByTagNameNS(XADES_NS, 'EncapsulatedTimeStamp')
        encapsulated.length == 1
        !encapsulated.item(0).textContent.isEmpty()
    }

    private void stubTimestamp() {
        def token = new TimeStampToken(new CMSSignedData(
            new FileInputStream(ResourceUtils.getFile('classpath:tsp/tsp_token.bin'))))
        when(tspService.create(any(byte[]), any(String), any(String))).thenReturn(token)
        when(tspService.extractCertificates(any())).thenReturn([])
    }

    private static AdesValidationData sampleValidationData() {
        def cf = CertificateFactory.getInstance('X.509')
        def cert = cf.generateCertificate(
            new FileInputStream(ResourceUtils.getFile('classpath:ca/nca_gost2015_test.cer')))
        def crl = ResourceUtils.getFile('classpath:crl/nca_gost2022_test.crl').bytes
        def ocsp = ResourceUtils.getFile('classpath:ocsp/ocsp_response_individual_2015.bin').bytes
        new AdesValidationData([cert] as List, [crl] as List, [ocsp] as List)
    }

    private static org.w3c.dom.Document parse(String xml) {
        DOMBuilder.newInstance(false, true).parse(new StringReader(xml))
    }

    /** Re-verifies the enveloped XAdES signature with Santuario after a fresh parse. */
    private static boolean verifies(org.w3c.dom.Document doc) {
        registerIdAttributes(doc.documentElement)
        def sig = doc.getElementsByTagNameNS(DS_NS, 'Signature').item(0) as Element
        new XMLSignatureWrapper(sig).check()
    }

    private static void registerIdAttributes(Element element) {
        if (element.hasAttribute('Id')) {
            element.setIdAttribute('Id', true)
        }
        def children = element.childNodes
        for (int i = 0; i < children.length; i++) {
            if (children.item(i) instanceof Element) {
                registerIdAttributes(children.item(i) as Element)
            }
        }
    }
}

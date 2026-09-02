package kz.ncanode.unit.service

import groovy.xml.DOMBuilder
import kz.gov.pki.kalkan.jce.provider.KalkanProvider
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData
import kz.gov.pki.kalkan.tsp.TimeStampToken
import org.apache.xml.security.c14n.Canonicalizer
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.util.ResourceUtils
import org.w3c.dom.Document
import org.w3c.dom.Element
import spock.lang.Specification
import spock.lang.Unroll

import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509CRL
import java.security.cert.X509Certificate
import java.time.Instant

/**
 * Проверяет, что эталонные XAdES-подписи (src/test/resources/xades/) — валидные подписи
 * на фиксированную дату {@link #REFERENCE_DATE} (2026-09-02 16:00:00 UTC+5).
 *
 * Дата фиксирована намеренно (см. AGENTS.md): сертификаты и CRL имеют срок действия, поэтому
 * «валидно на new Date()» со временем начнёт падать. Все проверки — на REFERENCE_DATE.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class XadesFixtureSpec extends Specification {

    private final static String XADES_NS = 'http://uri.etsi.org/01903/v1.3.2#'
    private final static String XADES141_NS = 'http://uri.etsi.org/01903/v1.4.1#'
    private final static String DS_NS = 'http://www.w3.org/2000/09/xmldsig#'
    private final static String C14N_EXCL = 'http://www.w3.org/2001/10/xml-exc-c14n#'

    /** 2026-09-02 16:00:00 UTC+5 */
    private final static Date REFERENCE_DATE = Date.from(Instant.parse('2026-09-02T11:00:00Z'))

    private CertificateFactory certFactory() {
        CertificateFactory.getInstance('X.509', KalkanProvider.PROVIDER_NAME)
    }

    @Unroll('#file — valid XAdES at reference date')
    def "reference XAdES signatures are valid at the reference date"() {
        given:
        def doc = parse(fixture(file))
        def signature = signatureElement(doc)

        expect: 'core XML-DSIG signature verifies against the embedded certificate'
        cryptographicallyVerifies(doc)

        and: 'exclusive c14n throughout'
        signature.getElementsByTagNameNS(DS_NS, 'CanonicalizationMethod').item(0)
            .getAttribute('Algorithm') == C14N_EXCL

        and: 'BES structure: QualifyingProperties / SignedProperties(Id) / SigningCertificateV2 / SigningTime'
        signature.getElementsByTagNameNS(XADES_NS, 'QualifyingProperties').length == 1
        !elem(signature, XADES_NS, 'SignedProperties').getAttribute('Id').isEmpty()
        signature.getElementsByTagNameNS(XADES_NS, 'SigningCertificateV2').length == 1
        signature.getElementsByTagNameNS(XADES_NS, 'SigningTime').length == 1
        signature.getElementsByTagNameNS(XADES_NS, 'SignedDataObjectProperties').length == 1

        and: 'SigningCertificateV2 digest matches the embedded certificate'
        signingCertificateDigestMatches(signature)

        and: 'signer certificate is within its validity period at the reference date'
        def signer = embeddedCertificate(signature)
        !REFERENCE_DATE.before(signer.notBefore)
        !REFERENCE_DATE.after(signer.notAfter)

        and: 'T level: signature timestamp present, parses, covers this signature and predates the reference date'
        def signatureTimeStamps = signature.getElementsByTagNameNS(XADES_NS, 'SignatureTimeStamp')
        signatureTimeStamps.length == (hasTimestamp ? 1 : 0)
        if (hasTimestamp) {
            def token = timeStampToken(signatureTimeStamps.item(0) as Element)
            token.timeStampInfo.genTime.before(REFERENCE_DATE)
            assert timestampImprintMatches(token, canonicalize(elem(signature, DS_NS, 'SignatureValue')))
        }

        and: 'LT level: certificate chain and revocation data embedded and current at the reference date'
        signature.getElementsByTagNameNS(XADES_NS, 'CertificateValues').length == (hasValidationData ? 1 : 0)
        if (hasValidationData) {
            assert signature.getElementsByTagNameNS(XADES_NS, 'EncapsulatedX509Certificate').length >= 1
            assert signature.getElementsByTagNameNS(XADES_NS, 'RevocationValues').length == 1
            assert (signature.getElementsByTagNameNS(XADES_NS, 'EncapsulatedCRLValue').length
                + signature.getElementsByTagNameNS(XADES_NS, 'EncapsulatedOCSPValue').length) >= 1
            embeddedCrls(signature).each { crl ->
                assert !REFERENCE_DATE.before(crl.thisUpdate)
                assert !REFERENCE_DATE.after(crl.nextUpdate)
                assert !crl.isRevoked(signer)
            }
        }

        and: 'LTA level: archive timestamp present, parses and predates the reference date'
        def archiveTimeStamps = signature.getElementsByTagNameNS(XADES141_NS, 'ArchiveTimeStamp')
        archiveTimeStamps.length == (hasArchiveTimestamp ? 1 : 0)
        if (hasArchiveTimestamp) {
            assert timeStampToken(archiveTimeStamps.item(0) as Element).timeStampInfo.genTime.before(REFERENCE_DATE)
        }

        where:
        file                          | hasTimestamp | hasValidationData | hasArchiveTimestamp
        'xades-test-signed-b.xml'     | false        | false             | false
        'xades-test-signed-t.xml'     | true         | false             | false
        'xades-test-signed-lt.xml'    | true         | true              | false
        'xades-test-signed-lta.xml'   | true         | true              | true
    }

    // --- helpers ---

    private static String fixture(String name) {
        ResourceUtils.getFile("classpath:xades/${name}").text
    }

    private static Document parse(String xml) {
        DOMBuilder.newInstance(false, true).parse(new StringReader(xml))
    }

    private static Element signatureElement(Document doc) {
        doc.getElementsByTagNameNS(DS_NS, 'Signature').item(0) as Element
    }

    private static Element elem(Element parent, String ns, String local) {
        parent.getElementsByTagNameNS(ns, local).item(0) as Element
    }

    private boolean cryptographicallyVerifies(Document doc) {
        registerIdAttributes(doc.documentElement)
        new kz.ncanode.wrapper.XMLSignatureWrapper(signatureElement(doc)).check()
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

    private X509Certificate embeddedCertificate(Element signature) {
        def base64 = elem(signature, DS_NS, 'X509Certificate').textContent.replaceAll('\\s', '')
        certFactory().generateCertificate(new ByteArrayInputStream(Base64.decoder.decode(base64))) as X509Certificate
    }

    private boolean signingCertificateDigestMatches(Element signature) {
        def certDigest = elem(signature, XADES_NS, 'CertDigest')
        def algorithm = elem(certDigest, DS_NS, 'DigestMethod').getAttribute('Algorithm')
        def expected = Base64.decoder.decode(elem(certDigest, DS_NS, 'DigestValue').textContent.replaceAll('\\s', ''))
        def actual = MessageDigest.getInstance(digestOid(algorithm), KalkanProvider.PROVIDER_NAME)
            .digest(embeddedCertificate(signature).encoded)
        Arrays.equals(expected, actual)
    }

    private static String digestOid(String xmlUri) {
        switch (xmlUri) {
            case 'urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-512': return '1.2.398.3.10.1.3.3'
            case 'urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-256': return '1.2.398.3.10.1.3.2'
            case 'http://www.w3.org/2001/04/xmlenc#sha256': return 'SHA-256'
            default: return 'SHA-1'
        }
    }

    private static TimeStampToken timeStampToken(Element timeStampProperty) {
        def base64 = timeStampProperty.getElementsByTagNameNS(XADES_NS, 'EncapsulatedTimeStamp')
            .item(0).textContent.replaceAll('\\s', '')
        new TimeStampToken(new CMSSignedData(Base64.mimeDecoder.decode(base64)))
    }

    private static boolean timestampImprintMatches(TimeStampToken token, byte[] timestampedData) {
        def info = token.timeStampInfo
        def digest = MessageDigest.getInstance(info.messageImprintAlgOID, KalkanProvider.PROVIDER_NAME)
            .digest(timestampedData)
        Arrays.equals(info.messageImprintDigest, digest)
    }

    private List<X509CRL> embeddedCrls(Element signature) {
        def values = signature.getElementsByTagNameNS(XADES_NS, 'EncapsulatedCRLValue')
        (0..<values.length).collect {
            certFactory().generateCRL(new ByteArrayInputStream(
                Base64.mimeDecoder.decode(values.item(it).textContent.replaceAll('\\s', '')))) as X509CRL
        }
    }

    private static byte[] canonicalize(Element element) {
        def out = new ByteArrayOutputStream()
        Canonicalizer.getInstance(C14N_EXCL).canonicalizeSubtree(element, out)
        out.toByteArray()
    }
}

package kz.ncanode.unit.service

import kz.gov.pki.kalkan.asn1.ASN1Object
import kz.gov.pki.kalkan.asn1.DERObjectIdentifier
import kz.gov.pki.kalkan.asn1.cms.ContentInfo
import kz.gov.pki.kalkan.asn1.cms.SignedData
import kz.gov.pki.kalkan.asn1.ess.SigningCertificateV2
import kz.gov.pki.kalkan.asn1.pkcs.PKCSObjectIdentifiers
import kz.gov.pki.kalkan.jce.provider.KalkanProvider
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformation
import kz.gov.pki.kalkan.tsp.TimeStampToken
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.util.ResourceUtils
import spock.lang.Specification
import spock.lang.Unroll

import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.Instant

/**
 * Проверяет, что эталонные CAdES-подписи (src/test/resources/cades/) — валидные подписи
 * на фиксированную дату {@link #REFERENCE_DATE} (2026-09-02 16:00:00 UTC+5), см. AGENTS.md.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class CadesFixtureSpec extends Specification {

    private final static DERObjectIdentifier ID_AA_ETS_ARCHIVE_TIMESTAMP_V3 =
        new DERObjectIdentifier('0.4.0.1733.2.4')
    private final static DERObjectIdentifier ID_RI_OCSP_RESPONSE = new DERObjectIdentifier('1.3.6.1.5.5.7.16.2')

    /** 2026-09-02 16:00:00 UTC+5 */
    private final static Date REFERENCE_DATE = Date.from(Instant.parse('2026-09-02T11:00:00Z'))

    @Unroll('#file — valid CAdES at reference date')
    def "reference CAdES signatures are valid at the reference date"() {
        given:
        def cms = new CMSSignedData(fixture(file))
        def signer = firstSigner(cms)
        def signerCert = signerCertificate(cms, signer)

        expect: 'attached content matches the source payload'
        content(cms) == fixture('cades-test.bin')

        and: 'CMS signature verifies cryptographically'
        signer.verify(signerCert.publicKey, KalkanProvider.PROVIDER_NAME)

        and: 'mandatory CAdES-B signed attribute: id-aa-signingCertificateV2, hash matches the signer certificate'
        def scv2Attr = signer.signedAttributes.get(PKCSObjectIdentifiers.id_aa_signingCertificateV2)
        scv2Attr != null
        def essCertId = SigningCertificateV2.getInstance(scv2Attr.attrValues.getObjectAt(0)).certs[0]
        Arrays.equals(essCertId.certHash,
            MessageDigest.getInstance('SHA-256', KalkanProvider.PROVIDER_NAME).digest(signerCert.encoded))

        and: 'signer certificate is within its validity period at the reference date'
        !REFERENCE_DATE.before(signerCert.notBefore)
        !REFERENCE_DATE.after(signerCert.notAfter)

        and: 'T level: signature timestamp present, covers this SignerInfo, made while the cert was valid'
        def signatureTimeStamp = timeStampToken(signer, PKCSObjectIdentifiers.id_aa_signatureTimeStampToken)
        (signatureTimeStamp != null) == hasTimestamp
        if (hasTimestamp) {
            assert withinValidity(signatureTimeStamp.timeStampInfo.genTime, signerCert)
            assert imprintMatches(signatureTimeStamp, signer.signature)
        }

        and: 'LT level: certificate chain and revocation data embedded in SignedData'
        def signedData = signedData(cms)
        if (hasValidationData) {
            assert cms.getCertificatesAndCRLs('Collection', KalkanProvider.PROVIDER_NAME)
                .getCertificates(null).size() >= 2
            assert revocationInfoCount(signedData) >= 1
        } else {
            assert revocationInfoCount(signedData) == 0
        }

        and: 'LTA level: id-aa-ets-archiveTimestampV3 present, parses, made while the cert was valid'
        def archiveTimeStamp = timeStampToken(signer, ID_AA_ETS_ARCHIVE_TIMESTAMP_V3)
        (archiveTimeStamp != null) == hasArchiveTimestamp
        if (hasArchiveTimestamp) {
            assert withinValidity(archiveTimeStamp.timeStampInfo.genTime, signerCert)
        }

        where:
        file                          | hasTimestamp | hasValidationData | hasArchiveTimestamp
        'cades-test-signed-b.p7s'     | false        | false             | false
        'cades-test-signed-t.p7s'     | true         | false             | false
        'cades-test-signed-lt.p7s'    | true         | true              | false
        'cades-test-signed-lta.p7s'   | true         | true              | true
    }

    // --- helpers ---

    private static byte[] fixture(String name) {
        ResourceUtils.getFile("classpath:cades/${name}").bytes
    }

    private static SignerInformation firstSigner(CMSSignedData cms) {
        cms.signerInfos.signers.iterator().next() as SignerInformation
    }

    private static X509Certificate signerCertificate(CMSSignedData cms, SignerInformation signer) {
        cms.getCertificatesAndCRLs('Collection', KalkanProvider.PROVIDER_NAME)
            .getCertificates(signer.SID).iterator().next() as X509Certificate
    }

    private static byte[] content(CMSSignedData cms) {
        def out = new ByteArrayOutputStream()
        cms.signedContent.write(out)
        out.toByteArray()
    }

    private static SignedData signedData(CMSSignedData cms) {
        SignedData.getInstance(ContentInfo.getInstance(ASN1Object.fromByteArray(cms.encoded)).content)
    }

    /** Число элементов RevocationInfoChoices (CRL + OCSP-как-OtherRevocationInfoFormat). */
    private static int revocationInfoCount(SignedData signedData) {
        signedData.getCRLs() == null ? 0 : signedData.getCRLs().size()
    }

    private static TimeStampToken timeStampToken(SignerInformation signer, DERObjectIdentifier oid) {
        def unsigned = signer.unsignedAttributes
        if (unsigned == null) {
            return null
        }
        def attribute = unsigned.get(oid)
        if (attribute == null) {
            return null
        }
        new TimeStampToken(new CMSSignedData(attribute.attrValues.getObjectAt(0).DERObject.encoded))
    }

    private static boolean withinValidity(Date date, X509Certificate certificate) {
        !date.before(certificate.notBefore) && !date.after(certificate.notAfter)
    }

    private static boolean imprintMatches(TimeStampToken token, byte[] timestampedData) {
        def info = token.timeStampInfo
        def digest = MessageDigest.getInstance(info.messageImprintAlgOID, KalkanProvider.PROVIDER_NAME)
            .digest(timestampedData)
        Arrays.equals(info.messageImprintDigest, digest)
    }
}

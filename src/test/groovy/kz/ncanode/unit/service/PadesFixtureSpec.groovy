package kz.ncanode.unit.service

import kz.gov.pki.kalkan.asn1.ess.SigningCertificateV2
import kz.gov.pki.kalkan.asn1.pkcs.PKCSObjectIdentifiers
import kz.gov.pki.kalkan.jce.provider.KalkanProvider
import kz.gov.pki.kalkan.jce.provider.cms.CMSProcessableByteArray
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformation
import kz.gov.pki.kalkan.tsp.TimeStampToken
import org.apache.pdfbox.cos.COSName
import org.apache.pdfbox.pdmodel.PDDocument
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.util.ResourceUtils
import spock.lang.Specification
import spock.lang.Unroll

import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.time.Instant

/**
 * Проверяет эталонные PAdES-подписи (src/test/resources/pades/) на фиксированную дату
 * {@link #REFERENCE_DATE} (2026-09-02 16:00:00 UTC+5), см. AGENTS.md.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class PadesFixtureSpec extends Specification {

    private final static Date REFERENCE_DATE = Date.from(Instant.parse('2026-09-02T11:00:00Z'))

    @Unroll('#file — valid PAdES at reference date')
    def "reference PAdES signatures are valid at the reference date"() {
        given:
        def pdf = fixture(file)
        def doc = PDDocument.load(new ByteArrayInputStream(pdf))

        and: 'the document signature (not the /DocTimeStamp), CMS over the /ByteRange content'
        def sigDict = doc.signatureDictionaries.find { !isDocTimestamp(it) }
        def signedContent = sigDict.getSignedContent(new ByteArrayInputStream(pdf))
        def cms = new CMSSignedData(new CMSProcessableByteArray(signedContent), sigDict.getContents(pdf))
        def signer = firstSigner(cms)
        def signerCert = signerCertificate(cms, signer)

        expect: 'CMS signature verifies cryptographically'
        signer.verify(signerCert.publicKey, KalkanProvider.PROVIDER_NAME)

        and: 'PAdES-B: id-aa-signingCertificateV2, hash matches the signer certificate'
        def scv2 = signer.signedAttributes.get(PKCSObjectIdentifiers.id_aa_signingCertificateV2)
        scv2 != null
        Arrays.equals(
            SigningCertificateV2.getInstance(scv2.attrValues.getObjectAt(0)).certs[0].certHash,
            MessageDigest.getInstance('SHA-256', KalkanProvider.PROVIDER_NAME).digest(signerCert.encoded))

        and: 'signer certificate valid at the reference date'
        !REFERENCE_DATE.before(signerCert.notBefore)
        !REFERENCE_DATE.after(signerCert.notAfter)

        and: 'SubFilter is ETSI.CAdES.detached'
        sigDict.subFilter == 'ETSI.CAdES.detached'

        and: 'T level: signature timestamp covers the SignerInfo, made while the cert was valid'
        def signatureTimeStamp = timeStampToken(signer)
        (signatureTimeStamp != null) == hasTimestamp
        if (hasTimestamp) {
            assert withinValidity(signatureTimeStamp.timeStampInfo.genTime, signerCert)
            assert imprintMatches(signatureTimeStamp, signer.signature)
        }

        and: 'LT level: /DSS document security store with /Certs'
        def dss = doc.documentCatalog.COSObject.getDictionaryObject(COSName.getPDFName('DSS'))
        (dss != null) == hasValidationData
        if (hasValidationData) {
            assert dss.getDictionaryObject(COSName.getPDFName('Certs')) != null
        }

        and: 'LTA level: a /DocTimeStamp revision with /SubFilter /ETSI.RFC3161'
        def docTs = doc.signatureDictionaries.find { isDocTimestamp(it) }
        (docTs != null) == hasArchiveTimestamp
        if (hasArchiveTimestamp) {
            assert docTs.subFilter == 'ETSI.RFC3161'
            assert new TimeStampToken(new CMSSignedData(docTs.getContents(pdf)))
                .timeStampInfo.genTime.before(new Date())
        }

        cleanup:
        doc?.close()

        where:
        file                        | hasTimestamp | hasValidationData | hasArchiveTimestamp
        'sample-signed-b.pdf'       | false        | false             | false
        'sample-signed-t.pdf'       | true         | false             | false
        'sample-signed-lt.pdf'      | true         | true              | false
        'sample-signed-lta.pdf'     | true         | true              | true
    }

    // --- helpers ---

    private static byte[] fixture(String name) {
        ResourceUtils.getFile("classpath:pades/${name}").bytes
    }

    private static boolean isDocTimestamp(PDSignature signature) {
        'DocTimeStamp' == signature.COSObject.getNameAsString(COSName.TYPE)
    }

    private static SignerInformation firstSigner(CMSSignedData cms) {
        cms.signerInfos.signers.iterator().next() as SignerInformation
    }

    private static X509Certificate signerCertificate(CMSSignedData cms, SignerInformation signer) {
        cms.getCertificatesAndCRLs('Collection', KalkanProvider.PROVIDER_NAME)
            .getCertificates(signer.SID).iterator().next() as X509Certificate
    }

    private static TimeStampToken timeStampToken(SignerInformation signer) {
        def unsigned = signer.unsignedAttributes
        if (unsigned == null) {
            return null
        }
        def attribute = unsigned.get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken)
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
        Arrays.equals(info.messageImprintDigest,
            MessageDigest.getInstance(info.messageImprintAlgOID, KalkanProvider.PROVIDER_NAME).digest(timestampedData))
    }
}

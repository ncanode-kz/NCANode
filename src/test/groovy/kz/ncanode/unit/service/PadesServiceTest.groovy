package kz.ncanode.unit.service

import kz.gov.pki.kalkan.asn1.pkcs.PKCSObjectIdentifiers
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformation
import kz.gov.pki.kalkan.tsp.TimeStampToken
import kz.ncanode.common.WithTestData
import kz.ncanode.dto.ades.AdesLevel
import kz.ncanode.dto.ades.AdesValidationData
import kz.ncanode.dto.request.PdfSignRequest
import kz.ncanode.dto.request.SignerRequest
import kz.ncanode.service.CertificateService
import kz.ncanode.service.PdfService
import kz.ncanode.service.TspService
import org.apache.pdfbox.pdmodel.PDDocument
import org.apache.pdfbox.pdmodel.PDPage
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.boot.test.mock.mockito.SpyBean
import org.springframework.util.ResourceUtils
import spock.lang.Specification

import java.security.cert.CertificateFactory

import static kz.ncanode.common.SignerRequestTestData.*
import static org.mockito.ArgumentMatchers.any
import static org.mockito.Mockito.doReturn

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class PadesServiceTest extends Specification implements WithTestData {

    @Autowired
    PdfService pdfService

    @SpyBean
    TspService tspService

    @MockBean
    CertificateService certificateService

    def "PAdES-B adds the SigningCertificateV2 signed attribute, no /DSS"() {
        when:
        def pdf = sign(AdesLevel.B)
        def cms = firstSignatureCms(pdf)

        then:
        firstSigner(cms).signedAttributes.get(PKCSObjectIdentifiers.id_aa_signingCertificateV2) != null
        firstSigner(cms).unsignedAttributes == null

        and:
        !containsMarker(pdf, '/DSS')
    }

    def "PAdES-T adds a signature timestamp"() {
        given:
        stubTimestamp()

        when:
        def pdf = sign(AdesLevel.T)
        def cms = firstSignatureCms(pdf)

        then:
        firstSigner(cms).unsignedAttributes?.get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken) != null

        and:
        !containsMarker(pdf, '/DSS')
    }

    def "PAdES-LT writes a /DSS document security store with /VRI"() {
        given:
        stubTimestamp()
        doReturn(sampleValidationData()).when(certificateService).collectAdesValidationData(any(), any())

        when:
        def pdf = sign(AdesLevel.LT)

        then:
        containsMarker(pdf, '/DSS')
        containsMarker(pdf, '/VRI')
        containsMarker(pdf, '/Certs')

        and: 'no document timestamp at LT level'
        !containsMarker(pdf, '/DocTimeStamp')
    }

    def "PAdES-LTA adds a /DocTimeStamp revision"() {
        given:
        stubTimestamp()
        doReturn(sampleValidationData()).when(certificateService).collectAdesValidationData(any(), any())

        when:
        def pdf = sign(AdesLevel.LTA)

        then:
        containsMarker(pdf, '/DSS')
        containsMarker(pdf, '/DocTimeStamp')
        containsMarker(pdf, 'ETSI.RFC3161')

        and: 'the document has a signature dictionary of type DocTimeStamp'
        withDocument(pdf) { doc ->
            doc.signatureDictionaries.any {
                'DocTimeStamp' == it.COSObject.getNameAsString(org.apache.pdfbox.cos.COSName.TYPE)
            }
        }
    }

    def "extend raises a signed PDF to #target"() {
        given:
        stubTimestamp()
        doReturn(sampleValidationData()).when(certificateService).collectAdesValidationData(any(), any())

        def req = new kz.ncanode.dto.request.PdfExtendRequest()
        req.pdf = Base64.encoder.encodeToString(
            ResourceUtils.getFile('classpath:pades/sample-signed-t.pdf').bytes)
        req.padesLevel = target

        when:
        def pdf = Base64.decoder.decode(pdfService.extend(req).pdf)

        then:
        containsMarker(pdf, '/DSS')
        containsMarker(pdf, '/DocTimeStamp') == archive

        where:
        target        || archive
        AdesLevel.LT  || false
        AdesLevel.LTA || true
    }

    def "extend rejects a B/T target"() {
        given:
        def req = new kz.ncanode.dto.request.PdfExtendRequest()
        req.pdf = Base64.encoder.encodeToString(blankPdf())
        req.padesLevel = AdesLevel.T

        when:
        pdfService.extend(req)

        then:
        thrown(kz.ncanode.exception.ClientException)
    }

    // --- helpers ---

    private byte[] sign(AdesLevel level) {
        def req = new PdfSignRequest()
        req.pdf = Base64.encoder.encodeToString(blankPdf())
        req.padesLevel = level
        def signer = new PdfSignRequest.PdfSigner()
        signer.signer = SIGNER_REQUEST_VALID_2015()
        req.signers = [signer]
        Base64.decoder.decode(pdfService.sign(req).pdf)
    }

    private void stubTimestamp() {
        def token = new TimeStampToken(new CMSSignedData(
            new FileInputStream(ResourceUtils.getFile('classpath:tsp/tsp_token.bin'))))
        doReturn(token).when(tspService).create(any(byte[]), any(String), any(String))
    }

    private static CMSSignedData firstSignatureCms(byte[] pdf) {
        withDocument(pdf) { doc ->
            new CMSSignedData(doc.signatureDictionaries.first().getContents(pdf))
        }
    }

    private static SignerInformation firstSigner(CMSSignedData cms) {
        cms.signerInfos.signers.iterator().next() as SignerInformation
    }

    private static <T> T withDocument(byte[] pdf, Closure<T> body) {
        def doc = PDDocument.load(new ByteArrayInputStream(pdf))
        try {
            body(doc)
        } finally {
            doc.close()
        }
    }

    private static boolean containsMarker(byte[] pdf, String marker) {
        new String(pdf, 'ISO-8859-1').contains(marker)
    }

    private static byte[] blankPdf() {
        def doc = new PDDocument()
        doc.addPage(new PDPage())
        def out = new ByteArrayOutputStream()
        doc.save(out)
        doc.close()
        out.toByteArray()
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

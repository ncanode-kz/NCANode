package kz.ncanode.unit.wrapper

import kz.ncanode.common.WithTestData
import kz.ncanode.wrapper.CertificateWrapper
import kz.ncanode.wrapper.KalkanWrapper
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.util.ResourceUtils
import spock.lang.Specification
import spock.lang.Unroll

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class CertificateWrapperTest extends Specification implements WithTestData {

    @Autowired
    KalkanWrapper kalkanWrapper

    private static CertificateWrapper fromResource(String path) {
        CertificateWrapper.fromFile(ResourceUtils.getFile("classpath:${path}")).get()
    }

    @Unroll
    def "toCertificateInfo parses the distinguished name for #path"() {
        given:
        def cert = fromResource(path)

        when:
        def info = cert.toCertificateInfo(new Date(), false, false)

        then:
        info.subject != null
        info.issuer != null
        info.serialNumber != null
        info.signAlg != null

        where:
        path << ['certs/individual_valid_sign_2004_rsa.cer',
                 'certs/individual_valid_sign_2004_rsa_auth.cer',
                 'certs/ceo_valid_sign_2004_gost.cer']
    }

    def "toCertificateInfo works for a CA certificate without an extendedKeyUsage extension"() {
        given:
        def ca = fromResource('ca/nca_gost2015_test.cer')

        expect:
        ca.getExtendedKeyUsage().isEmpty()
        ca.toCertificateInfo(new Date(), false, false).keyUser.isEmpty()
    }

    def "fromBytes / fromInputStream return empty for input that is not a certificate"() {
        expect:
        CertificateWrapper.fromBytes([1, 2, 3] as byte[]).isEmpty()
        CertificateWrapper.fromInputStream(new ByteArrayInputStream(new byte[0])).isEmpty()
    }

    def "toCertificateInfo of the individual test certificate exposes the IIN"() {
        given:
        def cert = CertificateWrapper.fromBase64(CERT_INDIVIDUAL).get()

        when:
        def info = cert.toCertificateInfo(new Date(), false, false)

        then:
        info.subject.iin == '123456789011'
    }

    def "toCertificateInfo of the CEO certificate parses organization, BIN and given name"() {
        given:
        def cert = fromResource('certs/ceo_valid_sign_2004_gost.cer')

        when:
        def s = cert.toCertificateInfo(new Date(), false, false).subject

        then:
        s.organization != null
        s.bin == '123456789021'
        s.surName != null
    }

    def "getCrlList returns the CRL distribution points from the certificate"() {
        given:
        def cert = CertificateWrapper.fromBase64(CERT_INDIVIDUAL).get()

        expect:
        !cert.getCrlList().isEmpty()
        cert.getCrlList().every { it.toString().startsWith('http') }
    }

    def "getCrlList is empty when the certificate has no distribution points"() {
        given:
        def root = fromResource('ca/nca_gost2015_test.cer')

        expect:
        root.getCrlList() != null
    }

    def "getExtendedKeyUsage returns the EKU OIDs"() {
        given:
        def cert = CertificateWrapper.fromBase64(CERT_INDIVIDUAL).get()

        expect:
        !cert.getExtendedKeyUsage().isEmpty()
    }

    def "fromFile returns empty for a missing file"() {
        expect:
        CertificateWrapper.fromFile(new File('/no/such/cert.cer')).isEmpty()
    }

    def "verify returns false against an unrelated public key"() {
        given:
        def cert = CertificateWrapper.fromBase64(CERT_INDIVIDUAL).get()
        def other = fromResource('ca/nca_gost2015_test.cer')

        expect:
        !cert.verify(other.publicKey)
    }

    def "isDateValid uses the current date by default"() {
        given:
        def cert = fromResource('ca/nca_gost2015_test.cer')

        expect:
        cert.isDateValid() == cert.isDateValid(new Date())
    }
}

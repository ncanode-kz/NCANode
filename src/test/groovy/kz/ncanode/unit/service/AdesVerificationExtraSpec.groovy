package kz.ncanode.unit.service

import kz.gov.pki.kalkan.tsp.TimeStampToken
import kz.gov.pki.kalkan.tsp.TimeStampTokenInfo
import kz.ncanode.common.WithTestData
import kz.ncanode.dto.crl.CrlResult
import kz.ncanode.dto.crl.CrlStatus
import kz.ncanode.dto.ocsp.OcspResult
import kz.ncanode.dto.ocsp.OcspStatus
import kz.ncanode.service.AdesVerificationService
import kz.ncanode.service.AdesVerificationService.EmbeddedRevocation
import kz.ncanode.service.AdesVerificationService.RevocationOutcome
import kz.ncanode.service.TspService
import kz.ncanode.wrapper.CertificateWrapper
import kz.ncanode.wrapper.KalkanWrapper
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.util.ResourceUtils
import spock.lang.Specification
import spock.lang.Unroll

import java.security.cert.CertificateFactory
import java.security.cert.X509CRL
import java.security.cert.X509Certificate
import java.time.Instant

import static org.mockito.ArgumentMatchers.any
import static org.mockito.ArgumentMatchers.anyBoolean
import static org.mockito.Mockito.doReturn
import static org.mockito.Mockito.mock

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class AdesVerificationExtraSpec extends Specification implements WithTestData {

    private final static Date EARLY = Date.from(Instant.parse('2000-01-01T00:00:00Z'))
    private final static Date LATE = Date.from(Instant.parse('2100-01-01T00:00:00Z'))

    @Autowired
    AdesVerificationService ades

    @Autowired
    KalkanWrapper kalkanWrapper

    @MockBean
    TspService tspService

    private static byte[] ocsp(String name) {
        ResourceUtils.getFile("classpath:ocsp/${name}").bytes
    }

    private CertificateWrapper cert(String key, String pass) {
        kalkanWrapper.read(key, null, pass).getCertificate()
    }

    def "verifiedTimestamp: null token -> empty"() {
        expect:
        ades.verifiedTimestamp(null, [1, 2, 3] as byte[]).isEmpty()
    }

    def "verifiedTimestamp: invalid token -> empty, valid -> present"() {
        given:
        def token = mock(TimeStampToken)
        doReturn(false).when(tspService).verify(any(), any(byte[]))

        expect:
        ades.verifiedTimestamp(token, [1] as byte[]).isEmpty()

        when:
        doReturn(true).when(tspService).verify(any(), any(byte[]))

        then:
        ades.verifiedTimestamp(token, [1] as byte[]).isPresent()
    }

    def "bestSignatureTime: falls back when no verified timestamp"() {
        expect:
        ades.bestSignatureTime(Optional.empty(), EARLY) == EARLY
    }

    def "bestSignatureTime: uses timestamp genTime when present"() {
        given:
        def info = mock(TimeStampTokenInfo)
        doReturn(LATE).when(info).getGenTime()
        def token = mock(TimeStampToken)
        doReturn(info).when(token).getTimeStampInfo()

        expect:
        ades.bestSignatureTime(Optional.of(token), EARLY) == LATE
    }

    def "revocationAcceptable: no crl status -> acceptable"() {
        given:
        def c = mock(CertificateWrapper)
        doReturn(null).when(c).getCrlStatus()

        expect:
        ades.revocationAcceptable(c, EARLY)
    }

    def "revocationAcceptable: revoked with null revocation date -> not acceptable"() {
        given:
        def c = mock(CertificateWrapper)
        doReturn(CrlStatus.builder().result(CrlResult.REVOKED).build()).when(c).getCrlStatus()

        expect:
        !ades.revocationAcceptable(c, EARLY)
    }

    @Unroll
    def "signerCertificateValid: timestamped=#timestamped -> #expected"() {
        given:
        def issuer = mock(CertificateWrapper)
        doReturn(true).when(issuer).isDateValid(any())
        def c = mock(CertificateWrapper)
        doReturn(true).when(c).isDateValid(any())
        doReturn(issuer).when(c).getIssuerCertificate()
        doReturn(null).when(c).getCrlStatus()
        doReturn(dateValid).when(c).isValid(any(Date), anyBoolean(), anyBoolean())

        expect:
        ades.signerCertificateValid(c, EARLY, timestamped, false, false) == expected

        where:
        timestamped | dateValid || expected
        true        | false     || true
        false       | true      || true
        false       | false     || false
    }

    def "checkRevocation: both checks off -> SKIPPED"() {
        given:
        def c = mock(CertificateWrapper)

        expect:
        ades.checkRevocation(c, EARLY, EmbeddedRevocation.empty(), false, false) == RevocationOutcome.SKIPPED
    }

    def "checkRevocation: embedded OCSP GOOD for individual 2004"() {
        given:
        def c = cert(KEY_INDIVIDUAL_VALID_SIGN_2004, KEY_INDIVIDUAL_VALID_SIGN_2004_PASSWORD)
        def embedded = new EmbeddedRevocation([], [ocsp('ocsp_response_individual_sign_2004.bin')])

        expect:
        ades.checkRevocation(c, EARLY, embedded, true, false) == RevocationOutcome.GOOD
    }

    @Unroll
    def "checkRevocation: embedded OCSP REVOKED for ceo 2015 (bestTime=#label)"() {
        given:
        def c = cert(KEY_CEO_REVOKED_2015, KEY_INDIVIDUAL_VALID_2015_PASSWORD)
        def embedded = new EmbeddedRevocation([], [ocsp('ocsp_response_ceo_2015_revoked.bin')])

        expect:
        ades.checkRevocation(c, bestTime, embedded, true, false) == expected

        where:
        label   | bestTime || expected
        'early' | EARLY    || RevocationOutcome.REVOKED_AFTER_SIGNING
        'late'  | LATE     || RevocationOutcome.REVOKED_BEFORE_SIGNING
    }

    def "checkRevocation: embedded OCSP with non-matching serial -> MISSING"() {
        given:
        def c = cert(KEY_INDIVIDUAL_VALID_2015, KEY_INDIVIDUAL_VALID_2015_PASSWORD)
        def embedded = new EmbeddedRevocation([], [ocsp('ocsp_response_ceo_2015_revoked.bin')])

        expect:
        ades.checkRevocation(c, EARLY, embedded, true, false) == RevocationOutcome.MISSING
    }

    def "checkRevocation: online OCSP ACTIVE -> GOOD"() {
        given:
        def c = mock(CertificateWrapper)
        doReturn(realX509()).when(c).getX509Certificate()
        doReturn([OcspStatus.builder().result(OcspResult.ACTIVE).build()]).when(c).getOcspStatus()
        doReturn(null).when(c).getCrlStatus()

        expect:
        ades.checkRevocation(c, EARLY, EmbeddedRevocation.empty(), true, false) == RevocationOutcome.GOOD
    }

    def "checkRevocation: online OCSP REVOKED after signing -> REVOKED_AFTER_SIGNING"() {
        given:
        def c = mock(CertificateWrapper)
        doReturn(realX509()).when(c).getX509Certificate()
        doReturn([OcspStatus.builder().result(OcspResult.REVOKED).revocationTime(LATE).build()]).when(c).getOcspStatus()
        doReturn(null).when(c).getCrlStatus()

        expect:
        ades.checkRevocation(c, EARLY, EmbeddedRevocation.empty(), true, false) == RevocationOutcome.REVOKED_AFTER_SIGNING
    }

    def "checkRevocation: online CRL ACTIVE -> GOOD, REVOKED before -> REVOKED_BEFORE_SIGNING"() {
        given:
        def c = mock(CertificateWrapper)
        doReturn(realX509()).when(c).getX509Certificate()
        doReturn(null).when(c).getOcspStatus()
        doReturn(CrlStatus.builder().result(CrlResult.ACTIVE).build()).when(c).getCrlStatus()

        expect:
        ades.checkRevocation(c, EARLY, EmbeddedRevocation.empty(), false, true) == RevocationOutcome.GOOD

        when:
        doReturn(CrlStatus.builder().result(CrlResult.REVOKED).revocationDate(EARLY).build()).when(c).getCrlStatus()

        then:
        ades.checkRevocation(c, LATE, EmbeddedRevocation.empty(), false, true) == RevocationOutcome.REVOKED_BEFORE_SIGNING
    }

    def "checkRevocation: nothing available -> MISSING"() {
        given:
        def c = mock(CertificateWrapper)
        doReturn(realX509()).when(c).getX509Certificate()
        doReturn(null).when(c).getOcspStatus()
        doReturn(null).when(c).getCrlStatus()

        expect:
        ades.checkRevocation(c, EARLY, EmbeddedRevocation.empty(), true, true) == RevocationOutcome.MISSING
    }

    def "checkRevocation: embedded CRL not covering issuer is skipped -> MISSING"() {
        given:
        def c = mock(CertificateWrapper)
        def x509 = realX509()
        doReturn(x509).when(c).getX509Certificate()
        doReturn(x509.getIssuerX500Principal()).when(c).getIssuerX500Principal()
        doReturn(null).when(c).getOcspStatus()
        doReturn(null).when(c).getCrlStatus()
        def foreignCrl = loadCrl('nca_rsa_test.crl')
        def embedded = new EmbeddedRevocation([foreignCrl], [])

        expect:
        ades.checkRevocation(c, EARLY, embedded, false, true) == RevocationOutcome.MISSING
    }

    @Unroll
    def "checkRevocation: embedded CRL revoking the signer -> #expected"() {
        given:
        def c = cert(KEY_CEO_REVOKED_2015, KEY_INDIVIDUAL_VALID_2015_PASSWORD)
        def embedded = new EmbeddedRevocation([loadCrl('nca_gost2022_test.crl')], [])

        expect:
        ades.checkRevocation(c, bestTime, embedded, false, true) == expected

        where:
        label   | bestTime || expected
        'early' | EARLY    || RevocationOutcome.REVOKED_AFTER_SIGNING
        'late'  | LATE     || RevocationOutcome.REVOKED_BEFORE_SIGNING
    }

    def "checkRevocation: embedded CRL not listing the signer -> GOOD"() {
        given:
        def c = cert(KEY_INDIVIDUAL_VALID_2015, KEY_INDIVIDUAL_VALID_2015_PASSWORD)
        def embedded = new EmbeddedRevocation([loadCrl('nca_gost2022_test.crl')], [])

        expect:
        ades.checkRevocation(c, EARLY, embedded, false, true) == RevocationOutcome.GOOD
    }

    def "toTspInfo maps fields"() {
        given:
        def info = mock(TimeStampTokenInfo)
        doReturn(BigInteger.valueOf(255)).when(info).getSerialNumber()
        doReturn(EARLY).when(info).getGenTime()
        doReturn('1.2.3').when(info).getPolicy()
        doReturn(null).when(info).getTsa()
        doReturn('2.16.840.1.101.3.4.2.1').when(info).getMessageImprintAlgOID()
        doReturn([1, 2, 3] as byte[]).when(info).getMessageImprintDigest()

        when:
        def tsp = ades.toTspInfo(info)

        then:
        tsp.serialNumber == '00ff'
        tsp.policy == '1.2.3'
        tsp.tsa == null
    }

    private static X509CRL loadCrl(String name) {
        (X509CRL) CertificateFactory.getInstance('X.509')
            .generateCRL(ResourceUtils.getFile("classpath:crl/${name}").newInputStream())
    }

    private X509Certificate realX509() {
        cert(KEY_INDIVIDUAL_VALID_2015, KEY_INDIVIDUAL_VALID_2015_PASSWORD).getX509Certificate()
    }
}

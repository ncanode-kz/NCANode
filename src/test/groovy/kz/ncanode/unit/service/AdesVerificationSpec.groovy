package kz.ncanode.unit.service

import kz.ncanode.dto.ades.AdesLevel
import kz.ncanode.dto.ades.AdesSubIndication
import kz.ncanode.dto.ades.AdesValidationStatus
import kz.ncanode.dto.certificate.CertificateRevocation
import kz.ncanode.dto.crl.CrlResult
import kz.ncanode.dto.crl.CrlStatus
import kz.ncanode.service.AdesVerificationService.EmbeddedRevocation
import kz.ncanode.service.AdesVerificationService.RevocationOutcome
import kz.ncanode.service.AdesVerificationService
import kz.ncanode.service.CertificateService
import kz.ncanode.service.CmsService
import kz.ncanode.wrapper.CertificateWrapper
import org.mockito.invocation.InvocationOnMock
import org.mockito.stubbing.Answer
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.util.ResourceUtils
import spock.lang.Specification
import spock.lang.Unroll

import java.security.cert.CertificateFactory
import java.time.Instant

import static org.mockito.ArgumentMatchers.any
import static org.mockito.ArgumentMatchers.anyBoolean
import static org.mockito.Mockito.mock
import static org.mockito.Mockito.when

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class AdesVerificationSpec extends Specification {

    private final static Date NOW = Date.from(Instant.parse('2026-09-02T11:00:00Z'))
    private final static Date SIGN_TIME = Date.from(Instant.parse('2026-06-01T00:00:00Z'))

    @Autowired
    AdesVerificationService adesVerificationService

    @Autowired
    CmsService cmsService

    @MockBean
    CertificateService certificateService

    @Unroll
    def "detectLevel: #expected"() {
        expect:
        adesVerificationService.detectLevel(hasT, hasLT, hasLTA) == expected

        where:
        hasT  | hasLT | hasLTA || expected
        false | false | false  || AdesLevel.B
        true  | false | false  || AdesLevel.T
        true  | true  | false  || AdesLevel.LT
        true  | true  | true   || AdesLevel.LTA
        false | true  | true   || AdesLevel.LTA   // archive метка → LTA даже если T не распознан
    }

    @Unroll('grade → #status / #sub')
    def "grade maps checks to ETSI-like status"() {
        given:
        def cert = mock(CertificateWrapper)
        when(cert.isDateValid(any())).thenReturn(certDateValid)
        if (issuerDateValid != null) {
            def issuer = mock(CertificateWrapper)
            when(issuer.isDateValid(any())).thenReturn(issuerDateValid)
            when(cert.getIssuerCertificate()).thenReturn(issuer)
        }

        when:
        def report = adesVerificationService.grade(certPresent, crypto, essHash, tsPresent, tsValid,
            certPresent ? cert : null, SIGN_TIME, revocation)

        then:
        report.status() == status
        report.subIndication() == sub

        where:
        certPresent | crypto | essHash | tsPresent | tsValid | certDateValid | issuerDateValid | revocation                                     || status                          | sub
        false       | false  | true    | false     | false   | true          | true            | RevocationOutcome.GOOD                          || AdesValidationStatus.INDETERMINATE | AdesSubIndication.NO_SIGNING_CERTIFICATE_FOUND
        true        | false  | true    | false     | false   | true          | true            | RevocationOutcome.GOOD                          || AdesValidationStatus.INVALID       | AdesSubIndication.SIG_CRYPTO_FAILURE
        true        | true   | false   | false     | false   | true          | true            | RevocationOutcome.GOOD                          || AdesValidationStatus.INVALID       | AdesSubIndication.CERT_HASH_MISMATCH
        true        | true   | true    | true      | false   | true          | true            | RevocationOutcome.GOOD                          || AdesValidationStatus.INDETERMINATE | AdesSubIndication.TIMESTAMP_INVALID
        true        | true   | true    | false     | false   | false         | true            | RevocationOutcome.GOOD                          || AdesValidationStatus.INDETERMINATE | AdesSubIndication.OUT_OF_BOUNDS_NO_POE
        true        | true   | true    | false     | false   | true          | null            | RevocationOutcome.GOOD                          || AdesValidationStatus.INDETERMINATE | AdesSubIndication.CHAIN_INCOMPLETE
        true        | true   | true    | false     | false   | true          | true            | RevocationOutcome.REVOKED_BEFORE_SIGNING        || AdesValidationStatus.INVALID       | AdesSubIndication.CERT_REVOKED
        true        | true   | true    | true      | true    | true          | true            | RevocationOutcome.REVOKED_AFTER_SIGNING         || AdesValidationStatus.VALID         | null
        true        | true   | true    | false     | false   | true          | true            | RevocationOutcome.MISSING                       || AdesValidationStatus.INDETERMINATE | AdesSubIndication.REVOCATION_DATA_MISSING
        true        | true   | true    | false     | false   | true          | true            | RevocationOutcome.GOOD                          || AdesValidationStatus.VALID         | null
    }

    @Unroll
    def "checkRevocation applies POE by revocation date (#expected)"() {
        given:
        def cf = CertificateFactory.getInstance('X.509')
        def cert = mock(CertificateWrapper)
        when(cert.getX509Certificate()).thenReturn(cf.generateCertificate(
            ResourceUtils.getFile('classpath:certs/ceo_valid_sign_2004_gost.cer').newInputStream()) as java.security.cert.X509Certificate)
        when(cert.getCrlStatus()).thenReturn(CrlStatus.builder()
            .result(CrlResult.REVOKED).revocationDate(REVOKED_ON).build())

        when:
        def outcome = adesVerificationService.checkRevocation(cert, referenceDate, EmbeddedRevocation.empty(), false, true)

        then:
        outcome == expected

        where:
        referenceDate                                              || expected
        Date.from(java.time.Instant.parse('2000-01-01T00:00:00Z')) || RevocationOutcome.REVOKED_AFTER_SIGNING
        Date.from(java.time.Instant.parse('2030-01-01T00:00:00Z')) || RevocationOutcome.REVOKED_BEFORE_SIGNING
    }

    private final static Date REVOKED_ON = Date.from(java.time.Instant.parse('2025-01-01T00:00:00Z'))

    def "revocationAcceptable: revoked after best signature time is still acceptable"() {
        given:
        def cert = mock(CertificateWrapper)
        when(cert.getCrlStatus()).thenReturn(CrlStatus.builder()
            .result(CrlResult.REVOKED)
            .revocationDate(Date.from(Instant.parse('2026-07-01T00:00:00Z')))
            .build())

        expect:
        adesVerificationService.revocationAcceptable(cert, SIGN_TIME)      // отзыв позже подписи — ок
        !adesVerificationService.revocationAcceptable(cert, NOW)           // отзыв раньше "сейчас" — не ок
    }

    @Unroll('#file → adesLevel #expectedLevel')
    def "CmsService.verify reports the CAdES level"() {
        given:
        when(certificateService.getCurrentDate()).thenReturn(NOW)
        when(certificateService.attachValidationData(any(), anyBoolean(), anyBoolean()))
            .thenAnswer(new IssuerAnswer())

        when:
        def response = cmsService.verify(base64('cades/' + file), null, false, false)

        then:
        response.signers.size() == 1
        response.signers[0].adesLevel == expectedLevel

        and: 'T+ uses the signature timestamp genTime as the proven signing time'
        (expectedLevel == AdesLevel.B) == (response.signers[0].tsp == null)

        where:
        file                        || expectedLevel
        'cades-test-signed-b.p7s'   || AdesLevel.B
        'cades-test-signed-t.p7s'   || AdesLevel.T
        'cades-test-signed-lt.p7s'  || AdesLevel.LT
        'cades-test-signed-lta.p7s' || AdesLevel.LTA
    }

    private static String base64(String resource) {
        Base64.encoder.encodeToString(ResourceUtils.getFile("classpath:${resource}").bytes)
    }

    /** attachValidationData → прикрепляет действующий issuer (для прохождения проверки цепочки). */
    private static class IssuerAnswer implements Answer<Void> {
        @Override
        Void answer(InvocationOnMock invocation) {
            def cert = invocation.getArgument(0, CertificateWrapper)
            def issuer = mock(CertificateWrapper)
            when(issuer.isDateValid(any())).thenReturn(true)
            cert.setIssuerCertificate(issuer)
            return null
        }
    }
}

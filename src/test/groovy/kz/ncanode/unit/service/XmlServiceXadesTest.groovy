package kz.ncanode.unit.service

import kz.ncanode.common.WithTestData
import kz.ncanode.dto.ades.AdesLevel
import kz.ncanode.service.CertificateService
import kz.ncanode.service.XmlService
import kz.ncanode.wrapper.CertificateWrapper
import org.mockito.invocation.InvocationOnMock
import org.mockito.stubbing.Answer
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.util.ResourceUtils
import spock.lang.Specification
import spock.lang.Unroll

import java.time.Instant

import static org.mockito.ArgumentMatchers.any
import static org.mockito.ArgumentMatchers.anyBoolean
import static org.mockito.Mockito.mock
import static org.mockito.Mockito.when

/**
 * Покрывает XAdES-ветки {@link XmlService#verify} (проверка метки времени, извлечение вшитого
 * отзыва, {@code CertDigest}) и очистку пробелов. Подпись XAdES B/T/LT/LTA — в {@code XadesServiceTest}.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class XmlServiceXadesTest extends Specification implements WithTestData {

    private final static Date REFERENCE_DATE = Date.from(Instant.parse('2026-09-02T11:00:00Z'))

    @Autowired
    XmlService xmlService

    @MockBean
    CertificateService certificateService

    private static String fixture(String name) {
        ResourceUtils.getFile("classpath:xades/${name}").text
    }

    @Unroll('#file -> adesLevel #level')
    def "verify reports the XAdES level for the reference signatures"() {
        given:
        when(certificateService.getCurrentDate()).thenReturn(REFERENCE_DATE)
        when(certificateService.attachValidationData(any(), anyBoolean(), anyBoolean())).thenAnswer(new IssuerAnswer())

        when:
        def response = xmlService.verify(fixture(file), false, false)

        then:
        response.signers.size() == 1
        response.adesLevel == level

        where:
        file                         || level
        'xades-test-signed-b.xml'    || AdesLevel.B
        'xades-test-signed-t.xml'    || AdesLevel.T
        'xades-test-signed-lt.xml'   || AdesLevel.LT
        'xades-test-signed-lta.xml'  || AdesLevel.LTA
    }

    def "verify with OCSP/CRL checks walks the embedded-revocation path"() {
        given:
        when(certificateService.getCurrentDate()).thenReturn(REFERENCE_DATE)
        when(certificateService.attachValidationData(any(), anyBoolean(), anyBoolean())).thenAnswer(new IssuerAnswer())

        when:
        def response = xmlService.verify(fixture('xades-test-signed-lt.xml'), true, true)

        then:
        response.signers.size() == 1
        response.adesLevel == AdesLevel.LT
    }

    def "removeWhitespace strips insignificant text nodes"() {
        given:
        def xml = "<?xml version=\"1.0\"?>\n<a>\n  <b>test</b>\n</a>\n"

        when:
        def trimmed = xmlService.removeWhitespace(xml)

        then:
        !trimmed.contains('  <b>')
        trimmed.contains('<b>test</b>')
    }

    def "prepare trims and optionally removes whitespace"() {
        given:
        def xml = "<?xml version=\"1.0\"?>\n<a> <b>x</b> </a>\n"

        expect:
        xmlService.prepare(xml, false) == xml.trim()
        !xmlService.prepare(xml, true).contains('> <b>')
    }

    static class IssuerAnswer implements Answer<Void> {
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

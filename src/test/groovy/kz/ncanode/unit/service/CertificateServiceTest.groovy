package kz.ncanode.unit.service

import kz.ncanode.common.WithTestData
import kz.ncanode.service.CertificateService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import spock.lang.Specification

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class CertificateServiceTest extends Specification implements WithTestData {

    @Autowired
    CertificateService certificateService

    def "check certificate info method"() {
        given:
        def certs = [
            CERT_INDIVIDUAL
        ]

        when:
        def result = certificateService.info(certs, false, false)

        then:
        result != null
        result.signers.size() == 1
    }

    def "info with an empty certificate list is invalid"() {
        when:
        def result = certificateService.info([], false, false)

        then:
        !result.valid
        result.signers.isEmpty()
    }

    def "invalid certificate info method"() {
        given:
        def certs = [
            "YXNkYXNk"
        ]

        when:
        def result = certificateService.info(certs, false, false)

        then:
        !result.valid
        result.message == '[0]: Invalid certificate given.'
    }
}

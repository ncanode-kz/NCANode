package kz.ncanode.unit.service

import kz.ncanode.service.CaService
import kz.ncanode.service.CrlService
import kz.ncanode.service.WarmupService
import spock.lang.Specification

class WarmupServiceTest extends Specification {

    CaService caService = Mock()
    CrlService crlA = Mock()
    CrlService crlB = Mock()

    WarmupService service() {
        new WarmupService(caService, [crlA, crlB])
    }

    def "isReady requires CA and every CRL service to be ready"() {
        given:
        caService.isCacheReady() >> ca
        crlA.isCacheReady() >> a
        crlB.isCacheReady() >> b

        expect:
        service().isReady() == expected

        where:
        ca    | a     | b     || expected
        true  | true  | true  || true
        false | true  | true  || false
        true  | false | true  || false
        true  | true  | false || false
    }

    def "exposes per-module readiness"() {
        given:
        caService.isCacheReady() >> true
        crlA.isCacheReady() >> true
        crlB.isCacheReady() >> false

        expect:
        service().isCaReady()
        !service().isCrlReady()
    }
}

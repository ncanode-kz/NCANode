package kz.ncanode.unit.service

import kz.ncanode.configuration.SystemConfiguration
import kz.ncanode.service.DirectoryService
import spock.lang.Specification

class DirectoryServiceTest extends Specification {

    def "creates and returns the cache path"() {
        given:
        def base = File.createTempDir()
        def config = Mock(SystemConfiguration) { getCacheDir() >> base.absolutePath }
        def service = new DirectoryService(config)

        when:
        def result = service.getCachePathFor('crl/full')

        then:
        result.isPresent()
        result.get().isDirectory()

        cleanup:
        base.deleteDir()
    }

    def "returns empty when the cache path cannot be created"() {
        given: 'cacheDir points at a regular file, so mkdirs under it fails'
        def file = File.createTempFile('ncanode', '.tmp')
        def config = Mock(SystemConfiguration) { getCacheDir() >> file.absolutePath }
        def service = new DirectoryService(config)

        expect:
        service.getCachePathFor('sub').isEmpty()

        cleanup:
        file.delete()
    }
}

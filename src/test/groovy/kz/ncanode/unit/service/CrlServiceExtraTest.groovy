package kz.ncanode.unit.service

import kz.ncanode.common.WithTestData
import kz.ncanode.configuration.crl.CrlConfiguration
import kz.ncanode.dto.crl.CrlResult
import kz.ncanode.exception.ServerException
import kz.ncanode.service.CrlService
import kz.ncanode.service.DirectoryService
import kz.ncanode.wrapper.KalkanWrapper
import org.apache.http.StatusLine
import org.apache.http.client.methods.CloseableHttpResponse
import org.apache.http.entity.ByteArrayEntity
import org.apache.http.impl.client.CloseableHttpClient
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.scheduling.TaskScheduler
import org.springframework.util.ResourceUtils
import spock.lang.Specification

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class CrlServiceExtraTest extends Specification implements WithTestData {

    @Autowired
    KalkanWrapper kalkanWrapper

    DirectoryService directoryService = Mock()
    CrlConfiguration crlConfiguration = Mock()
    CloseableHttpClient client = Mock()
    TaskScheduler taskScheduler = Mock()
    CrlService service

    File cacheDir

    def setup() {
        cacheDir = File.createTempDir()
        service = new CrlService(directoryService, crlConfiguration, client, taskScheduler, CrlService.CRL_DEFAULT)
    }

    def cleanup() {
        cacheDir.deleteDir()
    }

    private CloseableHttpResponse httpResponse(int status, byte[] body) {
        def statusLine = Mock(StatusLine) { getStatusCode() >> status }
        Mock(CloseableHttpResponse) {
            getStatusLine() >> statusLine
            getEntity() >> (body == null ? null : new ByteArrayEntity(body))
        }
    }

    private static byte[] crlBytes(String name) {
        ResourceUtils.getFile("classpath:crl/${name}").bytes
    }

    def "isCacheReady is true when CRL scheduling is disabled"() {
        given:
        crlConfiguration.isEnabled() >> false

        expect:
        service.isCacheReady()
    }

    def "isCacheReady reflects presence of a full CRL file"() {
        given:
        crlConfiguration.isEnabled() >> true
        crlConfiguration.getTtl() >> 10
        directoryService.getCachePathFor('crl/full') >> Optional.of(cacheDir)

        expect:
        !service.isCacheReady()

        when:
        new File(cacheDir, 'x.crl').text = 'x'

        then:
        service.isCacheReady()
    }

    def "verify returns ACTIVE immediately when CRL checking is disabled"() {
        given:
        crlConfiguration.isEnabled() >> false
        def cert = kalkanWrapper.read(KEY_INDIVIDUAL_VALID_2015, null, KEY_INDIVIDUAL_VALID_2015_PASSWORD).certificate

        expect:
        service.verify(cert).result == CrlResult.ACTIVE
    }

    def "verify finds a revoked certificate in a cached CRL"() {
        given:
        crlConfiguration.isEnabled() >> true
        new File(cacheDir, 'nca_gost2022_test.crl').bytes = crlBytes('nca_gost2022_test.crl')
        directoryService.getCachePathFor(_) >> Optional.of(cacheDir)
        def cert = kalkanWrapper.read(KEY_CEO_REVOKED_2015, null, KEY_INDIVIDUAL_VALID_2015_PASSWORD).certificate

        when:
        def status = service.verify(cert)

        then:
        status.result == CrlResult.REVOKED
        status.file == 'nca_gost2022_test.crl'
    }

    def "getEncodedCrlsFor returns DER CRLs matching the certificate issuer"() {
        given:
        new File(cacheDir, 'nca_gost2022_test.crl').bytes = crlBytes('nca_gost2022_test.crl')
        new File(cacheDir, 'nca_rsa_test.crl').bytes = crlBytes('nca_rsa_test.crl')
        def emptyDir = File.createTempDir()
        directoryService.getCachePathFor('crl/full') >> Optional.of(cacheDir)
        directoryService.getCachePathFor('crl/delta') >> Optional.of(emptyDir)
        def cert = kalkanWrapper.read(KEY_CEO_REVOKED_2015, null, KEY_INDIVIDUAL_VALID_2015_PASSWORD)
            .certificate.x509Certificate

        when:
        def encoded = service.getEncodedCrlsFor(cert)

        then:
        encoded.size() == 1

        cleanup:
        emptyDir.deleteDir()
    }

    def "loadCrl throws ServerException on a non-CRL file"() {
        given:
        def bad = new File(cacheDir, 'broken.crl')
        bad.text = 'not a crl'

        when:
        service.loadCrl(bad)

        then:
        thrown(ServerException)
    }

    def "getCrlFiles lists only readable .crl files"() {
        given:
        new File(cacheDir, 'a.crl').text = 'x'
        new File(cacheDir, 'b.txt').text = 'x'
        directoryService.getCachePathFor('crl/full') >> Optional.of(cacheDir)

        expect:
        service.getCrlFiles('crl/full')*.name == ['a.crl']
    }

    def "updateCache downloads missing CRL files"() {
        given:
        crlConfiguration.isEnabled() >> true
        crlConfiguration.getTtl() >> 10
        crlConfiguration.getUrlList() >> ['abc': new URL('http://example.test/nca.crl')]
        directoryService.getCachePathFor(_) >> Optional.of(cacheDir)
        client.execute(_) >> httpResponse(200, crlBytes('nca_rsa_test.crl'))

        when:
        service.updateCache(true, crlConfiguration, 'crl/full')

        then:
        cacheDir.listFiles().find { it.name.endsWith('.crl') && it.length() > 0 }
    }

    def "updateCache does nothing when disabled"() {
        given:
        crlConfiguration.isEnabled() >> false
        directoryService.getCachePathFor(_) >> Optional.of(cacheDir)

        when:
        service.updateCache(false, crlConfiguration, 'crl/full')

        then:
        0 * client.execute(_)
    }

    def "downloadCrl swallows an IO failure"() {
        given:
        directoryService.getCachePathFor(_) >> Optional.of(cacheDir)
        client.execute(_) >> { throw new IOException('boom') }

        when:
        service.downloadCrl('crl/full', new URL('http://example.test/x.crl'))

        then:
        noExceptionThrown()
    }

    def "updateCache deletes a stale CRL file and re-downloads it"() {
        given:
        def stale = new File(cacheDir, 'old.crl')
        stale.text = 'stale'
        stale.setLastModified(0L)
        crlConfiguration.isEnabled() >> true
        crlConfiguration.getTtl() >> 10
        crlConfiguration.getUrlList() >> ['fresh': new URL('http://example.test/fresh.crl')]
        directoryService.getCachePathFor(_) >> Optional.of(cacheDir)
        client.execute(_) >> httpResponse(200, crlBytes('nca_rsa_test.crl'))

        when:
        service.updateCache(false, crlConfiguration, 'crl/full')

        then:
        !stale.exists()
    }

    def "downloadCrl swallows a non-200 response"() {
        given:
        directoryService.getCachePathFor(_) >> Optional.of(cacheDir)
        client.execute(_) >> httpResponse(500, null)

        when:
        service.downloadCrl('crl/full', new URL('http://example.test/x.crl'))

        then:
        noExceptionThrown()
        !cacheDir.listFiles()
    }
}

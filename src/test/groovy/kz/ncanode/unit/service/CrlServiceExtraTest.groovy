package kz.ncanode.unit.service

import kz.ncanode.common.WithTestData
import kz.ncanode.configuration.crl.CrlConfiguration
import kz.ncanode.dto.crl.CrlResult
import kz.ncanode.exception.ServerException
import kz.ncanode.service.CrlService
import kz.ncanode.service.DirectoryService
import kz.ncanode.util.Util
import kz.ncanode.wrapper.KalkanWrapper
import org.apache.http.StatusLine
import org.apache.http.client.methods.CloseableHttpResponse
import org.apache.http.entity.ByteArrayEntity
import org.apache.http.entity.InputStreamEntity
import org.apache.http.impl.client.CloseableHttpClient
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.scheduling.TaskScheduler
import org.springframework.util.ResourceUtils
import spock.lang.Specification
import spock.lang.Timeout

import javax.security.auth.x500.X500Principal
import java.security.cert.X509CRL
import java.security.cert.X509CRLEntry
import java.security.cert.X509Certificate
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

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

    def "verify reads each CRL file only once"() {
        given:
        crlConfiguration.isEnabled() >> true
        new File(cacheDir, 'nca_gost2022_test.crl').bytes = crlBytes('nca_gost2022_test.crl')
        def emptyDir = File.createTempDir()
        directoryService.getCachePathFor('crl/full') >> Optional.of(cacheDir)
        directoryService.getCachePathFor('crl/delta') >> Optional.of(emptyDir)
        def loads = new AtomicInteger()
        def counting = new CrlService(directoryService, crlConfiguration, client, taskScheduler, CrlService.CRL_DEFAULT) {
            @Override
            X509CRL loadCrl(File file) {
                loads.incrementAndGet()
                return super.loadCrl(file)
            }
        }
        def cert = kalkanWrapper.read(KEY_CEO_REVOKED_2015, null, KEY_INDIVIDUAL_VALID_2015_PASSWORD).certificate

        when:
        def statuses = (1..3).collect { counting.verify(cert) }

        then:
        statuses*.result == [CrlResult.REVOKED] * 3
        loads.get() == 1

        cleanup:
        emptyDir.deleteDir()
    }

    def "verify notices a replaced CRL file"() {
        given:
        crlConfiguration.isEnabled() >> true
        def crlFile = new File(cacheDir, 'nca.crl')
        crlFile.bytes = crlBytes('nca_rsa_test.crl')
        directoryService.getCachePathFor(_) >> Optional.of(cacheDir)
        def cert = kalkanWrapper.read(KEY_CEO_REVOKED_2015, null, KEY_INDIVIDUAL_VALID_2015_PASSWORD).certificate

        when:
        def before = service.verify(cert)
        crlFile.bytes = crlBytes('nca_gost2022_test.crl')
        crlFile.setLastModified(crlFile.lastModified() + 60_000)
        def after = service.verify(cert)

        then:
        before.result == CrlResult.ACTIVE
        after.result == CrlResult.REVOKED
    }

    def "downloadCrl invalidates an index for the overwritten file"() {
        given:
        crlConfiguration.isEnabled() >> true
        def emptyDir = File.createTempDir()
        directoryService.getCachePathFor('crl/full') >> Optional.of(cacheDir)
        directoryService.getCachePathFor('crl/delta') >> Optional.of(emptyDir)
        def url = new URL('http://example.test/nca.crl')
        client.execute(_) >>> [
            httpResponse(200, crlBytes('nca_rsa_test.crl')),
            httpResponse(200, crlBytes('nca_gost2022_test.crl')),
        ]
        new File(cacheDir, 'other.crl').bytes = crlBytes('nca_rsa_test.crl')
        new File(emptyDir, 'delta.crl').bytes = crlBytes('nca_rsa_test.crl')
        def cert = kalkanWrapper.read(KEY_CEO_REVOKED_2015, null, KEY_INDIVIDUAL_VALID_2015_PASSWORD).certificate
        def indexesField = CrlService.getDeclaredField('crlIndexes')
        indexesField.setAccessible(true)
        def indexes = (Map) indexesField.get(service)

        when:
        service.downloadCrl('crl/full', url)
        def before = service.verify(cert)
        def indexesBeforeOverwrite = indexes.size()
        service.downloadCrl('crl/full', url)
        def indexesAfterOverwrite = indexes.size()
        def after = service.verify(cert)

        then:
        before.result == CrlResult.ACTIVE
        indexesBeforeOverwrite == 3
        indexesAfterOverwrite == 2
        after.result == CrlResult.REVOKED

        cleanup:
        emptyDir.deleteDir()
    }

    def "verify forgets a deleted CRL file"() {
        given:
        crlConfiguration.isEnabled() >> true
        def crlFile = new File(cacheDir, 'nca.crl')
        crlFile.bytes = crlBytes('nca_gost2022_test.crl')
        directoryService.getCachePathFor(_) >> Optional.of(cacheDir)
        def cert = kalkanWrapper.read(KEY_CEO_REVOKED_2015, null, KEY_INDIVIDUAL_VALID_2015_PASSWORD).certificate

        when:
        def before = service.verify(cert)
        crlFile.delete()
        def after = service.verify(cert)

        then:
        before.result == CrlResult.REVOKED
        after.result == CrlResult.ACTIVE
    }

    def "verify falls back to X509CRL when the CRL cannot be indexed"() {
        given:
        crlConfiguration.isEnabled() >> true
        new File(cacheDir, 'nca.crl').text = 'x'
        directoryService.getCachePathFor(_) >> Optional.of(cacheDir)
        def cert = kalkanWrapper.read(KEY_CEO_REVOKED_2015, null, KEY_INDIVIDUAL_VALID_2015_PASSWORD).certificate
        def revokedAt = new Date(1_000_000)
        def first = Mock(X509CRLEntry) {
            getSerialNumber() >> BigInteger.ONE
            getRevocationDate() >> revokedAt
        }
        def second = Mock(X509CRLEntry) {
            getSerialNumber() >> BigInteger.ONE
            getRevocationDate() >> new Date(2_000_000)
        }
        def ambiguous = Mock(X509CRL) {
            getIssuerX500Principal() >> new X500Principal("CN=Test CA")
            getRevokedCertificates() >> ([first, second] as Set)
            getRevokedCertificate(_ as X509Certificate) >> first
        }
        def fallback = new CrlService(directoryService, crlConfiguration, client, taskScheduler, CrlService.CRL_DEFAULT) {
            @Override
            X509CRL loadCrl(File file) {
                return ambiguous
            }
        }

        when:
        def status = fallback.verify(cert)

        then:
        status.result == CrlResult.REVOKED
        status.file == 'nca.crl'
        status.revocationDate == revokedAt
        status.reason == ''
    }

    private File ownCrlFile(URL url) {
        new File(cacheDir, Util.sha1(url.toString()) + '.crl')
    }

    private void staleCacheConfiguration(URL url) {
        crlConfiguration.isEnabled() >> true
        crlConfiguration.getTtl() >> 10
        crlConfiguration.getUrlList() >> [(Util.sha1(url.toString())): url]
        directoryService.getCachePathFor(_) >> Optional.of(cacheDir)
    }

    def "updateCache does not re-download an actual CRL file"() {
        given:
        def url = new URL('http://example.test/nca.crl')
        def crlFile = ownCrlFile(url)
        crlFile.bytes = crlBytes('nca_rsa_test.crl')
        staleCacheConfiguration(url)

        when:
        service.updateCache(false, crlConfiguration, 'crl/full')

        then:
        0 * client.execute(_)
        crlFile.bytes == crlBytes('nca_rsa_test.crl')
    }

    def "updateCache replaces a stale CRL file with the downloaded one"() {
        given:
        def url = new URL('http://example.test/nca.crl')
        def crlFile = ownCrlFile(url)
        crlFile.text = 'stale'
        crlFile.setLastModified(0L)
        staleCacheConfiguration(url)
        client.execute(_) >> httpResponse(200, crlBytes('nca_rsa_test.crl'))

        when:
        service.updateCache(false, crlConfiguration, 'crl/full')

        then:
        crlFile.bytes == crlBytes('nca_rsa_test.crl')
        cacheDir.list() as List == [crlFile.name]
    }

    def "updateCache keeps the previous CRL file when the download fails"() {
        given:
        def url = new URL('http://example.test/nca.crl')
        def crlFile = ownCrlFile(url)
        crlFile.bytes = crlBytes('nca_gost2022_test.crl')
        crlFile.setLastModified(0L)
        staleCacheConfiguration(url)
        client.execute(_) >> httpResponse(500, null)
        def cert = kalkanWrapper.read(KEY_CEO_REVOKED_2015, null, KEY_INDIVIDUAL_VALID_2015_PASSWORD).certificate

        when:
        service.updateCache(false, crlConfiguration, 'crl/full')

        then: "без CRL проверка отвечала бы ACTIVE на отозванный сертификат"
        crlFile.bytes == crlBytes('nca_gost2022_test.crl')
        service.verify(cert).result == CrlResult.REVOKED
    }

    @Timeout(10)
    def "updateCache does not lock the cache directory and hide the previous CRL while downloading"() {
        given: "актуальный CRL устарел, а сервер отдаёт новый с паузой посреди передачи"
        def url = new URL('http://example.test/nca.crl')
        def crlFile = ownCrlFile(url)
        crlFile.bytes = crlBytes('nca_gost2022_test.crl')
        crlFile.setLastModified(0L)
        staleCacheConfiguration(url)

        def body = crlBytes('nca_rsa_test.crl')
        def transferStalled = new CountDownLatch(1)
        def releaseTransfer = new CountDownLatch(1)
        def stalledStream = new InputStream() {
            int position = 0

            @Override
            int read() {
                def single = new byte[1]
                return read(single, 0, 1) == -1 ? -1 : (single[0] & 0xff)
            }

            @Override
            int read(byte[] buffer, int offset, int length) {
                if (position < 100) {
                    int count = Math.min(length, 100 - position)
                    System.arraycopy(body, position, buffer, offset, count)
                    position += count
                    return count
                }

                transferStalled.countDown()
                releaseTransfer.await(10, TimeUnit.SECONDS)
                throw new IOException('connection reset')
            }
        }
        def statusLine = Mock(StatusLine) { getStatusCode() >> 200 }
        client.execute(_) >> Mock(CloseableHttpResponse) {
            getStatusLine() >> statusLine
            getEntity() >> new InputStreamEntity(stalledStream, -1)
        }
        def cert = kalkanWrapper.read(KEY_CEO_REVOKED_2015, null, KEY_INDIVIDUAL_VALID_2015_PASSWORD).certificate

        when:
        def update = Thread.start { service.updateCache(false, crlConfiguration, 'crl/full') }
        transferStalled.await(5, TimeUnit.SECONDS)

        def lockAcquired = new CountDownLatch(1)
        Thread.start { synchronized (directoryService) { lockAcquired.countDown() } }
        def lockedDuringDownload = !lockAcquired.await(2, TimeUnit.SECONDS)
        def filesDuringDownload = service.getCrlFiles('crl/full')*.name
        def statusDuringDownload = service.verify(cert).result

        releaseTransfer.countDown()
        update.join()

        then: "CaService.getRootCertificates берёт ту же блокировку и не должен ждать скачивания"
        !lockedDuringDownload

        and: "недокачанный файл не виден, работает прежний CRL"
        filesDuringDownload == [crlFile.name]
        statusDuringDownload == CrlResult.REVOKED

        and: "после обрыва передачи прежний CRL на месте, временный файл удалён"
        crlFile.bytes == crlBytes('nca_gost2022_test.crl')
        cacheDir.list() as List == [crlFile.name]

        cleanup:
        releaseTransfer.countDown()
    }
}

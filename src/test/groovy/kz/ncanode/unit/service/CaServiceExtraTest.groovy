package kz.ncanode.unit.service

import kz.ncanode.common.WithTestData
import kz.ncanode.configuration.CaConfiguration
import kz.ncanode.dto.crl.CrlResult
import kz.ncanode.dto.crl.CrlStatus
import kz.ncanode.exception.CaException
import kz.ncanode.service.CaService
import kz.ncanode.service.CrlService
import kz.ncanode.service.DirectoryService
import kz.ncanode.wrapper.CertificateWrapper
import kz.ncanode.wrapper.KalkanWrapper
import org.apache.http.StatusLine
import org.apache.http.client.methods.CloseableHttpResponse
import org.apache.http.entity.ByteArrayEntity
import org.apache.http.impl.client.CloseableHttpClient
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.mock.mockito.SpyBean
import org.springframework.context.ApplicationContext
import org.springframework.util.ResourceUtils
import spock.lang.Specification

import static org.mockito.Mockito.doReturn

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class CaServiceExtraTest extends Specification implements WithTestData {

    @Autowired
    KalkanWrapper kalkanWrapper

    @SpyBean
    CaService caService

    ApplicationContext applicationContext = Mock()
    CaConfiguration caConfiguration = Mock()
    CloseableHttpClient client = Mock()
    DirectoryService directoryService = Mock()
    CrlService caCrlService = Mock()

    private CaService standalone() {
        new CaService(applicationContext, caConfiguration, client, directoryService, caCrlService)
    }

    private CloseableHttpResponse httpResponse(int status, byte[] body) {
        def statusLine = Mock(StatusLine) { getStatusCode() >> status }
        Mock(CloseableHttpResponse) {
            getStatusLine() >> statusLine
            getEntity() >> (body == null ? null : new ByteArrayEntity(body))
        }
    }

    private static byte[] rootBytes() {
        ResourceUtils.getFile('classpath:ca/nca_gost2015_test.cer').bytes
    }

    def "download writes the response body to the file"() {
        given:
        def service = standalone()
        def out = File.createTempFile('cacert', '.cer')
        client.execute(_) >> httpResponse(200, rootBytes())

        when:
        service.download(new URL('http://root.test/root.cer'), out)

        then:
        out.length() == rootBytes().length

        cleanup:
        out.delete()
    }

    def "download throws CaException on a non-200 response"() {
        given:
        def service = standalone()
        client.execute(_) >> httpResponse(404, null)

        when:
        service.download(new URL('http://root.test/root.cer'), File.createTempFile('cacert', '.cer'))

        then:
        thrown(CaException)
    }

    def "download throws CaException on an empty entity"() {
        given:
        def service = standalone()
        client.execute(_) >> httpResponse(200, null)

        when:
        service.download(new URL('http://root.test/root.cer'), File.createTempFile('cacert', '.cer'))

        then:
        thrown(CaException)
    }

    def "downloadCert returns a CertificateWrapper on success"() {
        given:
        def service = standalone()
        def out = File.createTempFile('cacert', '.cer')
        client.execute(_) >> httpResponse(200, rootBytes())

        expect:
        service.downloadCert(new URL('http://root.test/root.cer'), out) != null

        cleanup:
        out.delete()
    }

    def "downloadCert returns null when the download fails"() {
        given:
        def service = standalone()
        client.execute(_) >> httpResponse(500, null)

        expect:
        service.downloadCert(new URL('http://root.test/root.cer'), File.createTempFile('cacert', '.cer')) == null
    }

    def "buildChain walks from the leaf up to the self-signed root"() {
        given:
        def root = CertificateWrapper.fromFile(ResourceUtils.getFile('classpath:ca/nca_gost2015_test.cer')).get()
        doReturn([root]).when(caService).getRootCertificates()
        def leaf = kalkanWrapper.read(KEY_INDIVIDUAL_VALID_2015, null, KEY_INDIVIDUAL_VALID_2015_PASSWORD).certificate

        when:
        def chain = caService.buildChain(leaf)

        then:
        chain.size() == 2
        chain[0] == leaf
        chain[1] == root
    }

    def "buildChain returns just the leaf when no issuer is known"() {
        given:
        doReturn([]).when(caService).getRootCertificates()
        def leaf = kalkanWrapper.read(KEY_INDIVIDUAL_VALID_2015, null, KEY_INDIVIDUAL_VALID_2015_PASSWORD).certificate

        expect:
        caService.buildChain(leaf).size() == 1
    }

    def "getRootCertificateFor returns empty for a self-signed certificate"() {
        given:
        def root = CertificateWrapper.fromFile(ResourceUtils.getFile('classpath:ca/nca_gost2015_test.cer')).get()

        expect:
        caService.getRootCertificateFor(root).isEmpty()
    }

    def "updateCache(false) is a no-op when the CA feature is disabled"() {
        given:
        def service = standalone()
        caConfiguration.isEnabled() >> false

        when:
        service.updateCache()

        then:
        0 * caConfiguration.getUrlList()
    }

    def "updateCache downloads and caches a fresh CA certificate"() {
        given:
        def service = standalone()
        def dir = File.createTempDir()
        caConfiguration.isEnabled() >> true
        caConfiguration.getUrlList() >> ['root': new URL('http://root.test/root.cer')]
        directoryService.getCachePathFor('ca') >> Optional.of(dir)
        client.execute(_) >> httpResponse(200, rootBytes())
        caCrlService.verify(_) >> CrlStatus.builder().result(CrlResult.ACTIVE).build()

        when:
        service.updateCache(true)

        then:
        new File(dir, 'root.cer').exists()

        cleanup:
        dir.deleteDir()
    }

    def "updateCache reads an already cached CA certificate without downloading"() {
        given:
        def service = standalone()
        def dir = File.createTempDir()
        new File(dir, 'root.cer').bytes = rootBytes()
        caConfiguration.getUrlList() >> ['root': new URL('http://root.test/root.cer')]
        directoryService.getCachePathFor('ca') >> Optional.of(dir)
        caCrlService.verify(_) >> CrlStatus.builder().result(CrlResult.ACTIVE).build()

        when:
        service.updateCache(false)

        then:
        0 * client.execute(_)

        cleanup:
        dir.deleteDir()
    }
}

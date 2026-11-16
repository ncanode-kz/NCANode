package kz.ncanode.unit.configuration

import com.sun.net.httpserver.HttpServer
import io.micrometer.observation.ObservationRegistry
import kz.ncanode.configuration.HttpClientConfiguration
import org.apache.http.client.methods.HttpGet
import org.apache.http.conn.ConnectionPoolTimeoutException
import org.apache.http.impl.client.CloseableHttpClient
import spock.lang.Specification
import spock.lang.Timeout

import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class HttpClientConfigurationTest extends Specification {

    HttpServer server
    ExecutorService serverExecutor
    CountDownLatch requestReceived = new CountDownLatch(1)
    CountDownLatch releaseResponse = new CountDownLatch(1)

    def setup() {
        serverExecutor = Executors.newCachedThreadPool()
        server = HttpServer.create(new InetSocketAddress(InetAddress.getByName('127.0.0.1'), 0), 0)
        server.setExecutor(serverExecutor)
        server.createContext('/hanging') { exchange ->
            // «зависший» CRL/OCSP/TSP-сервер: принимает запрос и молчит
            requestReceived.countDown()
            releaseResponse.await(10, TimeUnit.SECONDS)
            exchange.sendResponseHeaders(200, -1)
            exchange.close()
        }
        server.start()
    }

    def cleanup() {
        releaseResponse.countDown()
        server.stop(0)
        serverExecutor.shutdownNow()
    }

    private CloseableHttpClient client(Map<String, Integer> settings) {
        def configuration = new HttpClientConfiguration()
        configuration.connectionTtl = 10
        settings.each { name, value -> configuration."$name" = value }

        return configuration.httpClient(ObservationRegistry.NOOP)
    }

    private String hangingUrl() {
        return "http://127.0.0.1:${server.address.port}/hanging"
    }

    @Timeout(5)
    def "check request to a hanging server fails by socket timeout instead of waiting forever"() {
        given:
        def httpClient = client(socketTimeout: 1)

        when:
        httpClient.execute(new HttpGet(hangingUrl()))

        then:
        thrown(SocketTimeoutException)

        cleanup:
        httpClient?.close()
    }

    @Timeout(5)
    def "check request waits for a free pooled connection no longer than connectionRequestTimeout"() {
        given: "пул на одно соединение к хосту, и оно занято зависшим запросом"
        def httpClient = client(maxConnectionsPerRoute: 1, connectionRequestTimeout: 1, socketTimeout: 5)
        def busyRequest = Thread.start {
            try {
                httpClient.execute(new HttpGet(hangingUrl())).close()
            } catch (IOException ignored) {
            }
        }
        requestReceived.await(3, TimeUnit.SECONDS)

        when:
        httpClient.execute(new HttpGet(hangingUrl()))

        then:
        thrown(ConnectionPoolTimeoutException)

        cleanup:
        releaseResponse.countDown()
        busyRequest?.join()
        httpClient?.close()
    }
}

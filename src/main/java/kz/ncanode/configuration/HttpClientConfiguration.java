package kz.ncanode.configuration;

import io.micrometer.observation.ObservationRegistry;
import kz.ncanode.dto.http.HttpProxyConfig;
import kz.ncanode.wrapper.TracedHttpRequestExecutor;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.client.LaxRedirectStrategy;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.concurrent.TimeUnit;

@Slf4j
@Configuration
@ConfigurationProperties(prefix = "ncanode.http-client")
@Getter
@Setter
public class HttpClientConfiguration {
    private HttpProxyConfig proxy;
    private Integer connectionTtl;

    /** Таймаут установки TCP-соединения, секунды */
    private Integer connectTimeout = 10;

    /** Таймаут ожидания данных от сервера (пауза между пакетами, а не время всего ответа), секунды */
    private Integer socketTimeout = 30;

    /** Таймаут ожидания свободного соединения из пула, секунды */
    private Integer connectionRequestTimeout = 10;

    /** Максимум соединений в пуле клиента */
    private Integer maxConnections = 50;

    /** Максимум соединений к одному хосту */
    private Integer maxConnectionsPerRoute = 20;

    private String userAgent = "NCANode/" + HttpClientConfiguration.class.getPackage().getImplementationVersion();

    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    @Bean
    public CloseableHttpClient httpClient(ObservationRegistry observationRegistry) {
        var customClient = HttpClients.custom();

        // исходящие CRL/OCSP/TSP/CA-запросы — отдельными CLIENT-span-ами внутри трейса запроса
        customClient.setRequestExecutor(new TracedHttpRequestExecutor(observationRegistry));

        if (proxy != null && proxy.getUrl() != null && !proxy.getUrl().isBlank()) {
            try {
                URL proxyUrl = new URL(proxy.getUrl());
                customClient.setProxy(new HttpHost(proxyUrl.getHost(), proxyUrl.getPort(), proxyUrl.getProtocol()));

                if (proxy.getUsername() != null && !proxy.getUsername().isBlank()) {
                    Credentials credentials = new UsernamePasswordCredentials(proxy.getUsername(), proxy.getPassword());
                    CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
                    credentialsProvider.setCredentials(new AuthScope(proxyUrl.getHost(), proxyUrl.getPort()), credentials);

                    customClient.setDefaultCredentialsProvider(credentialsProvider);
                }

            } catch (MalformedURLException e) {
                log.error(String.format("Invalid proxy url: %s", proxy), e);
            }
        }

        customClient.setConnectionTimeToLive(connectionTtl, TimeUnit.SECONDS);

        // без таймаутов запрос к зависшему CRL/OCSP/TSP-серверу держит поток бесконечно
        customClient.setDefaultRequestConfig(RequestConfig.custom()
            .setConnectTimeout(secondsToMillis(connectTimeout))
            .setSocketTimeout(secondsToMillis(socketTimeout))
            .setConnectionRequestTimeout(secondsToMillis(connectionRequestTimeout))
            .build());

        // по умолчанию в пуле Apache HttpClient всего 2 соединения на хост
        customClient.setMaxConnTotal(maxConnections);
        customClient.setMaxConnPerRoute(maxConnectionsPerRoute);

        customClient.setUserAgent(userAgent);
        customClient.setRedirectStrategy(new LaxRedirectStrategy());
        customClient.disableCookieManagement();

        return customClient.build();
    }

    private static int secondsToMillis(int seconds) {
        return (int) TimeUnit.SECONDS.toMillis(seconds);
    }
}

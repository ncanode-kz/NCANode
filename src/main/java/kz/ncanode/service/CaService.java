package kz.ncanode.service;

import kz.ncanode.annotation.Generated;
import kz.ncanode.configuration.CaConfiguration;
import kz.ncanode.dto.crl.CrlResult;
import kz.ncanode.exception.CaException;
import kz.ncanode.wrapper.CertificateWrapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ApplicationContext;
import org.springframework.retry.annotation.Retryable;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * Сервис для работы с центром сертификации
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class CaService {
    private final static int EXIT_CODE = 32;
    private final static String CA_CACHE_DIR_NAME = "ca";
    private final static String CA_FILE_EXTENSION = ".cer";

    private final ApplicationContext applicationContext;
    private final CaConfiguration caConfiguration;
    private final CloseableHttpClient client;
    private final DirectoryService directoryService;

    @Qualifier("caCrlService")
    private final CrlService caCrlService;

    private final List<CertificateWrapper> certificates = new ArrayList<>();

    @Retryable(value = CaException.class)
    @Scheduled(fixedRateString = "${ncanode.ca.ttl}", initialDelay = 0, timeUnit = TimeUnit.MINUTES)
    public void updateCache() {
        if (!caConfiguration.isEnabled()) {
            return;
        }

        updateCache(false);
    }

    public void updateCache(boolean force) {
        synchronized (directoryService) {
            synchronized (certificates) {
                certificates.clear();

                var urls = caConfiguration.getUrlList();

                if (urls.isEmpty()) {
                    log.error("CA certificates urls is empty. Please set NCANODE_CA_URL environment variable.");
                    shutdown();
                }

                log.info("Updating CA certificates cache...");

                for (var urlEntry : urls.entrySet()) {
                    File caFile = new File(directoryService.getCachePathFor(CA_CACHE_DIR_NAME).orElseThrow(), urlEntry.getKey() + CA_FILE_EXTENSION);
                    CertificateWrapper cert;

                    if (force || !caFile.exists() || !caFile.canRead()) {
                        cert = downloadCert(urlEntry.getValue(), caFile);
                    } else {
                        cert = CertificateWrapper.fromFile(caFile).orElseThrow();
                    }

                    checkCertForNull(urlEntry, cert, caFile);

                    if (!cert.isDateValid() || caCrlService.verify(cert).getResult() == CrlResult.REVOKED) {
                        downloadCert(urlEntry.getValue(), caFile);
                        cert = downloadCert(urlEntry.getValue(), caFile);
                    }

                    checkCertForNull(urlEntry, cert, caFile);
                }
            }
        }
    }

    public CertificateWrapper downloadCert(URL url, File file) {
        try {
            log.info("Downloading CA file: {}", url.toString());
            download(url, file);
            log.info("Download complete");
            return CertificateWrapper.fromFile(file).orElse(null);
        } catch (CaException e) {
            log.error(e.getMessage());
            return null;
        }
    }

    /**
     * Возвращает доверенный корневой сертификат для сертификата ЭЦП
     *
     * @param cert Сертификат из ЭЦП
     * @return Сертификат Удостоверяющего центра, либо ничего
     */
    public Optional<CertificateWrapper> getRootCertificateFor(CertificateWrapper cert) {
        if (cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal())) {
            return Optional.empty();
        }

        return getRootCertificates().stream()
            .filter(root -> cert.getIssuerX500Principal().equals(root.getSubjectX500Principal()) && cert.verify(root.getPublicKey()))
            .findFirst();
    }

    /**
     * Строит цепочку сертификатов от конечного до корневого, используя кэш УЦ.
     * Первый элемент — переданный сертификат, последний — самоподписанный корень (если найден).
     *
     * @param leaf конечный сертификат
     * @return цепочка (минимум сам {@code leaf})
     */
    public List<CertificateWrapper> buildChain(CertificateWrapper leaf) {
        final List<CertificateWrapper> chain = new ArrayList<>();
        chain.add(leaf);

        final Set<String> visited = new HashSet<>();
        CertificateWrapper current = leaf;

        while (!current.getIssuerX500Principal().equals(current.getSubjectX500Principal())
            && visited.add(current.getSubjectX500Principal().getName())) {

            final CertificateWrapper node = current;
            final CertificateWrapper issuer = getRootCertificates().stream()
                .filter(ca -> ca.getSubjectX500Principal().equals(node.getIssuerX500Principal())
                    && node.verify(ca.getPublicKey()))
                .findFirst()
                .orElse(null);

            if (issuer == null) {
                break;
            }

            chain.add(issuer);
            current = issuer;
        }

        return chain;
    }

    /**
     * Прогрет ли кэш УЦ: сертификаты скачаны и читаются (или фича выключена).
     */
    public boolean isCacheReady() {
        if (!caConfiguration.isEnabled()) {
            return true;
        }

        try {
            return !getRootCertificates().isEmpty();
        } catch (RuntimeException e) {
            return false;
        }
    }

    public List<CertificateWrapper> getRootCertificates() {
        synchronized (directoryService) {
            synchronized (certificates) {
                List<CertificateWrapper> certs;

                if (!certificates.isEmpty()) {
                    certs = certificates;
                } else {
                    certs = Arrays.stream(Objects.requireNonNull(directoryService.getCachePathFor(CA_CACHE_DIR_NAME).orElseThrow().listFiles()))
                        .filter(f -> f.isFile() && f.canRead() && f.getName().endsWith(CA_FILE_EXTENSION))
                        .map(CertificateWrapper::fromFile)
                        .map(Optional::orElseThrow)
                        .toList();

                    certificates.addAll(certs);
                }

                return certs;
            }
        }
    }

    public void download(URL url, File file) {
        try (CloseableHttpResponse response = client.execute(new HttpGet(url.toString()))) {
            if (response.getStatusLine().getStatusCode() != HttpStatus.SC_OK) {
                throw new CaException(String.format("Cannot download file: %s", url));
            }

            HttpEntity entity = response.getEntity();

            if (entity == null) {
                throw new CaException(String.format("Got empty request from: %s", url));
            }

            try(FileOutputStream out = new FileOutputStream(file)) {
                entity.writeTo(out);
            }
        } catch (IOException e) {
            throw new CaException(String.format("Cannot download file: %s", url), e);
        }
    }

    @Generated // недостижимо в тестах: завершает процесс
    private void shutdown() {
        SpringApplication.exit(applicationContext, () -> EXIT_CODE);
        System.exit(EXIT_CODE);
    }

    @Generated // ветка null ведёт к shutdown() — недостижимо в тестах
    private void checkCertForNull(final Map.Entry<String, URL> urlEntry, final CertificateWrapper cert, final File caFile) {
        if (cert == null) {
            log.error("Cannot open CA certificate from: '{}'. File name: {}", urlEntry.getValue().toString(), caFile.getAbsolutePath());
            shutdown();
            return;
        }
    }
}

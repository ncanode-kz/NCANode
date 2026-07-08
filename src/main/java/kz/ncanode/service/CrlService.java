package kz.ncanode.service;

import kz.ncanode.configuration.crl.CrlConfiguration;
import kz.ncanode.dto.crl.CrlResult;
import kz.ncanode.dto.crl.CrlStatus;
import kz.ncanode.exception.CrlException;
import kz.ncanode.exception.ServerException;
import kz.ncanode.util.Util;
import kz.ncanode.wrapper.CertificateWrapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.scheduling.support.PeriodicTrigger;

import jakarta.annotation.PostConstruct;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Path;
import java.security.cert.*;
import java.time.Duration;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Сервис для реализоции механизма проверки сертификатов в CRL
 */
@Slf4j
@RequiredArgsConstructor
public class CrlService {
    public final static String CRL_DEFAULT = "default";
    public final static String CRL_CA      = "ca-crl";
    private final static String CRL_CACHE_FULL_DIR_NAME = "crl/full";
    private final static String CRL_CACHE_DELTA_DIR_NAME = "crl/delta";
    private final static String CRL_FILE_EXTENSION = ".crl";

    private final DirectoryService directoryService;
    private final CrlConfiguration crlConfiguration;
    private final CloseableHttpClient client;
    private final TaskScheduler taskScheduler;
    private final String crlServiceType;

    @PostConstruct
    private void initializeScheduler() {
        if (crlConfiguration.getTtl() == null || crlConfiguration.getTtl() < 1) {
            return;
        }

        log.info("Initializing '{}' CRL Service...", crlServiceType);
        val periodicTrigger = new PeriodicTrigger(Duration.ofMinutes(crlConfiguration.getTtl()));
        periodicTrigger.setInitialDelay(Duration.ZERO);
        periodicTrigger.setFixedRate(true);
        taskScheduler.schedule(() -> updateCache(false, crlConfiguration, CRL_CACHE_FULL_DIR_NAME), periodicTrigger);
    }

    @PostConstruct
    private void initializeDeltaScheduler() {
        if (crlConfiguration.getDelta().getTtl() == null || crlConfiguration.getDelta().getTtl() < 1) {
            return;
        }

        log.info("Initializing '{}' CRL Delta Service...", crlServiceType);
        val periodicTrigger = new PeriodicTrigger(Duration.ofMinutes(crlConfiguration.getDelta().getTtl()));
        periodicTrigger.setInitialDelay(Duration.ZERO);
        periodicTrigger.setFixedRate(true);
        taskScheduler.schedule(() -> updateCache(false, crlConfiguration.getDelta(), CRL_CACHE_DELTA_DIR_NAME), periodicTrigger);
    }

    /**
     * Проверка сертификата в CRL
     *
     * @param cert Сертификат
     * @return Статус проверки
     */
    public CrlStatus verify(CertificateWrapper cert) {
        if (!crlConfiguration.isEnabled()) {
            return CrlStatus.builder()
                .result(CrlResult.ACTIVE)
                .build();
        }

        for (final String cacheDirectory : List.of(CRL_CACHE_DELTA_DIR_NAME, CRL_CACHE_FULL_DIR_NAME)) {
            // Проверяем в CRL
            for (File crlFile : getCrlFiles(cacheDirectory)) {
                X509CRL crl = loadCrl(crlFile);

                if (crl.isRevoked(cert.getX509Certificate())) {
                    return Optional.ofNullable(crl.getRevokedCertificate(cert.getX509Certificate()))
                        .map( entry -> CrlStatus.builder()
                            .result(CrlResult.REVOKED)
                            .file(crlFile.getName())
                            .revocationDate(entry.getRevocationDate())
                            .reason(Optional.ofNullable(entry.getRevocationReason()).map(CRLReason::toString).orElse(""))
                            .build()
                        ).orElse(CrlStatus.builder()
                            .result(CrlResult.REVOKED)
                            .build()
                        );
                }
            }
        }

        return CrlStatus.builder()
            .result(CrlResult.ACTIVE)
            .build();
    }

    /**
     * Обновляет кэш CRL
     *
     * @param force Если true, то кэш будет обновлен в любом случае
     */
    public synchronized void updateCache(boolean force, CrlConfiguration crlConfiguration, String cacheDirectory) {
        synchronized (directoryService) {
            if (!crlConfiguration.isEnabled() || crlConfiguration.getTtl() <= 0) {
                return;
            }

            log.info("Updating CRL cache...");
            long currentTime = System.currentTimeMillis();

            // Удаляем старые файлы CRL
            for (var crlFile : getCrlFiles(cacheDirectory)) {
                if (!force && crlFile.exists() && crlFile.isFile() && crlFile.canRead() && (currentTime - crlFile.lastModified()) <= (long) crlConfiguration.getTtl() * 60000L) {
                    log.debug("CRL file {} is actual. This file will not be removed", crlFile);
                    continue;
                }

                if (!crlFile.delete()) {
                    log.error("Cannot delete CRL cache file: {}", crlFile);
                }
            }

            int updatedCount = 0;

            // Скачиваем новые CRL файлы
            for (var crlEntry : crlConfiguration.getUrlList().entrySet()) {
                var crlFile = new File(directoryService.getCachePathFor(cacheDirectory).orElseThrow(), crlEntry.getKey() + CRL_FILE_EXTENSION);

                if (crlFile.exists()) {
                    continue;
                }

                downloadCrl(cacheDirectory, crlEntry.getValue());
                updatedCount++;
            }

            if (updatedCount == 0) {
                log.info("Nothing to update in CRL cache.");
            } else {
                log.info("{} files updated in CRL cache", updatedCount);
            }
        }
    }


    /**
     * Загружает CRL файл
     *
     * @param file
     * @return
     */
    public X509CRL loadCrl(File file) {
        try (FileInputStream in = new FileInputStream(file)) {
            return (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(in);
        } catch (IOException | CRLException | CertificateException e) {
            log.error("Cannot load CRL file \"{}\"", file, e);
            throw new ServerException(String.format("Cannot load CRL file \"%s\"", file.getName()), e);
        }
    }

    /**
     * Скачивает CRL файл в директорию
     *
     * @param cacheDirName
     * @param url
     */
    public void downloadCrl(String cacheDirName, URL url) {
        try {
            String crlUrl = url.toString();
            String crlFileName = Util.sha1(crlUrl) + CRL_FILE_EXTENSION;

            log.info("Downloading CRL file from: {}", crlUrl);
            final File downloadedFile = download(crlUrl, getCrlCacheFilePathFor(cacheDirName, crlFileName).toPath());
            log.info("CRL file \"{}\" successfully downloaded. Size: {} bytes", crlFileName, downloadedFile.length());
        } catch (CrlException e) {
            log.error("CRL File download failure", e.getCause());
        }
    }

    /**
     * Возвращает список CRL файлов в указанной директории
     *
     * @param cacheDirName
     * @return
     */
    public List<File> getCrlFiles(String cacheDirName) {
        return Arrays.stream(Objects.requireNonNull(directoryService.getCachePathFor(cacheDirName).orElseThrow().listFiles()))
            .filter(file -> file.isFile() && file.canRead() && file.getName().endsWith(CRL_FILE_EXTENSION))
            .toList();
    }

    private File download(String url, Path path) throws CrlException {
        try(CloseableHttpResponse response = client.execute(new HttpGet(url))) {
            int status = response.getStatusLine().getStatusCode();

            if (status != HttpStatus.OK.value()) {
                throw new CrlException(String.format("Cannot download file from: %s. Got HTTP status: %d", url, status));
            }

            HttpEntity entity = response.getEntity();

            if (entity == null) {
                throw new CrlException(String.format("Got empty request from: %s", url));
            }

            var file = path.toFile();

            try(FileOutputStream out = new FileOutputStream(file)) {
                entity.writeTo(out);
            }

            return file;
        } catch (IOException e) {
            throw new CrlException(e.getMessage(), e);
        }
    }

    private File getCrlCacheFilePathFor(String cacheDirName, String fileName) {
        return new File(directoryService.getCachePathFor(cacheDirName).orElseThrow(), fileName);
    }
}

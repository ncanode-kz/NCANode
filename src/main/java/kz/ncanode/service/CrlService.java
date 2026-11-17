package kz.ncanode.service;

import io.micrometer.observation.annotation.Observed;
import kz.ncanode.configuration.crl.CrlConfiguration;
import kz.ncanode.dto.crl.CrlResult;
import kz.ncanode.dto.crl.CrlStatus;
import kz.ncanode.exception.CrlException;
import kz.ncanode.exception.ServerException;
import kz.ncanode.util.Util;
import kz.ncanode.wrapper.CertificateWrapper;
import kz.ncanode.wrapper.CrlWrapper;
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
import java.io.IOException;
import java.io.OutputStream;
import java.net.URL;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.cert.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
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
    private final static String CRL_TEMP_FILE_EXTENSION = ".part";

    private final DirectoryService directoryService;
    private final CrlConfiguration crlConfiguration;
    private final CloseableHttpClient client;
    private final TaskScheduler taskScheduler;
    private final String crlServiceType;

    private final Map<CrlFileKey, Optional<CrlWrapper>> crlIndexes = new ConcurrentHashMap<>();

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
     * Прогрет ли кэш CRL: хотя бы один full-CRL скачан (или фича/расписание выключены).
     */
    public boolean isCacheReady() {
        if (!crlConfiguration.isEnabled() || crlConfiguration.getTtl() == null || crlConfiguration.getTtl() < 1) {
            return true;
        }

        try {
            return !getCrlFiles(CRL_CACHE_FULL_DIR_NAME).isEmpty();
        } catch (RuntimeException e) {
            return false;
        }
    }

    /**
     * Проверка сертификата в CRL
     *
     * @param cert Сертификат
     * @return Статус проверки
     */
    @Observed(name = "ncanode.crl", contextualName = "crl verify")
    public CrlStatus verify(CertificateWrapper cert) {
        if (!crlConfiguration.isEnabled()) {
            return CrlStatus.builder()
                .result(CrlResult.ACTIVE)
                .build();
        }

        for (final String cacheDirectory : List.of(CRL_CACHE_DELTA_DIR_NAME, CRL_CACHE_FULL_DIR_NAME)) {
            List<File> crlFiles = getCrlFiles(cacheDirectory);
            forgetRemovedCrlFiles(cacheDirectory, crlFiles);

            // Проверяем в CRL
            for (File crlFile : crlFiles) {
                Optional<CrlWrapper.RevokedEntry> revoked = findRevokedEntry(cacheDirectory, crlFile, cert);

                if (revoked.isPresent()) {
                    return CrlStatus.builder()
                        .result(CrlResult.REVOKED)
                        .file(crlFile.getName())
                        .revocationDate(revoked.get().revocationDate())
                        .reason(Optional.ofNullable(revoked.get().revocationReason()).map(CRLReason::toString).orElse(""))
                        .build();
                }
            }
        }

        return CrlStatus.builder()
            .result(CrlResult.ACTIVE)
            .build();
    }

    /**
     * Ищет сертификат в CRL-файле через индекс. Индекс строится один раз на версию файла:
     * при замене файла меняются время изменения и размер, и индекс строится заново
     *
     * @param cacheDirectory Каталог кэша
     * @param crlFile Файл CRL
     * @param cert Сертификат
     * @return Запись об отзыве, либо ничего
     */
    private Optional<CrlWrapper.RevokedEntry> findRevokedEntry(String cacheDirectory, File crlFile, CertificateWrapper cert) {
        Optional<CrlWrapper> index = crlIndexes.computeIfAbsent(crlFileKey(cacheDirectory, crlFile), key -> CrlWrapper.fromX509Crl(loadCrl(crlFile)));

        if (index.isPresent()) {
            return index.get().getRevokedEntry(cert.getX509Certificate());
        }

        // индекс не построить из-за повторяющихся записей — точный ответ даёт только сам X509CRL
        return Optional.ofNullable(loadCrl(crlFile).getRevokedCertificate(cert.getX509Certificate()))
            .map(entry -> new CrlWrapper.RevokedEntry(entry.getRevocationDate(), entry.getRevocationReason()));
    }

    /**
     * Удаляет индексы файлов, которых больше нет в каталоге кэша
     *
     * @param cacheDirectory Каталог кэша
     * @param crlFiles Файлы CRL, которые сейчас лежат в каталоге
     */
    private void forgetRemovedCrlFiles(String cacheDirectory, List<File> crlFiles) {
        Set<CrlFileKey> actual = new HashSet<>();

        for (File crlFile : crlFiles) {
            actual.add(crlFileKey(cacheDirectory, crlFile));
        }

        crlIndexes.keySet().removeIf(key -> key.cacheDirectory().equals(cacheDirectory) && !actual.contains(key));
    }

    private static CrlFileKey crlFileKey(String cacheDirectory, File crlFile) {
        return new CrlFileKey(cacheDirectory, crlFile.getName(), crlFile.lastModified(), crlFile.length());
    }

    private record CrlFileKey(String cacheDirectory, String fileName, long lastModified, long size) {
    }

    /**
     * Возвращает DER-кодированные CRL из кэша (full + delta), покрывающие переданный сертификат
     * (издатель CRL совпадает с издателем сертификата). Для вшивания в XAdES-LT.
     *
     * @param certificate сертификат, для которого нужны CRL
     * @return список DER-кодированных CRL (может быть пустым)
     */
    @Observed(name = "ncanode.crl", contextualName = "crl fetch")
    public List<byte[]> getEncodedCrlsFor(X509Certificate certificate) {
        final List<byte[]> result = new ArrayList<>();

        for (final String cacheDirectory : List.of(CRL_CACHE_FULL_DIR_NAME, CRL_CACHE_DELTA_DIR_NAME)) {
            for (final File crlFile : getCrlFiles(cacheDirectory)) {
                final X509CRL crl = loadCrl(crlFile);

                if (!crl.getIssuerX500Principal().equals(certificate.getIssuerX500Principal())) {
                    continue;
                }

                try {
                    result.add(crl.getEncoded());
                } catch (CRLException e) {
                    log.warn("Cannot encode CRL file {}: {}", crlFile.getName(), e.getMessage());
                }
            }
        }

        return result;
    }

    /**
     * Обновляет кэш CRL
     *
     * <p>Сетевые запросы идут без блокировки {@code directoryService}: её же берёт
     * {@code CaService.getRootCertificates}, и на время скачивания большого CRL вставали бы все проверки.
     * Актуальный файл не удаляется до скачивания: новый CRL пишется во временный файл и атомарно
     * подменяет старый, поэтому при ошибке скачивания продолжает работать прежний CRL.
     *
     * @param force Если true, то кэш будет обновлен в любом случае
     */
    public synchronized void updateCache(boolean force, CrlConfiguration crlConfiguration, String cacheDirectory) {
        if (!crlConfiguration.isEnabled() || crlConfiguration.getTtl() <= 0) {
            return;
        }

        log.info("Updating CRL cache...");
        final long currentTime = System.currentTimeMillis();
        final long ttlMillis = (long) crlConfiguration.getTtl() * 60000L;
        final Map<String, URL> urls = crlConfiguration.getUrlList();
        final Set<String> ownFileNames = new HashSet<>();

        int updatedCount = 0;

        // Скачиваем отсутствующие и устаревшие CRL файлы
        for (var crlEntry : urls.entrySet()) {
            final String crlFileName = crlEntry.getKey() + CRL_FILE_EXTENSION;
            final File crlFile = getCrlCacheFilePathFor(cacheDirectory, crlFileName);
            ownFileNames.add(crlFileName);

            if (!force && isActual(crlFile, currentTime, ttlMillis)) {
                log.debug("CRL file {} is actual", crlFile);
                continue;
            }

            if (refreshCrl(cacheDirectory, crlEntry.getValue())) {
                updatedCount++;
            }
        }

        // Удаляем устаревшие файлы, которые этот сервис не обновляет (например, URL убран из настроек)
        for (var crlFile : getCrlFiles(cacheDirectory)) {
            if (ownFileNames.contains(crlFile.getName()) || isActual(crlFile, currentTime, ttlMillis)) {
                continue;
            }

            if (!crlFile.delete()) {
                log.error("Cannot delete CRL cache file: {}", crlFile);
            } else {
                forgetCrlFile(cacheDirectory, crlFile.getName());
            }
        }

        if (updatedCount == 0) {
            log.info("Nothing to update in CRL cache.");
        } else {
            log.info("{} files updated in CRL cache", updatedCount);
        }
    }

    private static boolean isActual(File crlFile, long currentTime, long ttlMillis) {
        return crlFile.isFile() && crlFile.canRead() && (currentTime - crlFile.lastModified()) <= ttlMillis;
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
        refreshCrl(cacheDirName, url);
    }

    /**
     * Скачивает CRL файл и подменяет им файл в кэше
     *
     * @return true, если файл скачан и подменён
     */
    private boolean refreshCrl(String cacheDirName, URL url) {
        try {
            String crlUrl = url.toString();
            String crlFileName = Util.sha1(crlUrl) + CRL_FILE_EXTENSION;

            log.info("Downloading CRL file from: {}", crlUrl);
            final File downloadedFile = download(crlUrl, getCrlCacheFilePathFor(cacheDirName, crlFileName).toPath());
            forgetCrlFile(cacheDirName, crlFileName);
            log.info("CRL file \"{}\" successfully downloaded. Size: {} bytes", crlFileName, downloadedFile.length());
            return true;
        } catch (CrlException e) {
            log.error("CRL File download failure", e.getCause());
            return false;
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

    /**
     * Скачивает файл во временный файл рядом с целевым и атомарно подменяет им целевой.
     * Временный файл не имеет расширения {@code .crl}, поэтому недокачанный CRL не виден {@link #getCrlFiles}
     */
    private File download(String url, Path path) throws CrlException {
        Path tempFile = null;

        try (CloseableHttpResponse response = client.execute(new HttpGet(url))) {
            int status = response.getStatusLine().getStatusCode();

            if (status != HttpStatus.OK.value()) {
                throw new CrlException(String.format("Cannot download file from: %s. Got HTTP status: %d", url, status));
            }

            HttpEntity entity = response.getEntity();

            if (entity == null) {
                throw new CrlException(String.format("Got empty request from: %s", url));
            }

            tempFile = Files.createTempFile(path.getParent(), path.getFileName().toString() + ".", CRL_TEMP_FILE_EXTENSION);

            try (OutputStream out = Files.newOutputStream(tempFile)) {
                Util.copyEntityBounded(entity, out, Util.MAX_CRL_DOWNLOAD_BYTES);
            }

            replaceFile(tempFile, path);
            tempFile = null;

            return path.toFile();
        } catch (IOException e) {
            throw new CrlException(e.getMessage(), e);
        } finally {
            if (tempFile != null) {
                try {
                    Files.deleteIfExists(tempFile); // не оставляем недокачанный CRL в кэше
                } catch (IOException e) {
                    log.warn("Cannot delete temporary CRL file {}", tempFile, e);
                }
            }
        }
    }

    private static void replaceFile(Path source, Path target) throws IOException {
        try {
            Files.move(source, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private File getCrlCacheFilePathFor(String cacheDirName, String fileName) {
        return new File(directoryService.getCachePathFor(cacheDirName).orElseThrow(), fileName);
    }

    private void forgetCrlFile(String cacheDirectory, String fileName) {
        crlIndexes.keySet().removeIf(key -> key.cacheDirectory().equals(cacheDirectory) && key.fileName().equals(fileName));
    }
}

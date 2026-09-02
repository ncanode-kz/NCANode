# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## About

NCANode — сервер (Spring Boot 3.5, Java 25, Gradle 9) для работы с ЭЦП Республики Казахстан: подпись и проверка XML (xmldsig), CMS, PDF, WSSE (SmartBridge), JWT, проверка сертификатов через OCSP/CRL, TSP-метки. REST API на JSON, порт по умолчанию 14579.

## Build & Run

Требуются проприетарные библиотеки KalkanCrypt (`knca_provider_jce_kalkan-*.jar`, `kalkancrypt-xmldsig-*.jar`) в директории `lib/` — Gradle подключает их через flatDir-репозиторий. Без них проект не соберётся; их можно запросить на https://pki.gov.kz/developers/.

```bash
./gradlew bootRun            # запуск без сборки
./gradlew bootJar            # сборка jar -> build/libs/NCANode.jar
./gradlew bootWar            # сборка war
```

Проверка после запуска: http://localhost:14579/actuator/health, Swagger UI: `/swagger-ui/`.

Вся конфигурация — через переменные окружения `NCANODE_*` (см. `src/main/resources/application.yml`): порт, URL-ы CRL/OCSP/TSP/CA, прокси, каталог кэша (`NCANODE_CACHE_DIR`, по умолчанию `./cache`), `NCANODE_DEBUG` для детальных ошибок.

## Tests

Тесты написаны на Spock (Groovy), лежат в `src/test/groovy`:

```bash
./gradlew test                                                    # все тесты
./gradlew test --tests 'kz.ncanode.unit.service.CmsServiceTest'   # один класс
./gradlew test --tests '*CmsServiceTest' --tests '*XmlServiceTest'
./gradlew check                                                   # тесты + jacoco-отчёт
```

- `unit/` — юнит-тесты сервисов и wrapper'ов.
- `integration/` — тесты контроллеров через standalone MockMvc; базовый класс `common/IntegrationSpecification.groovy` (метод `doPostQuery`), тестовые ключи/данные — в `common/WithTestData.groovy` и `src/test/resources` (ca, certs, crl, ocsp, tsp).

`check` зависит от `jacocoTestReport`; из покрытия исключены dto, configuration, constants, exception, util.

## Architecture

Слои: **controller → service → wrapper**.

- `controller/` — REST-контроллеры, по одному на область API: `xml`, `cms`, `pdf`, `wsse`, `jwt`, `pkcs12`, `x509` (эндпоинты вида `/xml/sign`, `/cms/verify` и т.д.). Ошибки централизованно обрабатывает `controller/advice/ExceptionHandlerControllerAdvice`.
- `service/` — бизнес-логика подписи/проверки. `CertificateService` — центральная точка валидации сертификатов: собирает цепочку через `CaService` и статусы отзыва через `OcspService`/`CrlService`. `CaService` и `CrlService` кэшируют корневые сертификаты и CRL-файлы на диск (`cacheDir`) и обновляют кэш по расписанию с TTL из конфигурации. `TspService` использует spring-retry.
- `wrapper/` — обёртки над KalkanCrypt/JCA API: `KalkanWrapper` (чтение PKCS12-ключей из Base64, преобразование ошибок Kalkan в понятные сообщения), `KeyStoreWrapper`, `CertificateWrapper`, `DocumentWrapper`, `XMLSignatureWrapper`. Прямую работу с Kalkan-провайдером держать здесь, а не в сервисах.
- `dto/request` и `dto/response` — модели API; ключи подписантов приходят в запросах как Base64 PKCS12 (`SignerRequest`: key, password, keyAlias).
- `configuration/` — `@ConfigurationProperties`-классы под секции `ncanode.*` из application.yml.

Тексты ошибок — в `constants/MessageConstants`; наружу отдаются только они, без деталей от Kalkan (кроме режима `detailedErrors`).

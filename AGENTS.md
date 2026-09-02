# AGENTS.md

Guidance for AI coding agents (Claude Code, etc.) working in this repository.
`CLAUDE.md` points here; this file is the source of truth.

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

### Тесты не должны зависеть от текущего времени

Тестовые ключи и сертификаты имеют срок действия, а CRL/OCSP-ответы — окно валидности. Тест, который проверяет подпись/цепочку «на `new Date()`», начнёт падать, как только сертификат протухнет или CRL устареет.

- Валидацию по времени прогонять на **фиксированную дату внутри срока действия** тестового сертификата, а не на «сейчас». Пробрасывать время параметром / через `Clock`, не звать `new Date()` / `Instant.now()` в проверяемом коде без возможности подмены.
- Для проверки существующих подписей-эталонов (`xades-test-signed-*.xml` и т.п.) фиксировать validation time на момент подписания из самого файла (`SigningTime`) либо на заведомо валидную дату.
- Ассерты вида «подпись валидна сегодня» — запрещены; только «подпись валидна на дату T».

### Тестовые ключи

GOST-2015 (действующий на 2026–2027):
`/Users/malikzh/Downloads/SDK/SDK/SDK/SDK 2.0/Keys and Certs/Gost2015/2026.05.08-2027.05.07/Физическое лицо/valid/GOST512_ec425659bd2fc6dc587b871aede1857727cf8451.p12`
пароль `Qwerty12`. Это тот ключ, которым созданы эталоны `xades-test-signed-*.xml` (субъект `ТЕСТОВ ТЕСТ`, IIN123456789011, УЦ `... (GOST) TEST 2022`, CDP `http://test.pki.gov.kz/crl/nca_gost2022_test.crl`).

Прочие тестовые ключи (Base64 PKCS12) и их пароли/алиасы — в `WithTestData.groovy` (`KEY_INDIVIDUAL_VALID_2015` и др.).

## XAdES / CAdES / PAdES (LT / LTA) — work in progress

Задача: выдавать не голый xmldsig/CMS-with-TSP, а профили ETSI **B / T / LT / LTA** (клиентский запрос про «профили A, B, LT, LTA и XAdES»).

**Статус реализации.** Общий enum уровня — `dto/ades/AdesLevel { B, T, LT, LTA }`.
Сбор LT-материала — `CertificateService.collectAdesValidationData(signer, extraCerts)`
→ `dto/ades/AdesValidationData` (цепочка через `CaService.buildChain`, OCSP-в-DER через
`OcspService.getRawResponses`, CRL-в-DER через `CrlService.getEncodedCrlsFor`, сертификаты TSA
через `TspService.extractCertificates`). Формат-нейтрально. Нет OCSP/CRL для цепочки → `ClientException`.

- **XAdES B/T/LT/LTA** — `/xml/sign`, `XmlSignRequest.xadesLevel` (`null` = обычный XMLDSIG) + `tsaPolicy`.
  Оркестрация `XmlService.signXades`, формат — `wrapper/XadesSignatureWrapper` (Santuario + Kalkan).
- **CAdES B/T/LT/LTA** — `/cms/sign`, `CmsCreateRequest.cadesLevel` (`null` = обычный CMS + флаг `withTsp`).
  На `/cms/sign/add` (co-sign) — не поддержано, `ClientException`.
  Оркестрация `CmsService.applyCadesLevel`, формат — `wrapper/CadesSignatureWrapper`:
  - B — signed-атрибут `id-aa-signingCertificateV2` (ESSCertIDv2, SHA-256) + `signingTime`
    (в `CmsService.cadesSignedAttributes`, через 5-арг `addSigner`).
  - T — `TspService.addTspToSigner` (`id-aa-signatureTimeStampToken`).
  - LT — цепочка в `SignedData.certificates` (`replaceCertificatesAndCRLs`), отзыв в `SignedData.crls`
    (`CertificateList` / `[1] OtherRevocationInfoFormat` c `id-ri-ocsp-response`).
  - LTA — `id-aa-ets-archiveTimestampV3` (`0.4.0.1733.2.4`) + `id-aa-ATSHashIndex-v3` (`0.4.0.19122.1.5`)
    внутри токена; имприт по ETSI EN 319 122-1 §5.5.3 (порядок 1:1 с движком NCALayer).
    ponytail: для detached-CMS архивный имприт хэширует пустое содержимое (как и движок NCALayer).

- **PAdES B/T/LT/LTA** — `/pdf/sign`, `PdfSignRequest.padesLevel` (`null` = обычная подпись + флаг `withTsp`).
  Оркестрация `PdfService.sign`:
  - B — signed-атрибут `id-aa-signingCertificateV2` в CMS (`PdfSignatureInterface`, 5-арг `addSigner`).
  - T — `TspService.addTspToSigner` в CMS.
  - LT — `PdfService.addDocumentSecurityStore` + `wrapper/PadesLtvBuilder`: словарь `/DSS`
    (`/Certs`, `/CRLs`, `/OCSPs` как COSStream) + `/VRI/<hex SHA-1 CMS-байтов подписи>`, `saveIncremental`.
  - LTA — LT, затем ревизия с `/DocTimeStamp` (`/SubFilter /ETSI.RFC3161`, RFC3161-токен над ByteRange),
    затем повторный `/DSS` (цепочка TSA).

  Все 4 уровня XAdES, CAdES и PAdES из NCANode проходят `ValidationReport[VALID]` в движке NCALayer
  (`scratchpad/ltref/VerifyXades.java`, `VerifyCades.java`, `VerifyPades.java`).

**AdES-верификация** (Фаза 4) — `service/AdesVerificationService`, общая для XAdES/CAdES/PAdES:
- проверка метки времени подписи (`TspService.verify`: подпись TSA + imprint над правильными данными);
- «доказанное время подписи» = genTime валидной метки, иначе момент проверки — на неё проверяются
  срок действия сертификата и издателя (а не `new Date()`);
- определение уровня (`detectLevel`): метка → T, вшитый отзыв → LT, архивная метка → LTA;
- **проверка отзыва** (`checkRevocation`): приоритет вшитых CRL/OCSP над онлайн-запросами
  (CAdES `SignedData.crls`, XAdES `Encapsulated{CRL,OCSP}Value`, PAdES `/DSS/{CRLs,OCSPs}`);
  самый строгий исход выигрывает; POE по дате отзыва (отзыв позже подписи → всё ещё valid);
- **грейдинг** (`grade`): `AdesValidationStatus {VALID, INVALID, INDETERMINATE}` +
  `AdesSubIndication` (подмножество ETSI EN 319 102-1: `SIG_CRYPTO_FAILURE`, `CERT_HASH_MISMATCH`,
  `TIMESTAMP_INVALID`, `OUT_OF_BOUNDS_NO_POE`, `CHAIN_INCOMPLETE`, `CERT_REVOKED`, `REVOKED_NO_POE`,
  `REVOCATION_DATA_MISSING` …);
- проверка `SigningCertificateV2` хеша (`KalkanUtil.signingCertificateV2HashMatches` / `CertDigest` в XAdES).
Ответы `verify` несут `adesLevel`, `bestSignatureTime`, `tsp`/`signatureTimestamp`, `status`, `subIndication`.
Не делается: полная цепочка индикаций всех промежуточных проверок, проверка самих archive-timestamp
(пересчёт имприта — только парсинг + genTime).

**`id-aa-CMS-algorithm-protection`** — не добавляем: Kalkan-генератор (`addSigner(..., AttributeTable, ...)`)
молча отбрасывает неизвестные signed-атрибуты, движок NCALayer выдаёт CAdES-B без него (значит, для РК не требуется).

**`/cms/extend`, `/pdf/extend`** — достройка готовой подписи до LT/LTA (`CmsExtendRequest`/`PdfExtendRequest`,
поле `cadesLevel`/`padesLevel`). Идемпотентно: не дублирует уже вшитые метку/отзыв. Co-sign с профилем
по-прежнему не поддержан (`/cms/sign/add` → `ClientException` с подсказкой на `/cms/extend`).

Эталоны PAdES: `src/test/resources/pades/sample-signed-{b,t,lt,lta}.pdf` (+ `sample.pdf`), `PadesFixtureSpec`.
B/T подписаны пользователем; LT/LTA — `scratchpad/ltref/GenPades.java` (`extend` через движок NCALayer,
`/DocTimeStamp` от test-TSA `test.pki.gov.kz/tsp/`).

Референс — движок `kz.gov.pki.ades` из NCALayer (`knca_provider_util 0.9`, бандл `bundle23`), декомпилированный в `scratchpad` сессии. Ключевые факты:

- XAdES: exclusive-c14n везде, ns `http://uri.etsi.org/01903/v1.3.2#` (+ `v1.4.1#` для `ArchiveTimeStamp`/`TimeStampValidationData`), `SigningCertificateV2`/`IssuerSerialV2` (ESS v2), `SignedDataObjectProperties/DataObjectFormat`.
- `applyLevel`: `T` → `xades:SignatureTimeStamp` на `exc-c14n(ds:SignatureValue)`; `LT` → `xades:CertificateValues` + `xades:RevocationValues` (цепочка + OCSP-в-полном-`OCSPResponse` + CRL, на момент genTime метки времени); `LTA` → `xades141:ArchiveTimeStamp` + `TimeStampValidationData`.
- LT собирает отзыв фатально по цепочке подписанта и не-фатально по цепочке TSA.
- Порядок конкатенации канонизованных узлов для имприта `ArchiveTimeStamp` — см. `XadesSignatureService.archiveTimeStampImprintData` (самое хрупкое место, копировать 1:1).
- CAdES: unsigned-атрибуты `id-aa-signatureTimeStampToken`, `id-aa-ets-certValues`, `id-aa-ets-revocationValues`, `id-aa-ets-archiveTimestampV3`. PAdES: `/DSS` + `/VRI` + DocTimeStamp.

Формат XAdES (GOST-2015-512, УЦ `... (GOST) TEST 2022`, enveloped):
- Порядок в `RevocationValues`: `CRLValues` затем `OCSPValues`; OCSP-ответ — полный DER `OCSPResponse`.
- `CertificateValues` = подписант + промежуточный + корневой (+ сертификаты TSA).
- LTA = LT + `xades141:ArchiveTimeStamp` (собственный `xmlns:xades141`).

Эталоны на фиксированную дату `2026-09-02T11:00:00Z` (= 2026-09-02 16:00 UTC+5), проверяют
крипто-подпись, `SigningCertificateV2`-хэш, срок действия сертификата, imprint метки времени,
вшитый отзыв (LT/LTA), архивную метку (LTA). Дата фиксирована намеренно — «валидно на `new Date()`»
протухнет с истечением сертификата/CRL. Метки времени проверяются на попадание в срок действия
сертификата (а не «до REFERENCE_DATE») — устойчиво к перегенерации фикстур.
- XAdES: `src/test/resources/xades/xades-test-signed-{b,t,lt,lta}.xml` (+ `xades-test.xml`), `XadesFixtureSpec`.
- CAdES: `src/test/resources/cades/cades-test-signed-{b,t,lt,lta}.p7s` (+ `cades-test.bin`), `CadesFixtureSpec`.
  (B/T подписаны пользователем; LT/LTA сгенерены `scratchpad/ltref/GenCades.java` движком NCALayer.)

Кросс-проверка: `scratchpad`-сессии, `ltref/` — `GenXades.java` генерирует эталоны прогоном движка
NCALayer `kz.gov.pki.ades` напрямую (бандлы `kalkan`/`ades`/`xmldsig` + `StaticCrlSource`/`OnlineOcspSource`,
минуя баг pki.gov.kz с URL загрузки CRL); `VerifyXades.java` валидирует произвольный XAdES-XML этим же движком.
Материал УЦ (fresh CRL, root) — `test.pki.gov.kz` / `crl.root.gov.kz`.

## Architecture

Слои: **controller → service → wrapper**.

- `controller/` — REST-контроллеры, по одному на область API: `xml`, `cms`, `pdf`, `wsse`, `jwt`, `jws`, `pkcs12`, `x509` (эндпоинты вида `/xml/sign`, `/cms/verify` и т.д.). `jws` — подпись/проверка произвольного JSON (`/jws/sign`, `/jws/verify`), compact serialization, без семантики claim'ов JWT. Ошибки централизованно обрабатывает `controller/advice/ExceptionHandlerControllerAdvice`.
- `service/` — бизнес-логика подписи/проверки. `CertificateService` — центральная точка валидации сертификатов: собирает цепочку через `CaService` и статусы отзыва через `OcspService`/`CrlService`. `CaService` и `CrlService` кэшируют корневые сертификаты и CRL-файлы на диск (`cacheDir`) и обновляют кэш по расписанию с TTL из конфигурации. `TspService` использует spring-retry.
- `wrapper/` — обёртки над KalkanCrypt/JCA API: `KalkanWrapper` (чтение PKCS12-ключей из Base64, преобразование ошибок Kalkan в понятные сообщения), `KeyStoreWrapper`, `CertificateWrapper`, `DocumentWrapper`, `XMLSignatureWrapper`. Прямую работу с Kalkan-провайдером держать здесь, а не в сервисах.
- `dto/request` и `dto/response` — модели API; ключи подписантов приходят в запросах как Base64 PKCS12 (`SignerRequest`: key, password, keyAlias).
- `configuration/` — `@ConfigurationProperties`-классы под секции `ncanode.*` из application.yml.

Тексты ошибок — в `constants/MessageConstants`; наружу отдаются только они, без деталей от Kalkan (кроме режима `detailedErrors`).

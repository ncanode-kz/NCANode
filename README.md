
![NCANode](NCANode.png)


⭐ Приложение-сервер для работы с Электронно Цифровой Подписью (ЭЦП) РК

---

![License:MIT](https://img.shields.io/badge/license-MIT-green.svg)
![Downloads](https://img.shields.io/github/downloads/malikzh/NCANode/total.svg)
![Docker Pulls](https://img.shields.io/docker/pulls/malikzh/ncanode)
[![Build CI and Test](https://github.com/malikzh/NCANode/actions/workflows/build-ci.yml/badge.svg)](https://github.com/malikzh/NCANode/actions/workflows/build-ci.yml)
![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/malikzh/NCANode)
[![codecov](https://codecov.io/gh/malikzh/NCANode/branch/master/graph/badge.svg?token=yk6ln3mlTB)](https://codecov.io/gh/malikzh/NCANode)

---

## Возможности

- Кроссплатформенный сервер (Windows, Mac OS, Linux)
- Работа с API посредством JSON
- Подпись XML данных с помощью xmldsig
- Подпись Wsse для [SmartBridge](https://sb.egov.kz/)
- Поддержка OCSP и CRL
- Проверка валидности сертификатов (включая цепочку доверия)
- Поддержка работы с CMS ( [Cryptographic Message Syntax](https://en.wikipedia.org/wiki/Cryptographic_Message_Syntax) )
- Поддержка TSP-меток в CMS
- Поддержка множественных подписей для xmldsig и CMS
- Возможность добавления подписей уже в существующие файлы CMS и XML
- Подпись и проверка PDF (PAdES)
- Профили ETSI AdES для XML, CMS и PDF: **XAdES / CAdES / PAdES уровней B, T, LT, LTA** (эндпоинты `/xml/sign`, `/cms/sign`, `/pdf/sign` с параметром `xadesLevel` / `cadesLevel` / `padesLevel`)
- Достройка готовой подписи до уровня LT / LTA (`/cms/extend`, `/pdf/extend`)
- Проверка AdES-подписей: определение уровня, проверка метки времени, «доказанного времени подписи», вшитого отзыва (CRL/OCSP), статус по ETSI EN 319 102-1
- Подпись и проверка произвольного JSON через JWS (`/jws/sign`, `/jws/verify`, compact serialization)
- Подпись и проверка JWT (`/jwt/*`)
- Поддержка новых ЭЦП (ГОСТ 2015) и новых CRL
- Добавлены тесты на весь функционал
- Docker

## Официальная группа в Telegram

В целях оперативного решения проблем / помощи, была создана официальная группа в Telegram:
http://t.me/ncanode

## Кому надо?

Если Вам необходимо реализовать подпись данных будь формата XML или любом другом произвольном формате, при этом на стороне сервера,
Вы можете запустить NCANode на сервере и обращаться к нему посредством API (Http/RabbitMQ).

## Кто использует?

Исходя из полученных писем от программистов, NCANode используется как в стартапах, так и в крупных страховых компаниях

## СМИ об NCANode

https://profit.kz/news/56732/Otkritij-kod-Beeline-Hacktoberfest-v-Kazahstane/

## Пример

Пример запроса (запрос информации о ключе):

```json
{
  "xml": "<?xml version=\"1.0\" encoding=\"utf-8\"?><a><b>test</b></a>",
  "signers": [
    {
      "key": "MIIHTwIBAzCCBwkGCSqGS...",
      "password": "qwerty12"
    }
  ]
}
```

Пример ответа:

```json
{
  "status": 200,
  "message": "OK",
  "xml": "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"no\"?><a><b>test</b><ds:Signature x..."
}
```

## Документация

Документацию можно найти на http://ncanode.kz

Swagger: https://v3.ncanode.kz/swagger-ui/

## Contributors

<a href="https://github.com/malikzh/NCANode/graphs/contributors">
  <img src="https://contributors-img.web.app/image?repo=malikzh/NCANode" />
</a>

## Лицензия

Проект лицензирован под лицензией [MIT](LICENSE)

## Важно!!!

По требованию  АО «НИТ» | НУЦ РК. Библиотеки `kalkancrypt-*.jar`/`knca_provider_jce_kalkan-*.jar` и `kalkancrypt-xmldsig-*.jar`
Были удалены из репозитория, поэтому для компиляции Вам необходимо подставить библиотеки
из комплекта разработчика (SDK) в директорию `/lib`.

### Сборка проекта

Версия gradle: 9.6
Версия java: 25

Для сборки проекта необходимо:

1. Подставить библиотеки kalkancrypt (`knca_provider_jce_kalkan-*.jar` и `kalkancrypt-xmldsig-*.jar`) в директорию lib (Их можно запросить [тут](https://pki.gov.kz/developers/))
2. `./gradlew bootJar` (для jar файла) или `./gradlew bootWar` (для war файла)


Собранный проект будет лежать: `build/libs/NCANode.jar` или `build/libs/NCANode.war`

### Запуск проекта без сборки

Проект запустить можно командой:

```bash
$ ./gradlew bootRun
```

### Запуск в Docker из готового образа

```bash
docker volume create ncanode_cache
docker run -p 14579:14579 -v ncanode_cache:/app/cache -d malikzh/ncanode
```

### Запуск через Docker Compose

Предварительно нужно собрать проект через gradle и сгенерировать jar файлы

```bash
docker compose build  // сборка образа
docker compose up -d  // запуск контейнера
docker compose ps  // проверка статуса контейнера
docker compose stop  // остановка контейнера
```

### После запуска

Проверить можно, перейдя на страницу: http://localhost:14579/actuator/health

## Как отправить Pull Request

Если вы нашли и исправили ошибку, пожалуйста, отправьте Pull Request — я обязательно его рассмотрю.  
Если требуется срочное рассмотрение вашего PR, напишите в группу [Telegram](http://t.me/ncanode).

Сделано с ❤️

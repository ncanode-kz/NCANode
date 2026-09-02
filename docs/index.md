---
layout: page
---

<h1 class="text-center">
    NCANode
</h1>

---

<div style="display: flex; height: 100px;align-items: center;justify-content: center;">
    <div>
        <a class="github-button" href="https://github.com/ncanode-kz/NCANode" data-size="large" data-show-count="true" aria-label="Star ncanode-kz/NCANode on GitHub">Star</a>    
    </div>
    <div style="margin-left: 10px;">
<a class="github-button" href="https://github.com/ncanode-kz/NCANode/fork" data-size="large" data-show-count="true" aria-label="Fork ncanode-kz/NCANode on GitHub">Fork</a>    
</div>

 <div style="margin-left: 10px;">
<!-- Place this tag where you want the button to render. -->
<a class="github-button" href="https://github.com/ncanode-kz/NCANode/releases" download data-icon="octicon-download" data-size="large" aria-label="Download ncanode-kz/NCANode on GitHub">Download</a>
</div>
</div>

---

<div style="display: flex; justify-content: center;">
    <div style="margin: 0 5px;"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License:MIT"></div>
    <div style="margin: 0 5px;"><img src="https://img.shields.io/github/downloads/ncanode-kz/NCANode/total.svg" alt="Docker Pulls"></div>
    <div style="margin: 0 5px;"><a href="https://github.com/ncanode-kz/NCANode/actions/workflows/build-ci.yml" target="_blank"><img src="https://github.com/ncanode-kz/NCANode/actions/workflows/build-ci.yml/badge.svg" alt="Build CI and Test"></a></div>
    <div style="margin: 0 5px;"><img src="https://img.shields.io/github/v/release/ncanode-kz/NCANode" alt="GitHub release (latest SemVer)"></div>
    <div style="margin: 0 5px;"><a href="https://codecov.io/gh/ncanode-kz/NCANode" target="_blank"><img src="https://codecov.io/gh/ncanode-kz/NCANode/branch/master/graph/badge.svg?token=yk6ln3mlTB" alt="Build CI and Test"></a></div>
</div>

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
- Поддержка новых ЭЦП (ГОСТ 2015) и новых CRL
- Добавлены тесты на весь функционал
- Docker

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

## Contributors

<a href="https://github.com/ncanode-kz/NCANode/graphs/contributors">
  <img src="https://contributors-img.web.app/image?repo=ncanode-kz/NCANode" />
</a>

## Лицензия

Проект лицензирован под лицензией [MIT](LICENSE)

## Важно!!!

По требованию  АО «НИТ» | НУЦ РК. Библиотеки `kalkancrypt-0.6.jar` и `kalkancrypt_xmldsig-0.3.jar`
Были удалены из репозитория, поэтому для компиляции Вам необходимо подставить библиотеки
из комплекта разработчика (SDK) в директорию `/lib`.

### Сборка проекта

Для сборки проекта необходимо:

1. Подставить бибилиотеки kalkancrypt (Их можно запросить [тут](https://pki.gov.kz/developers/))
2. `./gradlew bootJar` (для jar файла) или `./gradlew bootWar` (для jar файла)


Собранный проект будет лежать: `build/libs/NCANode.jar` или `build/libs/NCANode.war`

### Запуск в Docker

```bash
docker volume create ncanode_cache
docker run -p 14579:14579 -v ncanode_cache:/app/cache -d malikzh/ncanode
```

### Запуск проекта без сборки

Проект запустить можно командой:

```bash
$ ./gradlew bootRun
```

### После запуска

Проверить можно, перейдя на страницу: http://localhost:14579/actuator/health


<!-- Place this tag in your head or just before your close body tag. -->
<script async defer src="https://buttons.github.io/buttons.js"></script>
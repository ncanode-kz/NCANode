package kz.ncanode.integration

import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.dataformat.yaml.YAMLGenerator
import com.fasterxml.jackson.dataformat.yaml.YAMLMapper
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.web.servlet.MockMvc
import spock.lang.Specification

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status

/**
 * Не совсем тест: экспортирует актуальную OpenAPI-спеку в ./openapi.yml.
 * Файл коммитится в репозиторий и раздаётся через Swagger UI на GitHub Pages (github-pages.yml).
 * build-ci.yml после сборки делает `git diff --exit-code openapi.yml` — если поправил контроллеры,
 * но не перегенерил спеку, PR падает. Перегенерация локально: ./gradlew test.
 *
 * Вывод springdoc не детерминирован (порядок ключей зависит от платформы/сканирования),
 * поэтому прогоняем через Jackson с сортировкой ключей — иначе diff-проверка в CI будет флапать.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
class OpenApiExportTest extends Specification {

    @Autowired
    MockMvc mockMvc

    def "export OpenAPI spec to openapi.yml"() {
        given:
        def yaml = YAMLMapper.builder()
            .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS)
            .disable(YAMLGenerator.Feature.WRITE_DOC_START_MARKER)
            .build()

        when:
        def bytes = mockMvc.perform(get("/v3/api-docs.yaml"))
            .andExpect(status().isOk())
            .andReturn().response.contentAsByteArray
        def spec = yaml.writeValueAsString(yaml.readValue(bytes, Object))
        new File("openapi.yml").write(spec, "UTF-8")

        then:
        spec.contains("\nopenapi: ")
        spec.contains("\npaths:\n")
    }
}

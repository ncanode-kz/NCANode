package kz.ncanode;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.retry.annotation.EnableRetry;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.context.annotation.Configuration;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.servers.Server;
import io.swagger.v3.oas.models.tags.Tag;
import org.springdoc.core.customizers.OpenApiCustomizer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;

import java.util.Comparator;


@SpringBootApplication
@EnableScheduling
@EnableCaching
@EnableRetry
public class NCANode extends SpringBootServletInitializer {
    public static void main(String[] args) {
        System.out.println(banner());
        SpringApplication.run(NCANode.class, args);
    }
    public static String banner() {
        return """
             ____  _____   ______       _       ____  _____               __          ______  \s
            |_   \\|_   _|.' ___  |     / \\     |_   \\|_   _|             |  ]        / ____ `.\s
              |   \\ | | / .'   \\_|    / _ \\      |   \\ | |   .--.    .--.| | .---.   `'  __) |\s
              | |\\ \\| | | |          / ___ \\     | |\\ \\| | / .'`\\ \\/ /'`\\' |/ /__\\\\  _  |__ '.\s
             _| |_\\   |_\\ `.___.'\\ _/ /   \\ \\_  _| |_\\   |_| \\__. || \\__/  || \\__., | \\____) |\s
            |_____|\\____|`.____ .'|____| |____||_____|\\____|'.__.'  '.__.;__]'.__.'  \\______.'\s
            """;
    }
    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder builder) {
        return builder.sources(NCANode.class);
    }
    @Configuration
    public static class OpenApiConfig {

        @Value("${SWAGGER_RELATIVE_PATH:}")
        private String swaggerRelativePath;

        @Bean
        public OpenAPI customOpenAPI() {
            String fullUrl = swaggerRelativePath;
            return new OpenAPI()
                .addServersItem(new Server().url(fullUrl).description("current server"));
        }

        // Порядок тегов у springdoc = порядок сканирования контроллеров (зависит от ФС/платформы).
        // Сортируем, чтобы экспортируемый openapi.yml был детерминированным (см. OpenApiExportTest).
        @Bean
        public OpenApiCustomizer sortTagsAlphabetically() {
            return openApi -> {
                if (openApi.getTags() != null) {
                    openApi.getTags().sort(Comparator.comparing(Tag::getName));
                }
            };
        }
    }

}

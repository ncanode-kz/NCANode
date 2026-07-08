package kz.ncanode.configuration;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import jakarta.validation.constraints.Min;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Optional;

@Configuration
@ConfigurationProperties(prefix = "ncanode.tsp")
@Getter
@Setter
public class TspConfiguration {
    private String url;

    @Min(1)
    private Integer retries;

    public Optional<URL> getParsedUrl() {
        try {
            return Optional.of(new URL(url));
        } catch (MalformedURLException e) {
            return Optional.empty();
        }
    }
}

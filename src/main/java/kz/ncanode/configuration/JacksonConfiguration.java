package kz.ncanode.configuration;

import com.fasterxml.jackson.core.StreamReadConstraints;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.jackson.Jackson2ObjectMapperBuilderCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class JacksonConfiguration {

    @Bean
    public Jackson2ObjectMapperBuilderCustomizer streamReadConstraintsCustomizer(
            @Value("${ncanode.system.maxJsonStringLength:31457280}") int maxStringLength) {
        return builder -> builder.postConfigurer(objectMapper ->
                objectMapper.getFactory().setStreamReadConstraints(
                        StreamReadConstraints.builder()
                                .maxStringLength(maxStringLength)
                                .build()));
    }
}

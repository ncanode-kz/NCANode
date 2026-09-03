package kz.ncanode.configuration;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import kz.ncanode.exception.WarmupException;
import kz.ncanode.service.WarmupService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Пока не скачаны сертификаты УЦ / не обновлены CRL:
 * <ul>
 *   <li>{@code /actuator/health} показывает компоненты {@code ca} / {@code crl} со статусом DOWN
 *       (а значит и общий статус — DOWN);</li>
 *   <li>эндпоинты {@code /*}{@code /verify} отвечают 503.</li>
 * </ul>
 */
@Configuration
@RequiredArgsConstructor
public class WarmupConfiguration implements WebMvcConfigurer {
    private final WarmupService warmupService;

    @Bean
    public HealthIndicator caHealthIndicator() {
        return () -> warmupService.isCaReady()
            ? Health.up().build()
            : Health.down().withDetail("reason", "CA certificates are not downloaded yet").build();
    }

    @Bean
    public HealthIndicator crlHealthIndicator() {
        return () -> warmupService.isCrlReady()
            ? Health.up().build()
            : Health.down().withDetail("reason", "CRL cache is not updated yet").build();
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new HandlerInterceptor() {
            @Override
            public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
                if (!warmupService.isReady()) {
                    throw new WarmupException();
                }
                return true;
            }
        }).addPathPatterns("/*/verify");
    }
}

package kz.ncanode.exception;

import org.springframework.http.HttpStatus;

/**
 * Сервер ещё не прогрелся: не скачаны сертификаты УЦ / не обновлены CRL.
 */
public class WarmupException extends ApplicationException {
    public WarmupException() {
        super("Service is warming up: CA certificate and CRL caches are not ready yet. Try again shortly.");
    }

    @Override
    public Integer getStatus() {
        return HttpStatus.SERVICE_UNAVAILABLE.value();
    }
}

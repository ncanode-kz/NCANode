package kz.ncanode.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Признак «прогрева» сервера: скачаны сертификаты УЦ и обновлены CRL.
 * Пока не прогрет — {@code /actuator/health} отдаёт DOWN, а эндпоинты verify — 503.
 */
@Service
@RequiredArgsConstructor
public class WarmupService {
    private final CaService caService;
    private final List<CrlService> crlServices;

    public boolean isCaReady() {
        return caService.isCacheReady();
    }

    public boolean isCrlReady() {
        return crlServices.stream().allMatch(CrlService::isCacheReady);
    }

    public boolean isReady() {
        return isCaReady() && isCrlReady();
    }
}

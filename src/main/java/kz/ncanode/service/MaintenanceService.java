package kz.ncanode.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.info.BuildProperties;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;

@RequiredArgsConstructor
@Slf4j
@Service
public class MaintenanceService {
    private final BuildProperties buildProperties;

    public String getNCANodeVersion() {
        return buildProperties.getVersion();
    }

    @PostConstruct
    public void displayVersion() {
        log.info("NCANode version: {}", getNCANodeVersion());
    }
}

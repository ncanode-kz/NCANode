package kz.ncanode.service;

import kz.ncanode.dto.request.JwtDecodeRequest;
import kz.ncanode.dto.request.JwtEncodeRequest;
import kz.ncanode.dto.response.JwtDecodeResponse;
import kz.ncanode.dto.response.JwtEncodeResponse;
import kz.ncanode.wrapper.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;

/**
 * JWT Service.
 *
 * Сервис отвечает за всё что связано с JWT.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class JwtService {
    private final KalkanWrapper kalkanWrapper;

    /**
     * Подписывание JWT
     *
     * @param jwtEncodeRequest Запрос на подпись JWT
     * @return Ответ с подписанным XML
     */
    public JwtEncodeResponse encode(JwtEncodeRequest jwtEncodeRequest) {

        String jwt = JWT.create().withIssuer("hello").withSubject("world")
            .withClaim("key", "value")
            .withIssuedAt(new java.util.Date())
            .withExpiresAt(new java.util.Date(System.currentTimeMillis() + 60000))
            .sign(Algorithm.GG2015(publicKey, privateKey));

        return JwtEncodeResponse.builder()
            .jwt(jwt)
            .build();


    }

    /**
     * Проверяет JWT-подписи
     *
     * @param jwt JWT-строка
     * @param key Ключ или сертификат
     * @return Результат проверки
     */
    public JwtDecodeResponse decode(JwtDecodeRequest jwtDecodeRequest) {

        JWTVerifier verifier = JWT.require(Algorithm.GG2015(publicKey)).build();

        return JwtDecodeResponse.builder()
            .jwt(verifier.toString())
            .build();
    }
}

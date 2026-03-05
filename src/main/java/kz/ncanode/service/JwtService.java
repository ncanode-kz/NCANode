package kz.ncanode.service;

import kz.ncanode.dto.request.JwtDecodeRequest;
import kz.ncanode.dto.request.JwtEncodeRequest;
import kz.ncanode.dto.response.JwtDecodeResponse;
import kz.ncanode.dto.response.JwtEncodeResponse;
import kz.ncanode.exception.ClientException;
import kz.ncanode.exception.KeyException;
import kz.ncanode.exception.ServerException;
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

        try {
            // read key
            final KeyStoreWrapper keystore = kalkanWrapper.read(jwtEncodeRequest.getKey(), jwtEncodeRequest.getKeyAlias(), jwtEncodeRequest.getPassword());
            final CertificateWrapper cert = keystore.getCertificate();

            String jwt = JWT.create().withIssuer("hello").withSubject("world")
                .withClaim("key", "value")
                .withIssuedAt(new java.util.Date())
                .withExpiresAt(new java.util.Date(System.currentTimeMillis() + 60000))
                .sign(Algorithm.GG2015((ECPublicKey) cert.getPublicKey(), (ECPrivateKey) keystore.getPrivateKey()));

            return JwtEncodeResponse.builder()
                .jwt(jwt)
                .build();

        } catch (KeyException e) {
            throw new ClientException(e.getMessage(), e);
        } catch (Exception e) {
            throw new ServerException(e.getMessage(), e);
        }
    }

    /**
     * Проверяет JWT-подписи
     *
     * @see https://gist.github.com/as1an/e87c371fc9fdece6a339d499f98e53ff
     * @see https://dev.azure.com/as1an/public/_artifacts/feed/repo/maven/kz.gov.pki%2Fjava-jwt/overview/4.4.0
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

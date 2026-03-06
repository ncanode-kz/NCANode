package kz.ncanode.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import kz.ncanode.dto.request.JwtDecodeRequest;
import kz.ncanode.dto.request.JwtEncodeRequest;
import kz.ncanode.dto.response.JwtDecodeResponse;
import kz.ncanode.dto.response.JwtEncodeResponse;
import kz.ncanode.exception.ClientException;
import kz.ncanode.exception.KeyException;
import kz.ncanode.exception.ServerException;
import kz.ncanode.wrapper.CertificateWrapper;
import kz.ncanode.wrapper.KalkanWrapper;
import kz.ncanode.wrapper.KeyStoreWrapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * JWT Service.
 * <p>
 * Сервис отвечает за всё что связано с JWT.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class JwtService {
    private final KalkanWrapper kalkanWrapper;

    /**
     * Формирование и подписание JWT
     *
     * @param jwtEncodeRequest Запрос на формирование и подписание JWT
     * @return Ответ с подписанным JWT
     */
    public JwtEncodeResponse encode(JwtEncodeRequest jwtEncodeRequest) {
        try {
            final KeyStoreWrapper keystore = kalkanWrapper.read(jwtEncodeRequest.getKey(), jwtEncodeRequest.getKeyAlias(), jwtEncodeRequest.getPassword());
            final CertificateWrapper cert = keystore.getCertificate();

            JWTCreator.Builder builder = JWT.create();

            Map<String, Object> claims = jwtEncodeRequest.getJwt().getPayload().getClaims();

            for (Map.Entry<String, Object> entry : claims.entrySet()) {
                addClaim(builder, entry.getKey(), entry.getValue());
            }

            Algorithm algorithm = resolveAlgorithm(
                jwtEncodeRequest.getJwt().getHeader().getAlg(),
                cert.getPublicKey(),
                keystore.getPrivateKey()
            );

            String jwt = builder.sign(algorithm);

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
     * Декодирование и проверка JWT
     *
     * @param jwtDecodeRequest Запрос на проверку JWT
     * @return Результат проверки с декодированными данными
     */
    public JwtDecodeResponse decode(JwtDecodeRequest jwtDecodeRequest) {
        try {

            var x509 = CertificateService.load(Base64.getDecoder().decode(jwtDecodeRequest.getKey().replaceAll("\\s", "")));

            boolean valid = true;

            DecodedJWT data;

            try {
                data = JWT.decode(jwtDecodeRequest.getJwt());
            } catch (JWTDecodeException e) {
                throw new ClientException(e.getMessage(), e);
            }

            Algorithm algorithm = resolveAlgorithm(
                data.getAlgorithm(),
                x509.getPublicKey()
            );

            try {
                JWTVerifier verifier = JWT.require(algorithm).build();
                verifier.verify(jwtDecodeRequest.getJwt());
            } catch (JWTVerificationException e) {
                log.error("JWT Verification Exception", e);
                valid = false;
            }

            Map<String, Object> payload = new LinkedHashMap<>();

            for (Map.Entry<String, Claim> entry : data.getClaims().entrySet()) {
                payload.put(entry.getKey(), entry.getValue().as(Object.class));
            }

            Map<String, String> header = new LinkedHashMap<>();

            header.put("alg", data.getAlgorithm());
            header.put("typ", data.getType());

            return JwtDecodeResponse.builder()
                .valid(valid)
                .jwt(JwtDecodeResponse.Jwt.builder()
                    .header(header)
                    .payload(payload)
                    .build())
                .build();

        } catch (ClientException e) {
            throw e;
        } catch (Exception e) {
            throw new ClientException(e.getMessage(), e);
        }
    }

    private Algorithm resolveAlgorithm(String alg, PublicKey publicKey, PrivateKey privateKey) {
        return switch (alg) {
            case "GG2015" -> Algorithm.GG2015((ECPublicKey) publicKey, (ECPrivateKey) privateKey);
            case "GG2004" -> Algorithm.GG2004((ECPublicKey) publicKey, (ECPrivateKey) privateKey);
            case "ES256" -> Algorithm.ECDSA256((ECPublicKey) publicKey, (ECPrivateKey) privateKey);
            case "ES384" -> Algorithm.ECDSA384((ECPublicKey) publicKey, (ECPrivateKey) privateKey);
            case "ES512" -> Algorithm.ECDSA512((ECPublicKey) publicKey, (ECPrivateKey) privateKey);
            case "RS256" -> Algorithm.RSA256((RSAPublicKey) publicKey, (RSAPrivateKey) privateKey);
            case "RS384" -> Algorithm.RSA384((RSAPublicKey) publicKey, (RSAPrivateKey) privateKey);
            case "RS512" -> Algorithm.RSA512((RSAPublicKey) publicKey, (RSAPrivateKey) privateKey);
            default -> throw new ClientException("Unsupported algorithm: " + alg);
        };
    }

    private Algorithm resolveAlgorithm(String alg, PublicKey publicKey) {
        return switch (alg) {
            case "GG2015" -> Algorithm.GG2015((ECPublicKey) publicKey);
            case "GG2004" -> Algorithm.GG2004((ECPublicKey) publicKey);
            case "ES256" -> Algorithm.ECDSA256((ECPublicKey) publicKey);
            case "ES384" -> Algorithm.ECDSA384((ECPublicKey) publicKey);
            case "ES512" -> Algorithm.ECDSA512((ECPublicKey) publicKey);
            case "RS256" -> Algorithm.RSA256((RSAPublicKey) publicKey);
            case "RS384" -> Algorithm.RSA384((RSAPublicKey) publicKey);
            case "RS512" -> Algorithm.RSA512((RSAPublicKey) publicKey);
            default -> throw new ClientException("Unsupported algorithm: " + alg);
        };
    }

    private void addClaim(JWTCreator.Builder builder, String key, Object value) {
        if (value instanceof String) {
            builder.withClaim(key, (String) value);
        } else if (value instanceof Integer) {
            builder.withClaim(key, (Integer) value);
        } else if (value instanceof Long) {
            builder.withClaim(key, (Long) value);
        } else if (value instanceof Double) {
            builder.withClaim(key, (Double) value);
        } else if (value instanceof Boolean) {
            builder.withClaim(key, (Boolean) value);
        } else if (value != null) {
            builder.withClaim(key, value.toString());
        }
    }
}

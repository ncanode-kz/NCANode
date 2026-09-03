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
import kz.ncanode.exception.ServerOp;
import kz.ncanode.util.JwtAlgorithmUtil;
import kz.ncanode.wrapper.CertificateWrapper;
import kz.ncanode.wrapper.KalkanWrapper;
import kz.ncanode.wrapper.KeyStoreWrapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
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
        return ServerOp.call(null, () -> {
            final KeyStoreWrapper keystore = kalkanWrapper.read(jwtEncodeRequest.getKey(), jwtEncodeRequest.getKeyAlias(), jwtEncodeRequest.getPassword());
            final CertificateWrapper cert = keystore.getCertificate();

            JWTCreator.Builder builder = JWT.create();

            Map<String, Object> claims = jwtEncodeRequest.getJwt().getPayload().getClaims();

            for (Map.Entry<String, Object> entry : claims.entrySet()) {
                addClaim(builder, entry.getKey(), entry.getValue());
            }

            Algorithm algorithm = JwtAlgorithmUtil.forSigning(
                jwtEncodeRequest.getJwt().getHeader().getAlg(),
                cert.getPublicKey(),
                keystore.getPrivateKey()
            );

            String jwt = builder.sign(algorithm);

            return JwtEncodeResponse.builder()
                .jwt(jwt)
                .build();
        });
    }

    /**
     * Декодирование и проверка JWT
     *
     * @param jwtDecodeRequest Запрос на проверку JWT
     * @return Результат проверки с декодированными данными
     */
    public JwtDecodeResponse decode(JwtDecodeRequest jwtDecodeRequest) {
        return ServerOp.callClient(null, () -> {

            var x509 = CertificateService.load(Base64.getDecoder().decode(jwtDecodeRequest.getKey().replaceAll("\\s", "")));

            boolean valid = true;

            DecodedJWT data;

            try {
                data = JWT.decode(jwtDecodeRequest.getJwt());
            } catch (JWTDecodeException e) {
                throw new ClientException(e.getMessage(), e);
            }

            Algorithm algorithm = JwtAlgorithmUtil.forVerification(
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
        });
    }

    @SuppressWarnings("unchecked")
    private void addClaim(JWTCreator.Builder builder, String key, Object value) {
        switch (value) {
            case null -> { }
            case String s -> builder.withClaim(key, s);
            case Integer i -> builder.withClaim(key, i);
            case Long l -> builder.withClaim(key, l);
            case Double d -> builder.withClaim(key, d);
            case Boolean b -> builder.withClaim(key, b);
            case Date d -> builder.withClaim(key, d);
            case Map<?, ?> m -> builder.withClaim(key, (Map<String, ?>) m);
            case List<?> l -> builder.withClaim(key, l);
            default -> builder.withClaim(key, value.toString());
        }
    }
}

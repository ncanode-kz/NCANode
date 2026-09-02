package kz.ncanode.util;

import com.auth0.jwt.algorithms.Algorithm;
import kz.ncanode.exception.ClientException;
import lombok.experimental.UtilityClass;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Сопоставление имени алгоритма из JOSE-заголовка (alg) с {@link Algorithm} библиотеки java-jwt.
 * Общее для JWT и JWS.
 */
@UtilityClass
public class JwtAlgorithmUtil {

    /**
     * Алгоритм для подписи — нужны обе части ключа.
     */
    public static Algorithm forSigning(String alg, PublicKey publicKey, PrivateKey privateKey) {
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

    /**
     * Алгоритм для проверки подписи — только открытый ключ.
     */
    public static Algorithm forVerification(String alg, PublicKey publicKey) {
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
}

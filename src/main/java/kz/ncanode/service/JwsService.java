package kz.ncanode.service;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import kz.ncanode.dto.certificate.CertificateRevocation;
import kz.ncanode.dto.jws.JwsSignerInfo;
import kz.ncanode.dto.request.JwsSignRequest;
import kz.ncanode.dto.request.JwsSignerRequest;
import kz.ncanode.dto.request.JwsVerifyRequest;
import kz.ncanode.dto.response.JwsSignResponse;
import kz.ncanode.dto.response.JwsVerifyResponse;
import kz.ncanode.exception.ClientException;
import kz.ncanode.exception.ServerOp;
import kz.ncanode.util.JwtAlgorithmUtil;
import kz.ncanode.wrapper.CertificateWrapper;
import kz.ncanode.wrapper.KalkanWrapper;
import kz.ncanode.wrapper.KeyStoreWrapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * JWS Service.
 * <p>
 * Подпись и проверка произвольного JSON в формате JWS (RFC 7515), JSON Serialization —
 * поддерживает несколько подписантов, дописывание подписей и detached payload.
 * В отличие от JWT здесь нет семантики claim'ов (exp/nbf/iat не проверяются).
 * <p>
 * ponytail: только JSON Serialization в общем синтаксисе (signatures[]); на входе принимаем
 * и flattened. Сигнатурные вычисления делегируем java-jwt (форк kz.gov.pki) — свой GOST не пишем.
 * ponytail: payload — любой JSON; сырые октеты (RFC 7515 §3) не поддержаны, добавить при нужде.
 * ponytail: detached-проверка полагается на детерминированную сериализацию payload через Jackson
 * (readTree → writeValueAsBytes стабилен). Для JWS, собранных не нами, передавать payload в том же виде.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class JwsService {
    private final KalkanWrapper kalkanWrapper;
    private final CertificateService certificateService;
    private final ObjectMapper objectMapper;

    /**
     * Создаёт новый JWS.
     */
    public JwsSignResponse sign(JwsSignRequest request) {
        return ServerOp.call(null, () -> {
            if (request.getPayload() == null) {
                throw new ClientException("payload argument not specified");
            }

            String payloadB64 = b64Url(objectMapper.writeValueAsBytes(request.getPayload()));

            ArrayNode signatures = objectMapper.createArrayNode();
            for (JwsSignerRequest signer : request.getSigners()) {
                signatures.add(signOne(signer, payloadB64, request.getTyp()));
            }

            ObjectNode jws = objectMapper.createObjectNode();
            if (!request.isDetached()) {
                jws.put("payload", payloadB64);
            }
            jws.set("signatures", signatures);

            return JwsSignResponse.builder().jws(jws).build();
        });
    }

    /**
     * Добавляет подписантов в существующий JWS.
     */
    public JwsSignResponse addSigners(JwsSignRequest request) {
        return ServerOp.call(null, () -> {
            JsonNode existing = request.getJws();
            if (existing == null || !existing.isObject()) {
                throw new ClientException("jws argument not specified");
            }

            boolean detached = !hasPayload(existing);
            String payloadB64;
            if (detached) {
                if (request.getPayload() == null) {
                    throw new ClientException("payload must be specified for detached JWS");
                }
                payloadB64 = b64Url(objectMapper.writeValueAsBytes(request.getPayload()));
            } else {
                payloadB64 = existing.get("payload").asText();
            }

            ArrayNode signatures = objectMapper.createArrayNode();
            if (existing.has("signatures")) {
                existing.get("signatures").forEach(signatures::add);
            } else if (existing.has("signature")) { // flattened -> нормализуем
                ObjectNode n = objectMapper.createObjectNode();
                n.set("protected", existing.get("protected"));
                n.set("signature", existing.get("signature"));
                signatures.add(n);
            }

            for (JwsSignerRequest signer : request.getSigners()) {
                signatures.add(signOne(signer, payloadB64, request.getTyp()));
            }

            ObjectNode jws = objectMapper.createObjectNode();
            if (!detached) {
                jws.put("payload", payloadB64);
            }
            jws.set("signatures", signatures);

            return JwsSignResponse.builder().jws(jws).build();
        });
    }

    /**
     * Проверяет JWS.
     */
    public JwsVerifyResponse verify(JwsVerifyRequest request) {
        return ServerOp.callClient(null, () -> {
            JsonNode jws = request.getJws();
            if (jws == null || !jws.isObject()) {
                throw new ClientException("jws argument not specified");
            }

            boolean checkOcsp = request.getRevocationCheck().contains(CertificateRevocation.OCSP);
            boolean checkCrl = request.getRevocationCheck().contains(CertificateRevocation.CRL);
            Date currentDate = certificateService.getCurrentDate();

            String payloadB64;
            JsonNode payloadOut;
            if (hasPayload(jws)) {
                payloadB64 = jws.get("payload").asText();
                payloadOut = objectMapper.readTree(Base64.getUrlDecoder().decode(payloadB64));
            } else {
                if (request.getPayload() == null) {
                    throw new ClientException("payload must be specified for detached JWS");
                }
                payloadB64 = b64Url(objectMapper.writeValueAsBytes(request.getPayload()));
                payloadOut = request.getPayload();
            }

            List<JsonNode> sigNodes = new ArrayList<>();
            if (jws.has("signatures")) {
                jws.get("signatures").forEach(sigNodes::add);
            } else if (jws.has("signature")) {
                sigNodes.add(jws);
            }
            if (sigNodes.isEmpty()) {
                throw new ClientException("JWS has no signatures");
            }

            boolean allValid = true;
            List<JwsSignerInfo> signers = new ArrayList<>();

            for (JsonNode sig : sigNodes) {
                String protectedB64 = sig.get("protected").asText();
                String signatureB64 = sig.get("signature").asText();
                JsonNode header = objectMapper.readTree(Base64.getUrlDecoder().decode(protectedB64));

                JsonNode x5c = header.get("x5c");
                if (x5c == null || !x5c.isArray() || x5c.isEmpty()) {
                    throw new ClientException("Signature protected header has no x5c certificate");
                }
                X509Certificate x509 = CertificateService.load(Base64.getDecoder().decode(x5c.get(0).asText().replaceAll("\\s", "")));
                CertificateWrapper cert = new CertificateWrapper(x509);

                boolean signatureValid = true;
                try {
                    JwtAlgorithmUtil.forVerification(header.get("alg").asText(), x509.getPublicKey())
                        .verify(new RawJws(protectedB64, payloadB64, signatureB64));
                } catch (JWTVerificationException e) {
                    log.warn("JWS signature verification failed", e);
                    signatureValid = false;
                }

                if (checkOcsp || checkCrl) {
                    certificateService.attachValidationData(cert, checkOcsp, checkCrl);
                    if (!cert.isValid(currentDate, checkOcsp, checkCrl)) {
                        signatureValid = false;
                    }
                }

                if (!signatureValid) {
                    allValid = false;
                }

                signers.add(JwsSignerInfo.builder()
                    .valid(signatureValid)
                    .header(objectMapper.convertValue(header, new TypeReference<LinkedHashMap<String, Object>>() {}))
                    .certificate(cert.toCertificateInfo(currentDate, checkOcsp, checkCrl))
                    .build());
            }

            return JwsVerifyResponse.builder()
                .valid(allValid)
                .signers(signers)
                .payload(payloadOut)
                .build();
        });
    }

    /**
     * Считает одну подпись над {@code protectedB64.payloadB64} и возвращает узел signatures[].
     */
    private ObjectNode signOne(JwsSignerRequest signer, String payloadB64, String typ) throws Exception {
        KeyStoreWrapper keystore = kalkanWrapper.read(signer.getKey(), signer.getKeyAlias(), signer.getPassword());
        CertificateWrapper cert = keystore.getCertificate();

        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", signer.getAlg());
        header.put("typ", typ == null ? "JWT" : typ);
        header.put("x5c", List.of(Base64.getEncoder().encodeToString(cert.getX509Certificate().getEncoded())));
        String protectedB64 = b64Url(objectMapper.writeValueAsBytes(header));

        Algorithm algorithm = JwtAlgorithmUtil.forSigning(signer.getAlg(), cert.getPublicKey(), keystore.getPrivateKey());
        byte[] signature = algorithm.sign(protectedB64.getBytes(StandardCharsets.US_ASCII), payloadB64.getBytes(StandardCharsets.US_ASCII));

        ObjectNode node = objectMapper.createObjectNode();
        node.put("protected", protectedB64);
        node.put("signature", b64Url(signature));
        return node;
    }

    private static boolean hasPayload(JsonNode jws) {
        return jws.hasNonNull("payload") && !jws.get("payload").asText().isEmpty();
    }

    private static String b64Url(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    /**
     * Минимальный {@link DecodedJWT} для {@link Algorithm#verify(DecodedJWT)} — отдаёт три части
     * (protected / payload / signature) в base64url. Позволяет проверять JWS с любым payload,
     * не проходя через {@code JWT.decode()}, который требует payload-объект.
     */
    private record RawJws(String header, String payload, String signature) implements DecodedJWT {
        @Override public String getHeader() { return header; }
        @Override public String getPayload() { return payload; }
        @Override public String getSignature() { return signature; }
        @Override public String getToken() { return header + "." + payload + "." + signature; }
        @Override public String getKeyId() { return null; }

        @Override public String getAlgorithm() { return null; }
        @Override public String getType() { return null; }
        @Override public String getContentType() { return null; }
        @Override public Claim getHeaderClaim(String name) { return null; }
        @Override public String getIssuer() { return null; }
        @Override public String getSubject() { return null; }
        @Override public List<String> getAudience() { return null; }
        @Override public Date getExpiresAt() { return null; }
        @Override public Date getNotBefore() { return null; }
        @Override public Date getIssuedAt() { return null; }
        @Override public String getId() { return null; }
        @Override public Claim getClaim(String name) { return null; }
        @Override public Map<String, Claim> getClaims() { return Map.of(); }
    }
}

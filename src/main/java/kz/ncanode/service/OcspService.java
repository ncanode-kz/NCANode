package kz.ncanode.service;

import kz.gov.pki.kalkan.asn1.ASN1InputStream;
import kz.gov.pki.kalkan.asn1.DERObject;
import kz.gov.pki.kalkan.asn1.DEROctetString;
import kz.gov.pki.kalkan.asn1.ocsp.OCSPObjectIdentifiers;
import kz.gov.pki.kalkan.asn1.x509.X509Extension;
import kz.gov.pki.kalkan.asn1.x509.X509Extensions;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.ocsp.*;
import kz.ncanode.configuration.OcspConfiguration;
import kz.ncanode.dto.ocsp.OcspResult;
import kz.ncanode.dto.ocsp.OcspStatus;
import kz.ncanode.util.Util;
import kz.ncanode.wrapper.CertificateWrapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URL;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Сервис для работы с сервером OCSP (Проверка сертификатов на отозванность)
 */
@Slf4j
@RequiredArgsConstructor
@Service
public class OcspService {
    private final KalkanProvider kalkanProvider;
    private final OcspConfiguration ocspConfiguration;
    private final CloseableHttpClient client;

    /**
     * Выполняет запрос на OCSP серверы и возвращает статус
     *
     * @param cert Сертификат
     * @param issuer Сертификат удостоверяющего центра
     * @return
     */
    public List<OcspStatus> verify(CertificateWrapper cert, CertificateWrapper issuer) {
        List<OcspStatus> statuses = new ArrayList<>();

        if (issuer == null) {
            statuses.add(OcspStatus.builder()
                .result(OcspResult.UNKOWN)
                .message("Cannot find root certificate in NCANode. Try add it using NCANODE_CA_URL variable.")
                .build()
            );

            return statuses;
        }

        for (Map.Entry<String, URL> entry : ocspConfiguration.getUrlList().entrySet()) {
            try {
                byte[] nonce = generateOcspNonce();
                OCSPReq request = buildOcspRequest(cert.getX509Certificate().getSerialNumber(), issuer.getX509Certificate(), nonce);

                try (CloseableHttpResponse response = makeRequest(entry.getValue().toString(), request.getEncoded())) {
                    byte[] body = Util.readEntityBounded(response.getEntity(), Util.MAX_HTTP_RESPONSE_BYTES);
                    statuses.add(processOcspResponse(new ByteArrayInputStream(body), nonce));
                }
            } catch (Exception e) {
                statuses.add(OcspStatus.builder()
                    .result(OcspResult.UNKOWN)
                    .url(entry.getValue().toString())
                    .message(e.getMessage())
                    .build()
                );
            }
        }

        return statuses;
    }

    /**
     * Запрашивает OCSP-ответы для сертификата и возвращает их в DER (полный {@code OCSPResponse}).
     * Для вшивания в XAdES-LT. Ответы со статусом != 0 и ошибки транспорта отбрасываются.
     *
     * @param cert   проверяемый сертификат
     * @param issuer сертификат издателя
     * @return список DER-кодированных {@code OCSPResponse} (может быть пустым)
     */
    public List<byte[]> getRawResponses(CertificateWrapper cert, CertificateWrapper issuer) {
        final List<byte[]> responses = new ArrayList<>();

        if (issuer == null) {
            return responses;
        }

        for (Map.Entry<String, URL> entry : ocspConfiguration.getUrlList().entrySet()) {
            try {
                byte[] nonce = generateOcspNonce();
                OCSPReq request = buildOcspRequest(cert.getX509Certificate().getSerialNumber(), issuer.getX509Certificate(), nonce);

                try (CloseableHttpResponse response = makeRequest(entry.getValue().toString(), request.getEncoded())) {
                    byte[] responseBytes = Util.readEntityBounded(response.getEntity(), Util.MAX_HTTP_RESPONSE_BYTES);

                    if (new OCSPResp(responseBytes).getStatus() == 0) {
                        responses.add(responseBytes);
                    }
                }
            } catch (Exception e) {
                log.warn("OCSP fetch for XAdES-LT failed ({}): {}", entry.getValue(), e.getMessage());
            }
        }

        return responses;
    }

    private OCSPReq buildOcspRequest(BigInteger serialNumber, X509Certificate issuer, byte[] nonce) throws OCSPException {
        final OCSPReqGenerator ocspReqGenerator = new OCSPReqGenerator();
        CertificateID certId = new CertificateID(CertificateID.HASH_SHA256, issuer, serialNumber, kalkanProvider.getName());
        ocspReqGenerator.addRequest(certId);
        Hashtable<Object,Object> ext = new Hashtable<>();
        ext.put(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, new X509Extension(false, new DEROctetString(new DEROctetString(nonce))) {});
        ocspReqGenerator.setRequestExtensions(new X509Extensions(ext));
        return ocspReqGenerator.generate();
    }

    public byte[] generateOcspNonce() {
        byte[] nonce = new byte[8];
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(nonce);

        return nonce;
    }

    private OcspStatus processOcspResponse(InputStream response, byte[] nonce) throws IOException, OCSPException {
        OCSPResp resp = new OCSPResp(response);

        if (resp.getStatus() != 0) {
            return OcspStatus.builder()
                .result(OcspResult.UNKOWN)
                .message("Unknown status")
                .build();
        }

        BasicOCSPResp brep = (BasicOCSPResp) resp.getResponseObject();
        byte[] respNonceExt = brep.getExtensionValue(OCSPObjectIdentifiers.id_pkix_ocsp_nonce.getId());

        if (respNonceExt != null) {
            try (ASN1InputStream asn1In = new ASN1InputStream(respNonceExt)) {
                DERObject derObj = asn1In.readObject();
                byte[] extV = DEROctetString.getInstance(derObj).getOctets();

                try (ASN1InputStream asn2In = new ASN1InputStream(extV)) {
                    derObj = asn2In.readObject();
                }

                if (!Arrays.equals(nonce, DEROctetString.getInstance(derObj).getOctets())) {
                    return OcspStatus.builder()
                        .result(OcspResult.UNKOWN)
                        .message("Nonce aren't equals")
                        .build();
                }
            }
        }

        SingleResp[] singleResps = brep.getResponses();
        SingleResp singleResp = singleResps[0];
        Object status = singleResp.getCertStatus();

        if (status == null) {
            return OcspStatus.builder()
                .result(OcspResult.ACTIVE)
                .message("OK")
                .build();
        } else if (status instanceof RevokedStatus rev) {
            int reason;

            try {
                reason = rev.getRevocationReason();
            } catch (IllegalStateException e) {
                reason = -1;
            }

            return OcspStatus.builder()
                .result(OcspResult.REVOKED)
                .revocationTime(rev.getRevocationTime())
                .revocationReason(reason)
                .message("OK")
                .build();
        }

        return OcspStatus.builder()
            .result(OcspResult.UNKOWN)
            .message("Unknown status")
            .build();
    }

    private CloseableHttpResponse makeRequest(String url, byte[] data) throws IOException {
        final HttpPost httpRequest = new HttpPost(url);
        httpRequest.addHeader("Content-Type", "application/ocsp-request");
        httpRequest.setEntity(new ByteArrayEntity(data));

        return client.execute(httpRequest);
    }
}

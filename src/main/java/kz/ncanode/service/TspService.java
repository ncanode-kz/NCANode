package kz.ncanode.service;

import kz.gov.pki.kalkan.asn1.ASN1Encodable;
import kz.gov.pki.kalkan.asn1.ASN1EncodableVector;
import kz.gov.pki.kalkan.asn1.DERSet;
import kz.gov.pki.kalkan.asn1.cms.Attribute;
import kz.gov.pki.kalkan.asn1.cms.AttributeTable;
import kz.gov.pki.kalkan.asn1.pkcs.PKCSObjectIdentifiers;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.jce.provider.cms.CMSException;
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData;
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformation;
import kz.gov.pki.kalkan.tsp.*;
import kz.ncanode.configuration.TspConfiguration;
import kz.ncanode.exception.TspException;
import kz.ncanode.util.KalkanUtil;
import kz.ncanode.util.Util;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.*;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class TspService {
    private final CloseableHttpClient client;
    private final TspConfiguration tspConfiguration;

    public TimeStampToken create(byte[] data, String hashAlg, String reqPolicy) {
        try {
            // Generate hash
            MessageDigest md = MessageDigest.getInstance(hashAlg, KalkanProvider.PROVIDER_NAME);
            md.update(data);
            byte[] hash = md.digest();

            // Create TSP request
            TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
            reqGen.setCertReq(true);
            reqGen.setReqPolicy(reqPolicy);
            TimeStampRequest request = reqGen.generate(hashAlg, hash, generateNonce());
            byte[] reqData = request.getEncoded();

            int retries = 0;
            int maxRetries = Math.max(1, tspConfiguration.getRetries());
            RuntimeException lastException = null;

            while (retries < maxRetries) {
                try {
                    TimeStampResponse response = makeRequest(reqData);
                    response.validate(request);

                    return response.getTimeStampToken();
                } catch (RuntimeException e) {
                    lastException = e;
                    retries++;
                }
            }

            throw lastException;
        } catch (GeneralSecurityException|IOException|TSPException e) {
            log.error("TSP creation failure.", e);
            throw new TspException("TSP creation failure", e);
        }
    }

    public Optional<TimeStampTokenInfo> info(CMSSignedData data) {
        try {
            TimeStampToken tspt = new TimeStampToken(data);
            X509CertSelector signerConstraints = tspt.getSID();
            CertStore certs = data.getCertificatesAndCRLs("Collection", KalkanProvider.PROVIDER_NAME);
            Collection<?> certCollection = certs.getCertificates(signerConstraints);
            Iterator<?> certIt = certCollection.iterator();

            if (!certIt.hasNext()) {
                return Optional.empty();
            }

            X509Certificate cert = (X509Certificate) certIt.next();
            tspt.validate(cert, KalkanProvider.PROVIDER_NAME);

            return Optional.of(tspt.getTimeStampInfo());
        } catch (TSPException | IOException | NoSuchProviderException | NoSuchAlgorithmException | CMSException | CertificateExpiredException | CertStoreException | CertificateNotYetValidException e) {
            log.error("TSP verification error.", e);
            return Optional.empty();
        }
    }

    public BigInteger generateNonce() {
        return BigInteger.valueOf(System.currentTimeMillis());
    }

    /**
     * Извлекает сертификаты (цепочку TSA) из TimeStampToken — для вшивания в XAdES-LT.
     *
     * @param token метка времени
     * @return список сертификатов (пустой при ошибке)
     */
    public List<X509Certificate> extractCertificates(TimeStampToken token) {
        if (token == null) {
            return List.of();
        }
        try {
            CertStore store = token.getCertificatesAndCRLs("Collection", KalkanProvider.PROVIDER_NAME);
            return store.getCertificates(null).stream()
                .filter(X509Certificate.class::isInstance)
                .map(X509Certificate.class::cast)
                .toList();
        } catch (GeneralSecurityException | CMSException e) {
            log.warn("Cannot extract TSA certificates from timestamp token: {}", e.getMessage());
            return List.of();
        }
    }

    public SignerInformation addTspToSigner(SignerInformation signer, X509Certificate cert, String useTsaPolicy) throws NoSuchAlgorithmException, NoSuchProviderException, TSPException, IOException {
        AttributeTable unsignedAttributes = signer.getUnsignedAttributes();
        ASN1EncodableVector vector = new ASN1EncodableVector();

        if (unsignedAttributes != null) {
            vector = unsignedAttributes.toASN1EncodableVector();
        }

        TimeStampToken tsp = create(signer.getSignature(), KalkanUtil.getTspHashAlgorithmByOid(cert.getSigAlgOID()), useTsaPolicy);
        byte[] ts = tsp.getEncoded();
        ASN1Encodable signatureTimeStamp = new Attribute(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken, new DERSet(Util.byteToASN1(ts)));
        vector.add(signatureTimeStamp);

        return SignerInformation.replaceUnsignedAttributes(signer, new AttributeTable(vector));
    }

    private TimeStampResponse makeRequest(byte[] request) {
        URL url = tspConfiguration.getParsedUrl().orElseThrow(() -> {
            log.error("Invalid TSP url");
            return new TspException("Invalid tsp url");
        });

        HttpPost httpPost = new HttpPost(url.toString());
        httpPost.setHeader("Content-Type", "application/timestamp-query");
        httpPost.setEntity(new ByteArrayEntity(request));

        try (CloseableHttpResponse response = client.execute(httpPost)) {
            int statusCode = response.getStatusLine().getStatusCode();

            if (statusCode != HttpStatus.SC_OK) {
                log.error("Invalid TSP response status: {}", statusCode);
                throw new TspException(String.format("Invalid TSP response status: %d", statusCode));
            }

            return new TimeStampResponse(response.getEntity().getContent());
        } catch (IOException | TSPException e) {
            throw new TspException("TSP request failure.", e);
        }
    }
}

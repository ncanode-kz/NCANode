package kz.ncanode.service;

import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.ncanode.constants.MessageConstants;
import kz.ncanode.dto.certificate.CertificateInfo;
import kz.ncanode.dto.certificate.CertificateRevocation;
import kz.ncanode.dto.request.Pkcs12InfoRequest;
import kz.ncanode.dto.request.SbaSignRequest;
import kz.ncanode.dto.response.SbaSignResponse;
import kz.ncanode.dto.response.VerificationResponse;
import kz.ncanode.dto.ades.AdesValidationData;
import kz.ncanode.exception.ClientException;
import kz.ncanode.exception.ServerException;
import kz.ncanode.wrapper.CertificateWrapper;
import kz.ncanode.wrapper.KalkanWrapper;
import lombok.RequiredArgsConstructor;
import lombok.val;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

@Service
@RequiredArgsConstructor
public class CertificateService {
    public final CrlService crlService;
    public final OcspService ocspService;
    public final CaService caService;
    public final KalkanWrapper kalkanWrapper;

    public void attachValidationData(final CertificateWrapper cert, boolean checkOcsp, boolean checkCrl) {
        cert.setIssuerCertificate(caService.getRootCertificateFor(cert).orElse(null));
        cert.setOcspStatus(checkOcsp ? ocspService.verify(cert, cert.getIssuerCertificate()) : null);
        cert.setCrlStatus(checkCrl ? crlService.verify(cert) : null);
    }

    public Date getCurrentDate() {
        return new Date();
    }

    /**
     * Собирает материал для AdES-LT: полную цепочку сертификатов подписанта (+ сертификаты TSA)
     * и данные отзыва (OCSP для конечного сертификата, CRL для УЦ).
     *
     * @param signer      сертификат подписанта
     * @param extraCerts  дополнительные сертификаты (например, цепочка TSA из метки времени)
     * @return материал для вшивания
     */
    public AdesValidationData collectAdesValidationData(CertificateWrapper signer, List<X509Certificate> extraCerts) {
        final List<CertificateWrapper> chain = caService.buildChain(signer);
        final List<X509Certificate> certificates = new ArrayList<>();
        final List<byte[]> crls = new ArrayList<>();
        final List<byte[]> ocsps = new ArrayList<>();

        chain.forEach(c -> addDistinct(certificates, c.getX509Certificate()));
        extraCerts.forEach(c -> addDistinct(certificates, c));

        // Конечный сертификат: OCSP, при неудаче — CRL.
        final CertificateWrapper issuer = chain.size() > 1 ? chain.get(1) : null;
        final List<byte[]> signerOcsp = ocspService.getRawResponses(signer, issuer);

        if (!signerOcsp.isEmpty()) {
            signerOcsp.forEach(o -> addDistinct(ocsps, o));
        } else {
            crlService.getEncodedCrlsFor(signer.getX509Certificate()).forEach(c -> addDistinct(crls, c));
        }

        // Промежуточные УЦ (без корня): CRL из кэша.
        for (int i = 1; i < chain.size(); i++) {
            final CertificateWrapper ca = chain.get(i);

            if (ca.getIssuerX500Principal().equals(ca.getSubjectX500Principal())) {
                continue;
            }

            crlService.getEncodedCrlsFor(ca.getX509Certificate()).forEach(c -> addDistinct(crls, c));
        }

        // Сертификаты TSA (best-effort): CRL их издателя.
        for (final X509Certificate tsa : extraCerts) {
            if (tsa.getIssuerX500Principal().equals(tsa.getSubjectX500Principal())) {
                continue;
            }

            crlService.getEncodedCrlsFor(tsa).forEach(c -> addDistinct(crls, c));
        }

        final AdesValidationData data = new AdesValidationData(certificates, crls, ocsps);

        if (!data.hasRevocation()) {
            throw new ClientException("Cannot build AdES-LT: no OCSP or CRL data available for the signer chain. "
                + "Configure NCANODE_OCSP_URL / NCANODE_CRL_URL / NCANODE_CA_CRL_URL.");
        }

        return data;
    }

    private static void addDistinct(List<byte[]> list, byte[] value) {
        if (list.stream().noneMatch(existing -> Arrays.equals(existing, value))) {
            list.add(value);
        }
    }

    private static void addDistinct(List<X509Certificate> list, X509Certificate value) {
        try {
            final byte[] encoded = value.getEncoded();
            for (final X509Certificate existing : list) {
                if (Arrays.equals(existing.getEncoded(), encoded)) {
                    return;
                }
            }
            list.add(value);
        } catch (CertificateException e) {
            list.add(value);
        }
    }

    public VerificationResponse verifyCerts(Pkcs12InfoRequest request) {
        var valid = true;
        val date = getCurrentDate();
        val withOcsp = request.getRevocationCheck().contains(CertificateRevocation.OCSP);
        val withCrl = request.getRevocationCheck().contains(CertificateRevocation.CRL);

        val keys = Optional.of(request.getKeys()).map(kalkanWrapper::read).orElseThrow();
        val certs = new ArrayList<CertificateInfo>();

        for (var key : keys) {
            val cert = key.getCertificate();

            attachValidationData(cert, withOcsp, withCrl);

            if (!cert.isValid(date, withOcsp, withCrl)) {
                valid = false;
            }

            certs.add(cert.toCertificateInfo(date, withOcsp, withCrl));
        }

        return VerificationResponse.builder()
            .valid(valid)
            .signers(certs)
            .build();
    }

    public VerificationResponse info(List<String> certsBase64, boolean checkOcsp, boolean checkCrl) {
        try {
            var valid = true;
            val currentDate = getCurrentDate();
            val certs = new ArrayList<CertificateInfo>();

            var message = "OK";
            var i = 0;

            for (String certBase64 : certsBase64) {
                var x509 = load(Base64.getDecoder().decode(certBase64.replaceAll("\\s", "")));

                if (x509 == null) {
                    message = String.format(MessageConstants.CERT_INVALID, i);
                    certs.add(null);
                    ++i;
                    valid = false;
                    continue;
                }

                val cert = new CertificateWrapper(x509);

                attachValidationData(cert, checkOcsp, checkCrl);

                if (!cert.isValid(currentDate, checkOcsp, checkCrl)) {
                    valid = false;
                }

                certs.add(cert.toCertificateInfo(currentDate, checkOcsp, checkCrl));
                ++i;
            }

            if (certsBase64.isEmpty()) {
                valid = false;
            }

            return VerificationResponse.builder()
                .valid(valid)
                .signers(certs)
                .message(message)
                .build();
        } catch (CertificateException|NoSuchProviderException|IOException e) {
            throw new ServerException(e.getMessage(), e);
        }
    }

    public VerificationResponse verify(String certBase64, String signature, String data, boolean checkOcsp, boolean checkCrl) {
        try {
            var valid = true;
            val currentDate = getCurrentDate();
            val certs = new ArrayList<CertificateInfo>();

            var message = "OK";

            var x509 = load(Base64.getDecoder().decode(certBase64.replaceAll("\\s", "")));

            if (x509 == null) {
                message = String.format(MessageConstants.CERT_INVALID, 0);
                certs.add(null);
                valid = false;
                return VerificationResponse.builder()
                    .valid(valid)
                    .signers(certs)
                    .message(message)
                    .build();
            }

            byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);
            byte[] signatureBytes = Base64.getDecoder().decode(signature);

            PublicKey publicKey = x509.getPublicKey();

            //System.out.println("Signature Algorithm: " + x509.getSigAlgName());

            //Signature sig = Signature.getInstance("ECGOST3410-2015-512");
            //Signature sig = Signature.getInstance("SHA256withRSA");
            Signature sig = Signature.getInstance(x509.getSigAlgName());

            //System.out.println("Алгоритм: " + sig.getAlgorithm());
            sig.initVerify(publicKey);

            //System.out.println("Ключ инициализирован");

            sig.update(dataBytes);

            valid = sig.verify(signatureBytes);
            //System.out.println("Подпись корректна? " + valid);

            val cert = new CertificateWrapper(x509);

            attachValidationData(cert, checkOcsp, checkCrl);

            if (!cert.isValid(currentDate, checkOcsp, checkCrl)) {
                valid = false;
            }

            certs.add(cert.toCertificateInfo(currentDate, checkOcsp, checkCrl));

            return VerificationResponse.builder()
                .valid(valid)
                .signers(certs)
                .message(message)
                .build();
        } catch (CertificateException | NoSuchProviderException | IOException | SignatureException | NoSuchAlgorithmException | InvalidKeyException e) {
            throw new ServerException(e.getMessage(), e);
        }
    }

    public static X509Certificate load(byte[] cert) throws CertificateException, NoSuchProviderException, IOException {
        try (ByteArrayInputStream stream = new ByteArrayInputStream(cert)) {
            return (X509Certificate)java.security.cert.CertificateFactory.getInstance("X.509", KalkanProvider.PROVIDER_NAME).generateCertificate(stream);
        }
    }

    public SbaSignResponse create(SbaSignRequest sbaSignRequest) {
        try {
            String keyBase64 = sbaSignRequest.getSigner().getKey();
            //System.out.println("keyBase64: " + keyBase64);

            byte[] keyBytes = Base64.getDecoder().decode(
                keyBase64.replaceAll("\\s", ""));

            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (ByteArrayInputStream is = new ByteArrayInputStream(keyBytes)) {
                keyStore.load(is, sbaSignRequest.getSigner().getPassword().toCharArray());
            }

            String alias = sbaSignRequest.getSigner().getKeyAlias();

            if (alias == null || alias.isBlank()) {
                Enumeration<String> aliases = keyStore.aliases();

                while (aliases.hasMoreElements()) {
                    String current = aliases.nextElement();
                    if (keyStore.isKeyEntry(current)) {
                        alias = current;
                        break;
                    }
                }
            }

            if (alias == null) {
                throw new ServerException("Private key not found in PKCS12");
            }

            PrivateKey privateKey = (PrivateKey) keyStore.getKey(
                alias,
                sbaSignRequest.getSigner().getPassword().toCharArray());

            X509Certificate certificate =
                (X509Certificate) keyStore.getCertificate(alias);

            Signature signature = Signature.getInstance(certificate.getSigAlgName());

            signature.initSign(privateKey);
            signature.update(sbaSignRequest.getData().getBytes(StandardCharsets.UTF_8));

            byte[] signBytes = signature.sign();

            return SbaSignResponse.builder()
                .certificate(Base64.getEncoder().encodeToString(certificate.getEncoded()))
                .signature(Base64.getEncoder().encodeToString(signBytes))
                .build();
        } catch (Exception e) {
            throw new ServerException(e.getMessage(), e);
        }
    }
}

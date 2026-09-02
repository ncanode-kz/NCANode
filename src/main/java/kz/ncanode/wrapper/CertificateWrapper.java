package kz.ncanode.wrapper;

import kz.gov.pki.kalkan.asn1.DERIA5String;
import kz.gov.pki.kalkan.asn1.x509.*;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.x509.extension.X509ExtensionUtil;
import kz.ncanode.dto.certificate.*;
import kz.ncanode.dto.crl.CrlResult;
import kz.ncanode.dto.crl.CrlStatus;
import kz.ncanode.dto.ocsp.OcspStatus;
import kz.ncanode.util.KalkanUtil;
import kz.ncanode.util.Util;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.bouncycastle.asn1.x509.Extension;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.net.URL;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
public class CertificateWrapper {

    @Getter
    private final X509Certificate x509Certificate;

    @Getter
    @Setter
    private CertificateWrapper issuerCertificate;

    @Getter
    @Setter
    private List<OcspStatus> ocspStatus;

    @Getter
    @Setter
    private CrlStatus crlStatus;

    private final String[] signAlg;

    public CertificateWrapper(X509Certificate certificate) {
        Objects.requireNonNull(certificate);
        x509Certificate = certificate;
        signAlg = KalkanUtil.getSignMethodByOID(x509Certificate.getSigAlgOID());
    }

    /**
     * Возвращает ID алгоритма подписи
     *
     * @return String
     */
    public String getSignAlgorithmId() {
        return signAlg[0];
    }

    /**
     * Возвращает ID алгоритма хэширования
     *
     * @return String
     */
    public String getHashAlgorithmId() {
        return signAlg[1];
    }

    /**
     * Создает объект CertificateInfo
     * @return CertificateInfo
     */
    public CertificateInfo toCertificateInfo(Date date ,boolean checkOcsp, boolean checkCrl) {
        final X509Certificate cert = getX509Certificate();

        val revocations = new ArrayList<CertificateRevocationStatus>();

        if (crlStatus != null) {
            revocations.add(crlStatus.toCertificateRevocationStatus());
        }

        if (ocspStatus != null) {
            revocations.addAll(ocspStatus.stream().map(OcspStatus::toCertificateRevocationStatus).toList());
        }

        return CertificateInfo.builder()
            .valid(isValid(date, checkOcsp, checkCrl))
            .revocations(revocations)
            .notBefore(cert.getNotBefore())
            .notAfter(cert.getNotAfter())
            .keyUsage(CertificateKeyUsage.fromKeyUsageBits(cert.getKeyUsage()))
            .serialNumber(cert.getSerialNumber().toString(16))
            .signAlg(cert.getSigAlgName())
            .keyUser(getKeyUser())
            .publicKey(new String(Base64.getEncoder().encode(cert.getPublicKey().getEncoded())))
            .signature(new String(Base64.getEncoder().encode(cert.getSignature())))
            .subject(createCertificateSubjectFromDn(cert.getSubjectX500Principal().toString()).orElse(null))
            .issuer(createCertificateSubjectFromDn(cert.getIssuerX500Principal().toString()).orElse(null))
            .build();

    }

    /**
     * Получает список CRL из сертификата
     *
     * @return
     */
    public List<URL> getCrlList() {
        byte[] crlDistributionPoint = getX509Certificate().getExtensionValue(Extension.cRLDistributionPoints.getId());
        CRLDistPoint distPoint = null;

        if (crlDistributionPoint == null) {
            return Collections.emptyList();
        }

        try {
            distPoint = CRLDistPoint.getInstance(X509ExtensionUtil.fromExtensionValue(crlDistributionPoint));
        } catch (IOException e) {
            return Collections.emptyList();
        }

        List<String> crls = new ArrayList<>();

        for (DistributionPoint dp : distPoint.getDistributionPoints()) {
            DistributionPointName dpn = dp.getDistributionPoint();

            if (dpn != null) {
                if (dpn.getType() == DistributionPointName.FULL_NAME) {
                    GeneralName[] genNames = GeneralNames.getInstance(dpn.getName()).getNames();
                    // Look for an URI
                    for (int j = 0; j < genNames.length; j++) {
                        if (genNames[j].getTagNo() == GeneralName.uniformResourceIdentifier) {
                            String url = DERIA5String.getInstance(genNames[j].getName()).getString();
                            crls.add(url);
                        }
                    }
                }
            }
        }

        return crls.stream().map(u -> Util.createNewUrl(u, log)).filter(Objects::nonNull).toList();
    }

    /**
     * Метод для валидации сертификата
     *
     * @param checkOcsp
     * @param checkCrl
     * @return
     */
    public boolean isValid(Date date, boolean checkOcsp, boolean checkCrl) {
        return isDateValid(date)
            && issuerCertificate != null
            && issuerCertificate.isDateValid(date)
            && (!checkOcsp || (ocspStatus != null && ocspStatus.stream().allMatch(OcspStatus::isActive)))
            && (!checkCrl || (crlStatus != null && crlStatus.getResult().equals(CrlResult.ACTIVE)));
    }

    public boolean isDateValid() {
        return isDateValid(new Date());
    }

    public boolean isDateValid(Date date) {
        return date.after(x509Certificate.getNotBefore()) && date.before(x509Certificate.getNotAfter());
    }

    public X500Principal getIssuerX500Principal() {
        return x509Certificate.getIssuerX500Principal();
    }

    public X500Principal getSubjectX500Principal() {
        return x509Certificate.getSubjectX500Principal();
    }

    public boolean verify(PublicKey key) {
        try {
            x509Certificate.verify(key);
            return true;
        } catch (CertificateException|NoSuchAlgorithmException|SignatureException|InvalidKeyException|NoSuchProviderException e) {
            return false;
        }
    }

    public PublicKey getPublicKey() {
        return x509Certificate.getPublicKey();
    }

    public List<String> getExtendedKeyUsage() {
        try {
            // getExtendedKeyUsage() возвращает null, если расширения EKU в сертификате нет
            return Optional.ofNullable(getX509Certificate().getExtendedKeyUsage()).orElse(Collections.emptyList());
        } catch (CertificateParsingException e) {
            log.error("Certificate key user extracting error", e);
            return Collections.emptyList();
        }
    }

    private Set<CertificateKeyUser> getKeyUser() {
        return getExtendedKeyUsage().stream()
            .map(CertificateKeyUser::fromOID)
            .filter(Optional::isPresent)
            .map(Optional::get)
            .collect(Collectors.toSet());
    }

    public static Optional<CertificateWrapper> fromBase64(final String encodedCert) {
        return fromBytes(Base64.getDecoder().decode(encodedCert.replaceAll("\\s", "")));
    }

    public static Optional<CertificateWrapper> fromBytes(final byte[] encodedCert) {
        try (ByteArrayInputStream inputStream = new ByteArrayInputStream(encodedCert)) {
            return fromInputStream(inputStream);
        } catch (IOException e) {
            return Optional.empty();
        }
    }

    public static Optional<CertificateWrapper> fromInputStream(final InputStream inputStream) {
        try {
            // generateCertificate может вернуть null на пустом/мусорном вводе, не бросив исключение
            final var cert = (X509Certificate) CertificateFactory.getInstance("X.509", KalkanProvider.PROVIDER_NAME)
                .generateCertificate(inputStream);
            return Optional.ofNullable(cert).map(CertificateWrapper::new);
        } catch (CertificateException|NoSuchProviderException e) {
            return Optional.empty();
        }
    }

    public static Optional<CertificateWrapper> fromFile(final File file) {
        try {
            return fromInputStream(new FileInputStream(file));
        } catch (FileNotFoundException e) {
            return Optional.empty();
        }
    }

    private static Optional<CertificateSubject> createCertificateSubjectFromDn(String dn) {
        try {
            final LdapName ldapName = new LdapName(dn);
            var subjectBuilder = CertificateSubject.builder();

            for (Rdn rdn : ldapName.getRdns()) {
                if (rdn.getType().equalsIgnoreCase("CN")) {
                    subjectBuilder.commonName((String)rdn.getValue());
                } else if (rdn.getType().equalsIgnoreCase("SURNAME")) {
                    subjectBuilder.surName((String)rdn.getValue());
                } else if (rdn.getType().equalsIgnoreCase("SERIALNUMBER")) {

                    String sn = ((String) rdn.getValue());

                    if (sn.startsWith("BIN")) {
                        subjectBuilder.bin(((String) rdn.getValue()).replaceAll("^BIN", ""));
                    } else {
                        subjectBuilder.iin(((String) rdn.getValue()).replaceAll("^IIN", ""));
                    }
                } else if (rdn.getType().equalsIgnoreCase("C")) {
                    subjectBuilder.country((String)rdn.getValue());
                } else if (rdn.getType().equalsIgnoreCase("L")) {
                    subjectBuilder.locality((String)rdn.getValue());
                } else if (rdn.getType().equalsIgnoreCase("S")) {
                    subjectBuilder.state((String)rdn.getValue());
                } else if ((rdn.getType().equalsIgnoreCase("E")) || (rdn.getType().equalsIgnoreCase("EMAILADDRESS"))) {
                    subjectBuilder.email((String)rdn.getValue());
                } else if (rdn.getType().equalsIgnoreCase("O")) {
                    subjectBuilder.organization((String)rdn.getValue());
                } else if (rdn.getType().equalsIgnoreCase("OU")) {
                    subjectBuilder.bin(((String) rdn.getValue()).replaceAll("^BIN", ""));
                } else if (rdn.getType().equalsIgnoreCase("G")) {
                    subjectBuilder.lastName((String)rdn.getValue());
                }


            }

            subjectBuilder.dn(dn);

            return Optional.of(subjectBuilder.build());
        } catch (InvalidNameException e) {
            log.warn("Distinguished name parsing error", e);
            return Optional.empty();
        }
    }
}

package kz.ncanode.util;

import kz.gov.pki.kalkan.asn1.DERSet;
import kz.gov.pki.kalkan.asn1.cms.Attribute;
import kz.gov.pki.kalkan.asn1.ess.ESSCertIDv2;
import kz.gov.pki.kalkan.asn1.ess.SigningCertificateV2;
import kz.gov.pki.kalkan.asn1.pkcs.PKCSObjectIdentifiers;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedDataGenerator;
import kz.gov.pki.kalkan.tsp.TSPAlgorithms;
import lombok.experimental.UtilityClass;
import org.apache.xml.security.encryption.XMLCipherParameters;
import org.apache.xml.security.utils.Constants;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.HashMap;

/**
 * Вспомогательные методы для работы с KalkanCrypt
 */
@UtilityClass
public class KalkanUtil {
    public final static String GOST3410_256_2015 = "1.2.398.3.10.1.1.2.3.1";
    public final static String GOST3410_512_2015 = "1.2.398.3.10.1.1.2.3.2";

    /**
     * Метод возвращает алгоритм подписи по OID.
     *
     * @param oid OID
     * @return Массив с двумя элементами (Первый = Алгоритм подписи, второй = Алгоритм хэширования)
     */
    public static String[] getSignMethodByOID(String oid) {

        String[] ret = new String[2];

        if (oid.equals(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId())) {
            ret[0] = Constants.MoreAlgorithmsSpecNS + "rsa-sha1";
            ret[1] = Constants.MoreAlgorithmsSpecNS + "sha1";
        } else if (oid.equals(PKCSObjectIdentifiers.sha256WithRSAEncryption.getId())) {
            ret[0] = Constants.MoreAlgorithmsSpecNS + "rsa-sha256";
            ret[1] = XMLCipherParameters.SHA256;
        } else if (oid.equals(GOST3410_512_2015)) { // GOST3410-2015 512
            ret[0] = "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-512";
            ret[1] = "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-512";
        } else if (oid.equals(GOST3410_256_2015)) { // GOST3410-2015 256
            ret[0] = "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-256";
            ret[1] = "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-256";
        } else {
            ret[0] = Constants.MoreAlgorithmsSpecNS + "gost34310-gost34311";
            ret[1] = Constants.MoreAlgorithmsSpecNS + "gost34311";
        }

        return ret;
    }

    /**
     * Возвращает алгоритм хэширования по алгоритму подписи.
     *
     * @param signOid sign OID
     * @return digest algorithm OID
     */
    public static String getDigestAlgorithmOidBYSignAlgorithmOid(String signOid) {
        if (signOid.equals(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId())) {
            return CMSSignedDataGenerator.DIGEST_SHA1;
        } else if (signOid.equals(PKCSObjectIdentifiers.sha256WithRSAEncryption.getId())) {
            return CMSSignedDataGenerator.DIGEST_SHA256;
        } else {
            return CMSSignedDataGenerator.DIGEST_GOST34311_95;
        }
    }

    /**
     * Возвращает алгоритм подписи по OID.
     *
     * @param signOid ObjectID
     * @return Algorithm name
     */
    public static String getTspHashAlgorithmByOid(String signOid) {
        if (signOid.equals(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId())) {
            return TSPAlgorithms.SHA1;
        }
        else if (signOid.equals(PKCSObjectIdentifiers.sha256WithRSAEncryption.getId())) {
            return TSPAlgorithms.SHA256;
        }
        else {
            return TSPAlgorithms.GOST34311;
        }
    }

    /**
     * JCA-имя (или OID) алгоритма хэширования по XML-URI из {@code ds:DigestMethod}.
     * Нужно для вычисления {@code xades:CertDigest} в SigningCertificateV2.
     *
     * @param xmlDigestUri URI алгоритма хэширования
     * @return имя алгоритма для {@link java.security.MessageDigest#getInstance(String, String)}
     */
    public static String getDigestJcaNameByXmlUri(String xmlDigestUri) {
        return switch (xmlDigestUri) {
            case "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-512" -> "1.2.398.3.10.1.3.3";
            case "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-256" -> "1.2.398.3.10.1.3.2";
            case "http://www.w3.org/2001/04/xmlenc#sha256" -> "SHA-256";
            case "http://www.w3.org/2001/04/xmldsig-more#sha1" -> "SHA-1";
            default -> "GOST34311";
        };
    }

    /**
     * OID алгоритма хэширования для message imprint метки времени XAdES-T,
     * подобранный под алгоритм ключа подписанта.
     *
     * @param certSignAlgOid OID алгоритма подписи сертификата
     * @return OID/имя алгоритма хэширования для {@link kz.ncanode.service.TspService#create}
     */
    public static String getXadesTspImprintDigest(String certSignAlgOid) {
        if (certSignAlgOid.equals(GOST3410_512_2015)) {
            return "1.2.398.3.10.1.3.3";
        } else if (certSignAlgOid.equals(GOST3410_256_2015)) {
            return "1.2.398.3.10.1.3.2";
        } else if (certSignAlgOid.equals(PKCSObjectIdentifiers.sha256WithRSAEncryption.getId())) {
            return TSPAlgorithms.SHA256;
        } else if (certSignAlgOid.equals(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId())) {
            return TSPAlgorithms.SHA1;
        } else {
            return TSPAlgorithms.GOST34311;
        }
    }

    /**
     * OID алгоритма хэширования message imprint для метки времени под политику TSA.
     *
     * @param tsaPolicyOid OID политики TSA
     * @return OID алгоритма хэширования
     */
    public static String getTspImprintDigestForPolicy(String tsaPolicyOid) {
        if ("1.2.398.3.3.2.6.4".equals(tsaPolicyOid)) { // tsa_gost2015_policy
            return "1.2.398.3.10.1.3.3"; // gost3411-2015-512
        }
        return TSPAlgorithms.GOST34311; // gost34311-95
    }

    /**
     * Обязательный signed-атрибут CAdES/PAdES-B: {@code id-aa-signingCertificateV2}
     * (ESSCertIDv2 с SHA-256 хэшем сертификата).
     */
    public static Attribute signingCertificateV2Attribute(X509Certificate certificate) {
        try {
            byte[] certHash = MessageDigest.getInstance("SHA-256", KalkanProvider.PROVIDER_NAME)
                .digest(certificate.getEncoded());
            return new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificateV2,
                new DERSet(new SigningCertificateV2(new ESSCertIDv2[]{new ESSCertIDv2(null, certHash)})));
        } catch (Exception e) {
            throw new IllegalStateException("Cannot build signingCertificateV2 attribute", e);
        }
    }

    /**
     * Проверяет, что хеш сертификата в {@code id-aa-signingCertificateV2} подписанта совпадает
     * с {@code certificate}. Если атрибута нет — {@code true} (проверить нечего).
     */
    public static boolean signingCertificateV2HashMatches(
            kz.gov.pki.kalkan.jce.provider.cms.SignerInformation signer, java.security.cert.X509Certificate certificate) {
        if (signer == null || certificate == null || signer.getSignedAttributes() == null) {
            return true;
        }
        var attr = signer.getSignedAttributes().get(PKCSObjectIdentifiers.id_aa_signingCertificateV2);
        if (attr == null) {
            return true;
        }
        try {
            var essId = SigningCertificateV2.getInstance(attr.getAttrValues().getObjectAt(0)).getCerts()[0];
            byte[] actual = MessageDigest.getInstance("SHA-256", KalkanProvider.PROVIDER_NAME)
                .digest(certificate.getEncoded());
            return java.util.Arrays.equals(essId.getCertHash(), actual);
        } catch (Exception e) {
            return false;
        }
    }

    public static String getHashingAlgorithmByOID(String oid) {
        HashMap<String, String> algos = new HashMap<>();

        algos.put(TSPAlgorithms.MD5,"MD5");
        algos.put(TSPAlgorithms.SHA1,"SHA1");
        algos.put(TSPAlgorithms.SHA224,"SHA224");
        algos.put(TSPAlgorithms.SHA256,"SHA256");
        algos.put(TSPAlgorithms.SHA384,"SHA384");
        algos.put(TSPAlgorithms.SHA512,"SHA512");
        algos.put(TSPAlgorithms.RIPEMD128,"RIPEMD128");
        algos.put(TSPAlgorithms.RIPEMD160,"RIPEMD160");
        algos.put(TSPAlgorithms.RIPEMD256,"RIPEMD256");
        algos.put(TSPAlgorithms.GOST34311GT,"GOST34311GT");
        algos.put(TSPAlgorithms.GOST34311,"GOST34311");

        return algos.get(oid);
    }
}

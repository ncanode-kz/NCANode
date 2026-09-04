package kz.ncanode.util;

import kz.gov.pki.kalkan.asn1.ASN1InputStream;
import kz.gov.pki.kalkan.asn1.DERObject;
import kz.gov.pki.kalkan.asn1.pkcs.PKCSObjectIdentifiers;
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedDataGenerator;
import lombok.experimental.UtilityClass;
import lombok.val;
import org.apache.http.HttpEntity;
import org.slf4j.Logger;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@UtilityClass
public class Util {

    public static String sha1(String data)
    {
        String sha1 = "";
        try
        {
            MessageDigest crypt = MessageDigest.getInstance("SHA-1");
            crypt.reset();
            crypt.update(data.getBytes(StandardCharsets.UTF_8));
            sha1 = bytesToHex(crypt.digest());
        }
        catch(NoSuchAlgorithmException e)
        {
            e.printStackTrace();
        }

        return sha1;
    }

    public static String bytesToHex(byte[] bytes) {
        char[] hexArray = "0123456789ABCDEF".toCharArray();

        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static URL createNewUrl(String url, Logger log) {
        try {
            return new URL(url);
        } catch (MalformedURLException e) {
            log.warn("Cannot parse url '{}'", url, e);
            return null;
        }
    }

    public static Map<String, URL> urlMap(final String url, Logger log) {
        if (url == null || url.isBlank()) {
            return Collections.emptyMap();
        }

        return Arrays.stream(url.split("\\s+"))
            .map(u -> createNewUrl(u, log))
            .filter(Objects::nonNull)
            .collect(Collectors.toMap(
                u -> Util.sha1(u.toString()),
                Function.identity()
            ));
    }

    public static DERObject byteToASN1(byte[] data) throws IOException {
        try (ASN1InputStream in = new ASN1InputStream(data))
        {
            return in.readObject();
        }
    }

    public static String getDigestAlgorithmOidBYSignAlgorithmOid(String signOid) {
        if (signOid.equals(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId())) {
            return CMSSignedDataGenerator.DIGEST_SHA1;
        }
        else if (signOid.equals(PKCSObjectIdentifiers.sha256WithRSAEncryption.getId())) {
            return CMSSignedDataGenerator.DIGEST_SHA256;
        }
        else if (signOid.equals("1.2.398.3.10.1.1.2.3.1")) { // GOST2015-256
            return CMSSignedDataGenerator.DIGEST_GOST3411_2015_256;
        }
        else if (signOid.equals("1.2.398.3.10.1.1.2.3.2")) { // GOST2015-512
            return CMSSignedDataGenerator.DIGEST_GOST3411_2015_512;
        }
        else {
            return CMSSignedDataGenerator.DIGEST_GOST34311_95;
        }
    }

    /** Потолок размера ответа для OCSP / TSP / CA — эти ответы измеряются килобайтами. */
    public static final long MAX_HTTP_RESPONSE_BYTES = 8L << 20;
    /** Потолок размера скачиваемого CRL. Боевой GOST-CRL ~20 МБ, здесь ~6x запаса. */
    public static final long MAX_CRL_DOWNLOAD_BYTES = 128L << 20;

    /**
     * Читает тело HTTP-ответа в память с ограничением размера. Объявленный сверх лимита
     * {@code Content-Length} отвергается до чтения тела.
     */
    public static byte[] readEntityBounded(HttpEntity entity, long maxBytes) throws IOException {
        if (entity.getContentLength() > maxBytes) {
            throw new IOException("Response too large: Content-Length " + entity.getContentLength() + " > limit " + maxBytes);
        }

        try (InputStream in = entity.getContent()) {
            byte[] data = in.readNBytes((int) Math.min(maxBytes + 1, Integer.MAX_VALUE));

            if (data.length > maxBytes) {
                throw new IOException("Response too large: exceeded limit " + maxBytes + " bytes");
            }

            return data;
        }
    }

    /**
     * Потоково копирует тело HTTP-ответа в {@code out}, обрывая обмен на превышении лимита.
     * Память при этом не растёт (буфер 64 КБ).
     */
    public static void copyEntityBounded(HttpEntity entity, OutputStream out, long maxBytes) throws IOException {
        if (entity.getContentLength() > maxBytes) {
            throw new IOException("Response too large: Content-Length " + entity.getContentLength() + " > limit " + maxBytes);
        }

        try (InputStream in = entity.getContent()) {
            byte[] buf = new byte[64 * 1024];
            long total = 0;
            int n;

            while ((n = in.read(buf)) != -1) {
                total += n;

                if (total > maxBytes) {
                    throw new IOException("Response too large: exceeded limit " + maxBytes + " bytes");
                }

                out.write(buf, 0, n);
            }
        }
    }

    public static List<String> findAllUrls(String str) {
        Pattern p = Pattern.compile("https?://[^\s]+", Pattern.CASE_INSENSITIVE);
        val matcher = p.matcher(str);

        List<String> urls = new ArrayList<>();

        while (matcher.find()) {
            urls.add(str.substring(matcher.start(), matcher.end()));
        }

        return urls;
    }
}

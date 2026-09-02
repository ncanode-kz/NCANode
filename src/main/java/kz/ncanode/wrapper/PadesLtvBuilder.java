package kz.ncanode.wrapper;

import kz.ncanode.dto.ades.AdesValidationData;
import kz.ncanode.exception.ServerException;
import lombok.extern.slf4j.Slf4j;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSStream;
import org.apache.pdfbox.pdmodel.PDDocument;

import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Пишет в каталог PDF словарь {@code /DSS} (Document Security Store) + {@code /VRI}
 * для профилей PAdES-LT / LTA — сертификаты, CRL и OCSP-ответы, нужные для проверки
 * подписей без обращения к сети (ETSI EN 319 142-1, PDF 2.0 §12.8.4.4).
 *
 * <p>Ссылки {@code /Certs}, {@code /CRLs}, {@code /OCSPs} — глобальные (все артефакты документа);
 * {@code /VRI/<hex SHA-1 подписи>} — что относится к конкретной подписи.
 */
@Slf4j
public class PadesLtvBuilder {

    private final PDDocument document;
    private final COSArray certs = new COSArray();
    private final COSArray crls = new COSArray();
    private final COSArray ocsps = new COSArray();

    /** DER (base64) → уже созданный поток, чтобы не дублировать одинаковые артефакты. */
    private final Map<String, COSStream> certStreams = new LinkedHashMap<>();
    private final Map<String, COSStream> crlStreams = new LinkedHashMap<>();
    private final Map<String, COSStream> ocspStreams = new LinkedHashMap<>();

    private final COSDictionary vri = new COSDictionary();

    public PadesLtvBuilder(PDDocument document) {
        this.document = document;
    }

    /**
     * Регистрирует материал одной подписи.
     *
     * @param vriKey  ключ VRI — SHA-1 от байтов CMS подписи в верхнем hex
     * @param data    цепочка и данные отзыва
     */
    public void addSignature(String vriKey, AdesValidationData data) {
        final COSDictionary vriEntry = new COSDictionary();

        final COSArray sigCerts = new COSArray();
        for (final byte[] cert : encodedCertificates(data)) {
            sigCerts.add(stream(certStreams, certs, cert));
        }
        vriEntry.setItem(COSName.getPDFName("Cert"), sigCerts);

        if (!data.crls().isEmpty()) {
            final COSArray sigCrls = new COSArray();
            for (final byte[] crl : data.crls()) {
                sigCrls.add(stream(crlStreams, crls, crl));
            }
            vriEntry.setItem(COSName.getPDFName("CRL"), sigCrls);
        }

        if (!data.ocsps().isEmpty()) {
            final COSArray sigOcsps = new COSArray();
            for (final byte[] ocsp : data.ocsps()) {
                sigOcsps.add(stream(ocspStreams, ocsps, ocsp));
            }
            vriEntry.setItem(COSName.getPDFName("OCSP"), sigOcsps);
        }

        vriEntry.setNeedToBeUpdated(true);
        vri.setItem(COSName.getPDFName(vriKey), vriEntry);
    }

    /** Записывает {@code /DSS} в каталог документа. Вызывать перед {@code saveIncremental}. */
    public void write() {
        final COSDictionary catalog = document.getDocumentCatalog().getCOSObject();

        final COSDictionary dss = new COSDictionary();
        dss.setItem(COSName.TYPE, COSName.getPDFName("DSS"));
        dss.setItem(COSName.getPDFName("Certs"), certs);
        if (crls.size() > 0) {
            dss.setItem(COSName.getPDFName("CRLs"), crls);
        }
        if (ocsps.size() > 0) {
            dss.setItem(COSName.getPDFName("OCSPs"), ocsps);
        }

        vri.setNeedToBeUpdated(true);
        dss.setItem(COSName.getPDFName("VRI"), vri);
        dss.setNeedToBeUpdated(true);

        catalog.setItem(COSName.getPDFName("DSS"), dss);
        catalog.setNeedToBeUpdated(true);
    }

    private COSStream stream(Map<String, COSStream> cache, COSArray global, byte[] der) {
        return cache.computeIfAbsent(Base64.getEncoder().encodeToString(der), key -> {
            try {
                final COSStream stream = document.getDocument().createCOSStream();
                try (OutputStream out = stream.createOutputStream()) {
                    out.write(der);
                }
                stream.setNeedToBeUpdated(true);
                global.add((COSBase) stream);
                return stream;
            } catch (Exception e) {
                log.error("Cannot create /DSS stream", e);
                throw new ServerException("Cannot create /DSS stream", e);
            }
        });
    }

    private static List<byte[]> encodedCertificates(AdesValidationData data) {
        final List<byte[]> result = new ArrayList<>();
        for (final var certificate : data.certificates()) {
            try {
                result.add(certificate.getEncoded());
            } catch (Exception e) {
                throw new ServerException("Certificate encoding error", e);
            }
        }
        return result;
    }
}

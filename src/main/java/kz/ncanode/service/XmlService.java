package kz.ncanode.service;

import kz.gov.pki.kalkan.tsp.TimeStampToken;
import kz.ncanode.dto.request.SignerRequest;
import kz.ncanode.dto.request.XmlSignRequest;
import kz.ncanode.dto.response.VerificationResponse;
import kz.ncanode.dto.response.XmlSignResponse;
import kz.ncanode.dto.ades.AdesLevel;
import kz.ncanode.dto.certificate.CertificateInfo;
import kz.ncanode.dto.tsp.TsaPolicy;
import kz.ncanode.exception.ClientException;
import kz.ncanode.exception.ServerException;
import kz.ncanode.util.KalkanUtil;
import kz.ncanode.wrapper.*;

import java.io.IOException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.traversal.DocumentTraversal;
import org.w3c.dom.traversal.NodeFilter;
import org.w3c.dom.traversal.NodeIterator;

import java.util.*;


/**
 * XML/XMLDSIG Service.
 *
 * Сервис отвечает за всё что связано с XML/XMLDSIG.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class XmlService {
    private final KalkanWrapper kalkanWrapper;
    private final CertificateService certificateService;
    private final TspService tspService;
    private final AdesVerificationService adesVerificationService;

    private static final String DS_NS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String XADES_NS = "http://uri.etsi.org/01903/v1.3.2#";
    private static final String XADES141_NS = "http://uri.etsi.org/01903/v1.4.1#";
    private static final String C14N_EXCL = "http://www.w3.org/2001/10/xml-exc-c14n#";

    /**
     * Read XML from String
     *
     * @param xml XML-String
     * @param removeSignatures Удалять подписи в XML
     * @return Document Object
     */
    public DocumentWrapper read(String xml, boolean removeSignatures) {
        final DocumentWrapper document = new DocumentWrapper(xml);

        if (removeSignatures) {
            final Element root = document.getDocumentElement();
            final NodeList signatures = root.getElementsByTagName("ds:Signature");

            for (int i=0; i< signatures.getLength(); ++i) {
                root.removeChild(signatures.item(i));
            }
        }

        return document;
    }

    /**
     * Подписывание XML
     *
     * @param xmlSignRequest Запрос на подпись XML
     * @return Ответ с подписанным XML
     */
    public XmlSignResponse sign(XmlSignRequest xmlSignRequest) {
        final DocumentWrapper document = read(xmlSignRequest.getXml(), xmlSignRequest.isClearSignatures());

        if (xmlSignRequest.isTrimXml()) {
            removeWhitespace(document.getDocument());
        }

        int i = 0;

        for (KeyStoreWrapper keyStore : kalkanWrapper.read(xmlSignRequest.getSigners())) {
            final SignerRequest signer = xmlSignRequest.getSigners().get(i++);

            if (xmlSignRequest.getXadesLevel() == null) {
                document.createXmlSignature(keyStore.getCertificate(), signer.getReferenceUri())
                    .sign(keyStore.getPrivateKey());
            } else {
                signXades(document, keyStore, signer, xmlSignRequest.getXadesLevel(), xmlSignRequest.getTsaPolicy());
            }
        }

        return XmlSignResponse.builder()
            .xml(document.toString())
            .build();
    }

    /**
     * Подписывает документ по профилю XAdES: B → T → LT → LTA (каждый следующий включает предыдущий).
     */
    private void signXades(DocumentWrapper document, KeyStoreWrapper keyStore, SignerRequest signer,
                           AdesLevel level, TsaPolicy tsaPolicy) {
        final CertificateWrapper certificate = keyStore.getCertificate();
        final String imprintDigest = KalkanUtil.getXadesTspImprintDigest(
            certificate.getX509Certificate().getSigAlgOID());

        final XadesSignatureWrapper xades = new XadesSignatureWrapper(document, certificate, signer.getReferenceUri());
        xades.sign(keyStore.getPrivateKey());

        if (level == AdesLevel.B) {
            return;
        }

        // XAdES-T: метка времени на ds:SignatureValue
        final TimeStampToken signatureTimeStamp = tspService.create(
            xades.getCanonicalizedSignatureValue(), imprintDigest, tsaPolicy.getPolicyId());
        xades.attachSignatureTimeStamp(encoded(signatureTimeStamp));

        if (level == AdesLevel.T) {
            return;
        }

        // XAdES-LT: вшиваем цепочку и данные отзыва
        final var validationData = certificateService.collectAdesValidationData(
            certificate, tspService.extractCertificates(signatureTimeStamp));
        xades.attachValidationData(validationData.certificates(), validationData.crls(), validationData.ocsps());

        if (level == AdesLevel.LT) {
            return;
        }

        // XAdES-LTA: архивная метка времени
        final TimeStampToken archiveTimeStamp = tspService.create(
            xades.getArchiveTimeStampImprintData(), imprintDigest, tsaPolicy.getPolicyId());
        xades.attachArchiveTimeStamp(encoded(archiveTimeStamp));
    }

    private static byte[] encoded(TimeStampToken token) {
        try {
            return token.getEncoded();
        } catch (IOException e) {
            throw new ServerException("Timestamp token encoding error", e);
        }
    }

    /**
     * Проверяет XML-подписи
     *
     * @param xml XML-строка
     * @param checkOcsp Проверять в OCSP
     * @param checkCrl Проверять в CRL
     * @return Результат проверки
     */
    public VerificationResponse verify(String xml, boolean checkOcsp, boolean checkCrl) {
        final DocumentWrapper document = read(xml, false);
        final Element root = document.getDocumentElement();
        final NodeList signatures = root.getElementsByTagName("ds:Signature");
        final int signaturesLength = signatures.getLength();

        boolean valid = true;

        final ArrayList<CertificateWrapper> certs = new ArrayList<>();
        final ArrayList<Date> validationTimes = new ArrayList<>();

        final Date currentDate = certificateService.getCurrentDate();

        AdesLevel adesLevel = null;
        Optional<TimeStampToken> lastSignatureTimestamp = Optional.empty();
        AdesVerificationService.AdesSignatureReport lastReport = null;

        for (int i = 0; i<signaturesLength; ++i) {
            final Element signature = (Element)signatures.item(signatures.getLength() - 1);

            if (Objects.isNull(signature)) {
                throw new ClientException("Bad signature: Element 'ds:Reference' is not found in XML document");
            }

            final XMLSignatureWrapper xmlSignature = new XMLSignatureWrapper(signature);

            val cert = xmlSignature.getCertificate().orElse(null);

            // XAdES: проверенная метка времени подписи → доказанное время подписи + уровень
            final Optional<TimeStampToken> signatureTimestamp = verifiedXadesSignatureTimestamp(signature);
            final Date bestSignatureTime = adesVerificationService.bestSignatureTime(signatureTimestamp, currentDate);
            lastSignatureTimestamp = signatureTimestamp;
            adesLevel = adesVerificationService.detectLevel(
                signatureTimestamp.isPresent(),
                signature.getElementsByTagNameNS(XADES_NS, "CertificateValues").getLength() > 0,
                signature.getElementsByTagNameNS(XADES141_NS, "ArchiveTimeStamp").getLength() > 0);

            boolean cryptoOk = false;
            if (cert != null) {
                certificateService.attachValidationData(cert, checkOcsp, checkCrl);
                cryptoOk = xmlSignature.check();
            }

            final AdesVerificationService.EmbeddedRevocation embeddedRevocation = extractXadesRevocation(signature);
            final AdesVerificationService.RevocationOutcome revocation = cert == null
                ? AdesVerificationService.RevocationOutcome.MISSING
                : adesVerificationService.checkRevocation(cert, bestSignatureTime, embeddedRevocation, checkOcsp, checkCrl);

            final AdesVerificationService.AdesSignatureReport report = adesVerificationService.grade(
                cert != null, cryptoOk, xadesCertDigestValid(signature, cert),
                signatureTimestamp.isPresent(), signatureTimestamp.isPresent(), cert, bestSignatureTime, revocation);
            lastReport = report;

            if (!report.isValid()) {
                valid = false;
            }

            root.removeChild(signature);
            certs.add(cert);
            validationTimes.add(bestSignatureTime);
        }

        if (signaturesLength < 1) {
            valid = false;
        }

        final List<CertificateInfo> signers = new ArrayList<>();
        for (int i = 0; i < certs.size(); i++) {
            final CertificateWrapper c = certs.get(i);
            signers.add(c == null ? null : c.toCertificateInfo(validationTimes.get(i), checkOcsp, checkCrl));
        }

        return VerificationResponse.builder()
            .valid(valid)
            .signers(signers)
            .adesLevel(adesLevel)
            .adesStatus(lastReport == null ? null : lastReport.status())
            .adesSubIndication(lastReport == null ? null : lastReport.subIndication())
            .signatureTimestamp(lastSignatureTimestamp
                .map(t -> adesVerificationService.toTspInfo(t.getTimeStampInfo())).orElse(null))
            .bestSignatureTime(validationTimes.isEmpty() ? null : validationTimes.get(validationTimes.size() - 1))
            .build();
    }

    /** Вшитые в XAdES-подпись CRL / OCSP ({@code xades:EncapsulatedCRLValue} / {@code EncapsulatedOCSPValue}). */
    private AdesVerificationService.EmbeddedRevocation extractXadesRevocation(Element signature) {
        final List<java.security.cert.X509CRL> crls = new ArrayList<>();
        final List<byte[]> ocspResponses = new ArrayList<>();
        try {
            final var cf = java.security.cert.CertificateFactory.getInstance("X.509",
                kz.gov.pki.kalkan.jce.provider.KalkanProvider.PROVIDER_NAME);
            final NodeList crlNodes = signature.getElementsByTagNameNS(XADES_NS, "EncapsulatedCRLValue");
            for (int i = 0; i < crlNodes.getLength(); i++) {
                byte[] der = java.util.Base64.getMimeDecoder().decode(crlNodes.item(i).getTextContent().trim());
                crls.add((java.security.cert.X509CRL) cf.generateCRL(new java.io.ByteArrayInputStream(der)));
            }
            final NodeList ocspNodes = signature.getElementsByTagNameNS(XADES_NS, "EncapsulatedOCSPValue");
            for (int i = 0; i < ocspNodes.getLength(); i++) {
                ocspResponses.add(java.util.Base64.getMimeDecoder().decode(ocspNodes.item(i).getTextContent().trim()));
            }
        } catch (Exception e) {
            log.warn("Cannot extract XAdES revocation values: {}", e.getMessage());
        }
        return new AdesVerificationService.EmbeddedRevocation(crls, ocspResponses);
    }

    /** Проверяет хеш сертификата в {@code xades:SigningCertificateV2/CertDigest}. Нет элемента → {@code true}. */
    private boolean xadesCertDigestValid(Element signature, CertificateWrapper cert) {
        if (cert == null) {
            return true;
        }
        final NodeList certDigests = signature.getElementsByTagNameNS(XADES_NS, "CertDigest");
        if (certDigests.getLength() == 0) {
            return true;
        }
        try {
            final Element certDigest = (Element) certDigests.item(0);
            final String algoUri = ((Element) certDigest.getElementsByTagNameNS(DS_NS, "DigestMethod").item(0))
                .getAttribute("Algorithm");
            final byte[] expected = java.util.Base64.getMimeDecoder().decode(
                certDigest.getElementsByTagNameNS(DS_NS, "DigestValue").item(0).getTextContent().trim());
            final byte[] actual = java.security.MessageDigest.getInstance(
                    KalkanUtil.getDigestJcaNameByXmlUri(algoUri),
                    kz.gov.pki.kalkan.jce.provider.KalkanProvider.PROVIDER_NAME)
                .digest(cert.getX509Certificate().getEncoded());
            return java.util.Arrays.equals(expected, actual);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Извлекает и проверяет {@code xades:SignatureTimeStamp} — метку времени над
     * exclusive-c14n значением {@code ds:SignatureValue}.
     */
    private Optional<TimeStampToken> verifiedXadesSignatureTimestamp(Element signature) {
        try {
            final NodeList timeStamps = signature.getElementsByTagNameNS(XADES_NS, "SignatureTimeStamp");
            if (timeStamps.getLength() == 0) {
                return Optional.empty();
            }
            final Element encapsulated = (Element) ((Element) timeStamps.item(0))
                .getElementsByTagNameNS(XADES_NS, "EncapsulatedTimeStamp").item(0);
            if (encapsulated == null) {
                return Optional.empty();
            }

            final byte[] tokenDer = java.util.Base64.getMimeDecoder().decode(encapsulated.getTextContent().trim());
            final TimeStampToken token = new TimeStampToken(
                new kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData(tokenDer));

            final Element signatureValue = (Element) signature
                .getElementsByTagNameNS(DS_NS, "SignatureValue").item(0);
            final java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            org.apache.xml.security.c14n.Canonicalizer.getInstance(C14N_EXCL)
                .canonicalizeSubtree(signatureValue, out);

            return adesVerificationService.verifiedTimestamp(token, out.toByteArray());
        } catch (Exception e) {
            log.warn("XAdES signature timestamp verification failed: {}", e.getMessage());
            return Optional.empty();
        }
    }

    public String prepare(String xml, boolean trimXml) {
        return (trimXml ? removeWhitespace(xml) : xml).trim();
    }

    public void removeWhitespace(Document document) {
        Set<Node> toRemove = new HashSet<>();
        DocumentTraversal t = (DocumentTraversal) document;
        NodeIterator it = t.createNodeIterator(document,
            NodeFilter.SHOW_TEXT, null, true);

        for (org.w3c.dom.Node n = it.nextNode(); n != null; n = it.nextNode()) {
            if (n.getNodeValue().trim().isEmpty()) {
                toRemove.add(n);
            }
        }

        for (org.w3c.dom.Node n : toRemove) {
            n.getParentNode().removeChild(n);
        }
    }

    public String removeWhitespace(String xml) {
        val document = read(xml, false);
        removeWhitespace(document.getDocument());
        return document.toString();
    }
}

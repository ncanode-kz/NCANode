package kz.ncanode.wrapper;

import kz.gov.pki.kalkan.asn1.ASN1Object;
import kz.gov.pki.kalkan.asn1.DERInteger;
import kz.gov.pki.kalkan.asn1.x509.GeneralName;
import kz.gov.pki.kalkan.asn1.x509.GeneralNames;
import kz.gov.pki.kalkan.asn1.x509.IssuerSerial;
import kz.gov.pki.kalkan.asn1.x509.X509Name;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.ncanode.exception.ServerException;
import kz.ncanode.util.KalkanUtil;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.ObjectContainer;
import org.apache.xml.security.signature.SignedInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.TimeZone;
import java.util.UUID;

/**
 * Построение XAdES-подписи (enveloped) поверх Apache Santuario.
 *
 * <p>Формат повторяет движок {@code kz.gov.pki.ades.XadesSignatureService} из NCALayer:
 * exclusive-c14n, ns {@code http://uri.etsi.org/01903/v1.3.2#}, {@code SigningCertificateV2}/
 * {@code IssuerSerialV2}, ссылка на {@code SignedProperties} с типом
 * {@code http://uri.etsi.org/01903#SignedProperties}.
 *
 * <p>Прямая работа с Kalkan/Santuario держится здесь; оркестрация (TSP, отзыв) — в сервисе.
 */
@Slf4j
public class XadesSignatureWrapper {

    static final String XADES_NS = "http://uri.etsi.org/01903/v1.3.2#";
    static final String XADES141_NS = "http://uri.etsi.org/01903/v1.4.1#";
    static final String DS_NS = "http://www.w3.org/2000/09/xmldsig#";
    static final String XMLNS_NS = "http://www.w3.org/2000/xmlns/";
    static final String SIGNED_PROPERTIES_TYPE = "http://uri.etsi.org/01903#SignedProperties";
    static final String C14N = Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS;

    private final Document doc;
    private final CertificateWrapper certificate;
    private final XMLSignatureWrapper signature;
    private final String signatureId;
    private final String digestUri;

    @Getter
    private final Element signatureElement;

    public XadesSignatureWrapper(DocumentWrapper document, CertificateWrapper certificate, String referenceUri) {
        this.doc = document.getDocument();
        this.certificate = certificate;
        this.digestUri = certificate.getHashAlgorithmId();
        this.signatureId = "sig-" + UUID.randomUUID();
        this.signature = new XMLSignatureWrapper(doc, certificate.getSignAlgorithmId(), C14N);

        final XMLSignature xs = signature.getXmlSignature();

        try {
            xs.setId(signatureId);
            doc.getDocumentElement().appendChild(xs.getElement());
            this.signatureElement = xs.getElement();

            final Transforms transforms = new Transforms(doc);
            transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
            transforms.addTransform(C14N);

            final String dataReferenceId = signatureId + "-ref0";
            xs.addDocument(Optional.ofNullable(referenceUri).filter(u -> !u.isBlank()).orElse(""),
                transforms, digestUri, dataReferenceId, null);
            xs.addKeyInfo(certificate.getX509Certificate());

            addSignedProperties(dataReferenceId);
        } catch (XMLSecurityException e) {
            log.error("XAdES signature build error", e);
            throw new ServerException("XAdES signature build error", e);
        }
    }

    public void sign(PrivateKey privateKey) {
        signature.sign(privateKey);
    }

    /**
     * Канонизованное (exclusive-c14n) значение {@code ds:SignatureValue} — вход для метки времени XAdES-T.
     */
    public byte[] getCanonicalizedSignatureValue() {
        final Element signatureValue = (Element) signatureElement
            .getElementsByTagNameNS(DS_NS, "SignatureValue").item(0);

        try {
            final ByteArrayOutputStream out = new ByteArrayOutputStream();
            Canonicalizer.getInstance(C14N).canonicalizeSubtree(signatureValue, out);
            return out.toByteArray();
        } catch (XMLSecurityException e) {
            log.error("SignatureValue canonicalization error", e);
            throw new ServerException("SignatureValue canonicalization error", e);
        }
    }

    /**
     * Добавляет {@code xades:SignatureTimeStamp} в {@code UnsignedSignatureProperties} (уровень XAdES-T).
     *
     * @param timeStampTokenDer DER-кодированный TimeStampToken
     */
    public void attachSignatureTimeStamp(byte[] timeStampTokenDer) {
        final Element unsignedSignatureProperties = unsignedSignatureProperties();

        final Element timeStamp = xadesElement("SignatureTimeStamp");
        final Element canonicalizationMethod = doc.createElementNS(DS_NS, "ds:CanonicalizationMethod");
        canonicalizationMethod.setAttribute("Algorithm", C14N);
        final Element encapsulated = xadesElement("EncapsulatedTimeStamp");
        encapsulated.setTextContent(Base64.getEncoder().encodeToString(timeStampTokenDer));

        timeStamp.appendChild(canonicalizationMethod);
        timeStamp.appendChild(encapsulated);
        unsignedSignatureProperties.appendChild(timeStamp);
    }

    /**
     * Извлекает {@code EncapsulatedTimeStamp} из {@code xades:SignatureTimeStamp} — для разбора genTime
     * и цепочки TSA при построении XAdES-LT.
     *
     * @return DER-кодированный TimeStampToken, либо {@code null}, если метки нет
     */
    public byte[] getSignatureTimeStampToken() {
        final Element usp = existingUnsignedSignatureProperties();
        if (usp == null) {
            return null;
        }
        final Element timeStamp = firstChild(usp, "SignatureTimeStamp");
        if (timeStamp == null) {
            return null;
        }
        final Element encapsulated = firstChild(timeStamp, "EncapsulatedTimeStamp");
        return encapsulated == null ? null : Base64.getMimeDecoder().decode(encapsulated.getTextContent().trim());
    }

    /**
     * Вшивает {@code xades:CertificateValues} и {@code xades:RevocationValues} (уровень XAdES-LT).
     */
    public void attachValidationData(List<X509Certificate> certificates, List<byte[]> crls, List<byte[]> ocsps) {
        final Element usp = unsignedSignatureProperties();

        final Element certificateValues = xadesElement("CertificateValues");
        for (final X509Certificate certificate : certificates) {
            final Element encapsulated = xadesElement("EncapsulatedX509Certificate");
            encapsulated.setTextContent(base64(certificateEncoded(certificate)));
            certificateValues.appendChild(encapsulated);
        }
        usp.appendChild(certificateValues);

        final Element revocationValues = xadesElement("RevocationValues");

        if (!crls.isEmpty()) {
            final Element crlValues = xadesElement("CRLValues");
            for (final byte[] crl : crls) {
                final Element encapsulated = xadesElement("EncapsulatedCRLValue");
                encapsulated.setTextContent(base64(crl));
                crlValues.appendChild(encapsulated);
            }
            revocationValues.appendChild(crlValues);
        }

        if (!ocsps.isEmpty()) {
            final Element ocspValues = xadesElement("OCSPValues");
            for (final byte[] ocsp : ocsps) {
                final Element encapsulated = xadesElement("EncapsulatedOCSPValue");
                encapsulated.setTextContent(base64(ocsp));
                ocspValues.appendChild(encapsulated);
            }
            revocationValues.appendChild(ocspValues);
        }

        usp.appendChild(revocationValues);
    }

    /**
     * Данные для message imprint архивной метки времени ({@code xades141:ArchiveTimeStamp}), порядок —
     * как в движке NCALayer {@code XadesSignatureService.archiveTimeStampImprintData}.
     */
    public byte[] getArchiveTimeStampImprintData() {
        try {
            final ByteArrayOutputStream out = new ByteArrayOutputStream();
            final SignedInfo signedInfo = signature.getXmlSignature().getSignedInfo();

            for (int i = 0; i < signedInfo.getLength(); ++i) {
                out.write(signedInfo.item(i).getContentsAfterTransformation().getBytes());
            }

            out.write(canonicalize(firstDsChild("SignedInfo")));
            out.write(canonicalize(signatureValueElement()));

            final Element keyInfo = firstDsChild("KeyInfo");
            if (keyInfo != null) {
                out.write(canonicalize(keyInfo));
            }

            final Element usp = existingUnsignedSignatureProperties();
            if (usp != null) {
                final NodeList children = usp.getChildNodes();
                for (int i = 0; i < children.getLength(); ++i) {
                    final Node child = children.item(i);
                    if (child.getNodeType() == Node.ELEMENT_NODE) {
                        out.write(canonicalize(child));
                    }
                }
            }

            final NodeList objects = signatureElement.getElementsByTagNameNS(DS_NS, "Object");
            for (int i = 0; i < objects.getLength(); ++i) {
                final Element object = (Element) objects.item(i);
                if (object.getElementsByTagNameNS(XADES_NS, "QualifyingProperties").getLength() == 0) {
                    out.write(canonicalize(object));
                }
            }

            return out.toByteArray();
        } catch (Exception e) {
            log.error("Archive timestamp imprint computation error", e);
            throw new ServerException("Archive timestamp imprint computation error", e);
        }
    }

    /**
     * Добавляет {@code xades141:ArchiveTimeStamp} (уровень XAdES-LTA).
     *
     * @param timeStampTokenDer DER-кодированный TimeStampToken над {@link #getArchiveTimeStampImprintData()}
     */
    public void attachArchiveTimeStamp(byte[] timeStampTokenDer) {
        final Element usp = unsignedSignatureProperties();

        final Element archive = doc.createElementNS(XADES141_NS, "xades141:ArchiveTimeStamp");
        archive.setAttributeNS(XMLNS_NS, "xmlns:xades141", XADES141_NS);

        final Element canonicalizationMethod = doc.createElementNS(DS_NS, "ds:CanonicalizationMethod");
        canonicalizationMethod.setAttribute("Algorithm", C14N);
        final Element encapsulated = xadesElement("EncapsulatedTimeStamp");
        encapsulated.setTextContent(Base64.getEncoder().encodeToString(timeStampTokenDer));

        archive.appendChild(canonicalizationMethod);
        archive.appendChild(encapsulated);
        usp.appendChild(archive);
    }

    private void addSignedProperties(String dataReferenceId) throws XMLSecurityException {
        final String signedPropertiesId = signatureId + "-signedprops";

        final Element qualifyingProperties = doc.createElementNS(XADES_NS, "xades:QualifyingProperties");
        qualifyingProperties.setAttributeNS(XMLNS_NS, "xmlns:xades", XADES_NS);
        qualifyingProperties.setAttribute("Target", "#" + signatureId);

        final Element signedProperties = xadesElement("SignedProperties");
        signedProperties.setAttribute("Id", signedPropertiesId);
        signedProperties.setIdAttribute("Id", true);

        final Element signedSignatureProperties = xadesElement("SignedSignatureProperties");

        final Element signingTime = xadesElement("SigningTime");
        signingTime.setTextContent(iso8601Utc(new Date()));
        signedSignatureProperties.appendChild(signingTime);
        signedSignatureProperties.appendChild(signingCertificateV2());

        signedProperties.appendChild(signedSignatureProperties);
        signedProperties.appendChild(signedDataObjectProperties(dataReferenceId));
        qualifyingProperties.appendChild(signedProperties);

        final ObjectContainer object = new ObjectContainer(doc);
        object.appendChild(qualifyingProperties);
        signature.getXmlSignature().appendObject(object);

        final Transforms transforms = new Transforms(doc);
        transforms.addTransform(C14N);
        signature.getXmlSignature().addDocument("#" + signedPropertiesId, transforms, digestUri, null,
            SIGNED_PROPERTIES_TYPE);
    }

    private Element signingCertificateV2() {
        final Element signingCertificate = xadesElement("SigningCertificateV2");
        final Element cert = xadesElement("Cert");

        final Element certDigest = xadesElement("CertDigest");
        final Element digestMethod = doc.createElementNS(DS_NS, "ds:DigestMethod");
        digestMethod.setAttribute("Algorithm", digestUri);
        final Element digestValue = doc.createElementNS(DS_NS, "ds:DigestValue");
        digestValue.setTextContent(base64(digest(encoded(certificate))));
        certDigest.appendChild(digestMethod);
        certDigest.appendChild(digestValue);

        final Element issuerSerial = xadesElement("IssuerSerialV2");
        issuerSerial.setTextContent(base64(issuerSerialV2()));

        cert.appendChild(certDigest);
        cert.appendChild(issuerSerial);
        signingCertificate.appendChild(cert);
        return signingCertificate;
    }

    private Element signedDataObjectProperties(String dataReferenceId) {
        final Element properties = xadesElement("SignedDataObjectProperties");
        final Element dataObjectFormat = xadesElement("DataObjectFormat");
        dataObjectFormat.setAttribute("ObjectReference", "#" + dataReferenceId);
        final Element mimeType = xadesElement("MimeType");
        mimeType.setTextContent("text/xml");
        dataObjectFormat.appendChild(mimeType);
        properties.appendChild(dataObjectFormat);
        return properties;
    }

    private Element unsignedSignatureProperties() {
        final Element qualifyingProperties = (Element) signatureElement
            .getElementsByTagNameNS(XADES_NS, "QualifyingProperties").item(0);

        Element unsignedProperties = firstChild(qualifyingProperties, "UnsignedProperties");
        if (unsignedProperties == null) {
            unsignedProperties = xadesElement("UnsignedProperties");
            qualifyingProperties.appendChild(unsignedProperties);
        }

        Element unsignedSignatureProperties = firstChild(unsignedProperties, "UnsignedSignatureProperties");
        if (unsignedSignatureProperties == null) {
            unsignedSignatureProperties = xadesElement("UnsignedSignatureProperties");
            unsignedProperties.appendChild(unsignedSignatureProperties);
        }
        return unsignedSignatureProperties;
    }

    private Element existingUnsignedSignatureProperties() {
        final NodeList found = signatureElement.getElementsByTagNameNS(XADES_NS, "UnsignedSignatureProperties");
        return found.getLength() == 0 ? null : (Element) found.item(0);
    }

    private Element firstDsChild(String localName) {
        final NodeList children = signatureElement.getChildNodes();
        for (int i = 0; i < children.getLength(); ++i) {
            final Node child = children.item(i);
            if (child.getNodeType() == Node.ELEMENT_NODE
                && DS_NS.equals(child.getNamespaceURI())
                && localName.equals(child.getLocalName())) {
                return (Element) child;
            }
        }
        return null;
    }

    private Element signatureValueElement() {
        return (Element) signatureElement.getElementsByTagNameNS(DS_NS, "SignatureValue").item(0);
    }

    private byte[] canonicalize(Node node) {
        try {
            final ByteArrayOutputStream out = new ByteArrayOutputStream();
            Canonicalizer.getInstance(C14N).canonicalizeSubtree(node, out);
            return out.toByteArray();
        } catch (XMLSecurityException e) {
            throw new ServerException("Canonicalization error", e);
        }
    }

    private static byte[] certificateEncoded(X509Certificate certificate) {
        try {
            return certificate.getEncoded();
        } catch (Exception e) {
            throw new ServerException("Certificate encoding error", e);
        }
    }

    private byte[] issuerSerialV2() {
        try {
            final var x509 = certificate.getX509Certificate();
            final X509Name issuer = X509Name.getInstance(
                ASN1Object.fromByteArray(x509.getIssuerX500Principal().getEncoded()));
            final GeneralNames issuerNames = new GeneralNames(new GeneralName(issuer));
            return new IssuerSerial(issuerNames, new DERInteger(x509.getSerialNumber())).getEncoded();
        } catch (Exception e) {
            log.error("IssuerSerialV2 encoding error", e);
            throw new ServerException("IssuerSerialV2 encoding error", e);
        }
    }

    private byte[] digest(byte[] data) {
        try {
            return MessageDigest.getInstance(KalkanUtil.getDigestJcaNameByXmlUri(digestUri),
                KalkanProvider.PROVIDER_NAME).digest(data);
        } catch (Exception e) {
            log.error("Certificate digest error", e);
            throw new ServerException("Certificate digest error", e);
        }
    }

    private static byte[] encoded(CertificateWrapper certificate) {
        try {
            return certificate.getX509Certificate().getEncoded();
        } catch (Exception e) {
            throw new ServerException("Certificate encoding error", e);
        }
    }

    private Element xadesElement(String localName) {
        return doc.createElementNS(XADES_NS, "xades:" + localName);
    }

    private static Element firstChild(Element parent, String localName) {
        final var children = parent.getChildNodes();
        for (int i = 0; i < children.getLength(); ++i) {
            final var child = children.item(i);
            if (child.getNodeType() == Element.ELEMENT_NODE
                && XADES_NS.equals(child.getNamespaceURI())
                && localName.equals(child.getLocalName())) {
                return (Element) child;
            }
        }
        return null;
    }

    private static String base64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    private static String iso8601Utc(Date date) {
        final SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        format.setTimeZone(TimeZone.getTimeZone("UTC"));
        return format.format(date);
    }
}

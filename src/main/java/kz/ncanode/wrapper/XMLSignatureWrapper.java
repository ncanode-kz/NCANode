package kz.ncanode.wrapper;

import kz.ncanode.exception.ServerException;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.keyresolver.KeyResolverException;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.security.PrivateKey;
import java.util.NoSuchElementException;
import java.util.Optional;

@Slf4j
public class XMLSignatureWrapper {

    @Getter
    private final XMLSignature xmlSignature;

    public XMLSignatureWrapper(Element signature) {
        try {
            xmlSignature = new XMLSignature(signature, "");
        } catch (XMLSecurityException e) {
            throw new ServerException("XML Signature creation error", e);
        }
    }

    public XMLSignatureWrapper(Document document, String signAlgorithmId) {
        try {
            xmlSignature = new XMLSignature(document, "", signAlgorithmId);
        } catch (XMLSecurityException e) {
            throw new ServerException("XML Signature creation error", e);
        }
    }

    public XMLSignatureWrapper(Document document, String signAlgorithmId, String c14nAlgorithmId) {
        try {
            Element signatureMethod = XMLUtils.createElementInSignatureSpace(document, "SignatureMethod");
            signatureMethod.setAttributeNS(null, "Algorithm", signAlgorithmId);

            Element c14nMethod = XMLUtils.createElementInSignatureSpace(document, "CanonicalizationMethod");
            c14nMethod.setAttributeNS(null, "Algorithm", c14nAlgorithmId);

            xmlSignature = new XMLSignature(document, "", signatureMethod, c14nMethod);
        } catch (XMLSecurityException e) {
            log.error("XML Signature creation error", e);
            throw new ServerException("XML Signature creation error", e);
        }
    }

    public void sign(PrivateKey privateKey) {
        try {
            getXmlSignature().sign(privateKey);
        } catch (XMLSignatureException e) {
            log.error("XML Signing error", e);
            throw new ServerException("XML Signing error", e);
        }
    }

    public Optional<CertificateWrapper> getCertificate() {
        try {
            // getKeyInfo() / getX509Certificate() возвращают null, если в подписи нет X509-данных
            return Optional.ofNullable(xmlSignature.getKeyInfo())
                .map(keyInfo -> {
                    try {
                        return keyInfo.getX509Certificate();
                    } catch (KeyResolverException e) {
                        return null;
                    }
                })
                .map(CertificateWrapper::new);
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    public boolean check() {
        try {
            return xmlSignature.checkSignatureValue(getCertificate().orElseThrow().getX509Certificate());
        } catch (XMLSignatureException|NoSuchElementException e) {
            return false;
        }
    }
}

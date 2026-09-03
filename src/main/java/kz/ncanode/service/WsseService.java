package kz.ncanode.service;

import kz.ncanode.dto.request.WsseSignRequest;
import kz.ncanode.dto.response.VerificationResponse;
import kz.ncanode.dto.response.XmlSignResponse;
import kz.ncanode.exception.ServerOp;
import kz.ncanode.wrapper.CertificateWrapper;
import kz.ncanode.wrapper.KalkanWrapper;
import kz.ncanode.wrapper.KeyStoreWrapper;
import kz.ncanode.wrapper.XMLSignatureWrapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.ws.security.components.crypto.CertificateStore;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.namespace.QName;
import jakarta.xml.soap.*;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.UUID;

/**
 * Сервис для работы с Wsse (Soap)
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class WsseService {

    private final KalkanWrapper kalkanWrapper;
    private final XmlService xmlService;
    private final CertificateService certificateService;

    /**
     * Подписывает Wsse XML
     *
     * @param wsseSignRequest Запрос на подпись
     * @return Подписанный SOAP-конверт
     */
    public XmlSignResponse sign(final WsseSignRequest wsseSignRequest) {
        return ServerOp.call(null, () -> {
            // read key
            final KeyStoreWrapper keystore = kalkanWrapper.read(wsseSignRequest.getKey(), wsseSignRequest.getKeyAlias(), wsseSignRequest.getPassword());
            final CertificateWrapper cert = keystore.getCertificate();

            // sign a soap request according to a reference implementation from smartbridge
            SOAPMessage msg = MessageFactory.newInstance().createMessage(null, new ByteArrayInputStream(
                xmlService.prepare(wsseSignRequest.getXml(), wsseSignRequest.isTrimXml()).getBytes(StandardCharsets.UTF_8)
            ));
            SOAPEnvelope env = msg.getSOAPPart().getEnvelope();
            SOAPBody body = env.getBody();

            String bodyId = "id-" + UUID.randomUUID();
            body.addAttribute(new QName(WSConstants.WSU_NS, "Id", WSConstants.WSU_PREFIX), bodyId);

            SOAPHeader header = env.getHeader();
            if (header == null) {
                header = env.addHeader();
            }

            Document doc = env.getOwnerDocument();

            Transforms transforms = new Transforms(env.getOwnerDocument());
            transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);

            XMLSignatureWrapper signature = new XMLSignatureWrapper(doc, cert.getSignAlgorithmId(), Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

            signature.getXmlSignature().addDocument("#" + bodyId, transforms, cert.getHashAlgorithmId());
            signature.getXmlSignature().getSignedInfo().getSignatureMethodElement().setNodeValue(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);

            WSSecHeader secHeader = new WSSecHeader(doc);
            secHeader.setMustUnderstand(true);
            secHeader.insertSecurityHeader();
            header.appendChild(secHeader.getSecurityHeaderElement());
            header.getFirstChild().appendChild(signature.getXmlSignature().getElement());

            SecurityTokenReference reference = new SecurityTokenReference(doc);
            reference.setKeyIdentifier(cert.getX509Certificate());

            signature.getXmlSignature().getKeyInfo().addUnknownElement(reference.getElement());
            signature.getXmlSignature().sign(keystore.getPrivateKey());



            try (StringWriter os = new StringWriter()) {
                TransformerFactory tf = TransformerFactory.newInstance();
                Transformer trans = tf.newTransformer();
                trans.transform(new DOMSource(doc), new StreamResult(os));

                return XmlSignResponse.builder()
                    .xml(os.toString())
                    .build();
            }
        });
    }

    /**
     * Проверяет подписанный SOAP-конверт
     *
     * @param xml soap envelope
     * @param checkOcsp Проверять в OCSP
     * @param checkCrl Проверять в CRL
     * @return Результат проверки
     */
    public VerificationResponse verify(String xml, boolean checkOcsp, boolean checkCrl) {
        return ServerOp.call(null, () -> {
            SOAPMessage msg = MessageFactory.newInstance().createMessage(null, new ByteArrayInputStream(
                xmlService.prepare(xml, false).getBytes(StandardCharsets.UTF_8)
            ));
            SOAPEnvelope env = msg.getSOAPPart().getEnvelope();
            Document doc = env.getOwnerDocument();

            Element root = (Element) doc.getFirstChild();
            NodeList signatures = root.getElementsByTagName("ds:Signature");

            if (signatures.getLength() < 1) {
                return VerificationResponse.builder()
                    .valid(false)
                    .signers(Collections.emptyList())
                    .build();
            }

            boolean valid = true;

            final ArrayList<CertificateWrapper> certs = new ArrayList<>();

            final Date currentDate = certificateService.getCurrentDate();

            Node sigNode = signatures.item(0);
            XMLSignature signature = new XMLSignature((Element) sigNode, "");
            NodeList securityRef = root.getElementsByTagName("wsse:SecurityTokenReference");
            SecurityTokenReference ref = new SecurityTokenReference((Element) securityRef.item(0));
            CertificateWrapper cert = new CertificateWrapper(ref.getKeyIdentifier(new CertificateStore(new X509Certificate[]{}))[0]);

            certificateService.attachValidationData(cert, checkOcsp, checkCrl);

            valid = signature.checkSignatureValue(cert.getPublicKey()) && cert.isValid(currentDate, checkOcsp, checkCrl);

            certs.add(cert);

            return VerificationResponse.builder()
                .valid(valid)
                .signers(certs.stream().map(c -> c.toCertificateInfo(currentDate, checkOcsp, checkCrl)).toList())
                .build();
        });
    }
}

package kz.ncanode.unit.service

import groovy.xml.DOMBuilder
import kz.ncanode.common.WithTestData
import kz.ncanode.dto.crl.CrlResult
import kz.ncanode.dto.crl.CrlStatus
import kz.ncanode.dto.ocsp.OcspResult
import kz.ncanode.dto.ocsp.OcspStatus
import kz.ncanode.dto.request.WsseSignRequest
import kz.ncanode.service.CertificateService
import kz.ncanode.service.WsseService
import kz.ncanode.wrapper.CertificateWrapper
import org.mockito.invocation.InvocationOnMock
import org.mockito.stubbing.Answer
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.mock.mockito.MockBean
import spock.lang.Specification
import spock.lang.Unroll

import static org.mockito.Mockito.*

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class WsseServiceTest extends Specification implements WithTestData {
    private final static String XML_VALID_STRING = """
<?xml version="1.0"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
<SOAP-ENV:Header/>
<SOAP-ENV:Body>
    <ns3:SendMessage xmlns:ns3="http://bip.bee.kz/SyncChannel/v10/Types" xmlns="">
        <request>
            <requestInfo>
                <messageId>ccb1010b-8446-4937-913f-c87a717f6809</messageId>
                <serviceId>GBDFL_UniversalServiceSync</serviceId>
                <messageDate>2019-12-25T12:48:21.024Z</messageDate>
                <sender>
                    <senderId>smartbridge</senderId>
                    <password>123</password>
                </sender>
                <properties>
                    <key>CONNECTOR_CLIENT</key>
                    <value>true</value>
                </properties>
            </requestInfo>
            <requestData>
                <ns4:data xmlns:ns4="http://bip.bee.kz/SyncChannel/v10/Interfaces" xmlns:cs="http://message.persistence.interactive.nat" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="cs:Request">
                    <messageId>1</messageId>
                    <messageDate>2017-10-12T15:22:16.183+06:00</messageDate>
                    <senderCode>smartbridge</senderCode>
                    <iin>931002451325</iin>
                </ns4:data>
            </requestData>
        </request>
    </ns3:SendMessage>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>
"""

    private final static String XML_SIGNED_STRING = """
<?xml version="1.0" encoding="UTF-8" standalone="no"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Header><wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" SOAP-ENV:mustUnderstand="1"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<ds:SignedInfo>
<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
<ds:Reference URI="#id-0ace83d4-0477-4890-90b2-50b3bd434949">
<ds:Transforms>
<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
</ds:Transforms>
<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
<ds:DigestValue>eqb07lP5ddRlF3l0RYWk7ZwYDjoifevOji7IqgtnX/I=</ds:DigestValue>
</ds:Reference>
</ds:SignedInfo>
<ds:SignatureValue>
UtsuKUTvau85Pdl2LN9o5GAuqMsoB6bV+t/WzPHlhRL3iEu6+J82Ib1GMdLdV6wTNZVW7szRgWz3&#13;
mjxyyo9PVyytjyCWHyfFl7NPcAxM220cvW3+lVhNdpVqhQQ8l5e+zJQWwMdRreevj5qxWw4KxZRP&#13;
rZ7xxyG05tq3NuVFonfbQ48TzHOdBTixbyPyi8rvmf663N0v0h8+wMZblZPy/7IMLJygbw1va6MU&#13;
O62+gqaNBwDXSxGysozb2Zoc9Kg/ST7tcTeowB5VUbd0WJd+aH+R3OCa1goQMhse4BsNxrU0SnnC&#13;
ngGRfppW9X6JHGjv5s7WO7Y+YPB9gqeN71+Huw==
</ds:SignatureValue>
<ds:KeyInfo>
<wsse:SecurityTokenReference><wsse:KeyIdentifier EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3">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</wsse:KeyIdentifier></wsse:SecurityTokenReference>
</ds:KeyInfo>
</ds:Signature></wsse:Security></SOAP-ENV:Header><SOAP-ENV:Body xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" wsu:Id="id-0ace83d4-0477-4890-90b2-50b3bd434949"><ns3:SendMessage xmlns:ns3="http://bip.bee.kz/SyncChannel/v10/Types"><request><requestInfo><messageId>ccb1010b-8446-4937-913f-c87a717f6809</messageId><serviceId>GBDFL_UniversalServiceSync</serviceId><messageDate>2019-12-25T12:48:21.024Z</messageDate><sender><senderId>smartbridge</senderId><password>123</password></sender><properties><key>CONNECTOR_CLIENT</key><value>true</value></properties></requestInfo><requestData><ns4:data xmlns:cs="http://message.persistence.interactive.nat" xmlns:ns4="http://bip.bee.kz/SyncChannel/v10/Interfaces" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="cs:Request"><messageId>1</messageId><messageDate>2017-10-12T15:22:16.183+06:00</messageDate><senderCode>smartbridge</senderCode><iin>931002451325</iin></ns4:data></requestData></request></ns3:SendMessage></SOAP-ENV:Body></SOAP-ENV:Envelope>
"""

    @Autowired
    WsseService wsseService

    @MockBean
    CertificateService certificateService

    @Unroll('#caseName')
    def "test sign method"() {
        given:
        def wsseSignRequest = WsseSignRequest.builder()
            .xml(xml)
            .key(key)
            .password(password)
            .build()

        when:
        def response = wsseService.sign(wsseSignRequest)
        def signed = DOMBuilder.parse(new StringReader(response.xml))
        def signatureValues = signed.getElementsByTagName('ds:SignatureValue')

        then:
        response != null
        signed != null

        and:
        signatureValues.length > 0
        !signatureValues.item(0).textContent.isEmpty()


        where:
        caseName         | xml              | key                            | password
        'sign gost 2004' | XML_VALID_STRING | KEY_INDIVIDUAL_VALID_SIGN_2004 | KEY_INDIVIDUAL_VALID_SIGN_2004_PASSWORD
        'sign gost 2015' | XML_VALID_STRING | KEY_INDIVIDUAL_VALID_2015      | KEY_INDIVIDUAL_VALID_2015_PASSWORD
    }

    @Unroll('#caseName')
    def "test soap envelope verifying"() {
        given:
        def validDate = buildValidDate()
        def issuerCert = mockIssuerCertificate(dateValid)

        when(certificateService.getCurrentDate()).thenReturn(validDate)
        when(certificateService.attachValidationData(any(), anyBoolean(), anyBoolean())).thenAnswer(new CertificateServiceAnswer(issuerCert, OcspResult.ACTIVE, CrlResult.ACTIVE))

        when:
        def response = wsseService.verify(xml, checkOcsp, checkCrl)

        then:
        response != null

        and:
        response.valid == expectedValid

        and:
        response.signers.size() == 1

        where:
        caseName       | xml               | checkOcsp | checkCrl | dateValid || expectedValid
        'simple soap'  | XML_SIGNED_STRING | false     | false    | true      || true
        'invalid date' | XML_SIGNED_STRING | false     | false    | false     || false
    }

    def "verify returns invalid for a SOAP envelope without a signature"() {
        given:
        def soap = '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">' +
            '<soapenv:Body><ping/></soapenv:Body></soapenv:Envelope>'

        when:
        def response = wsseService.verify(soap, false, false)

        then:
        !response.valid
        response.signers.isEmpty()
    }

    def "sign with trimXml still yields a signature"() {
        given:
        def request = WsseSignRequest.builder()
            .xml(XML_VALID_STRING)
            .key(KEY_INDIVIDUAL_VALID_2015)
            .password(KEY_INDIVIDUAL_VALID_2015_PASSWORD)
            .trimXml(true)
            .build()

        when:
        def response = wsseService.sign(request)

        then:
        response.xml.contains('ds:SignatureValue')
    }

    private CertificateWrapper mockIssuerCertificate(boolean dateValid) {
        def cert = mock(CertificateWrapper)
        when(cert.isDateValid(any())).thenReturn(dateValid)

        return cert
    }

    private OcspStatus mockOcspStatus(OcspResult result, boolean isActive) {
        def s = mock(OcspStatus)
        when(s.getResult()).thenReturn(result)
        when(s.isActive()).thenReturn(isActive)
        return s
    }

    private CrlStatus mockCrlStatus(CrlResult result) {
        def s = mock(CrlStatus)
        when(s.getResult()).thenReturn(result)
        return s
    }

    private Date buildValidDate() {
        def date = mock(Date)
        when(date.after(any())).thenReturn(true)
        when(date.before(any())).thenReturn(true)
        return date
    }

    protected class CertificateServiceAnswer implements Answer<Void> {

        private CertificateWrapper issuerCert
        private OcspResult ocspResult
        private CrlResult crlResult

        public CertificateServiceAnswer(CertificateWrapper issuerCert, OcspResult ocspResult, CrlResult crlResult) {
            this.issuerCert = issuerCert
            this.ocspResult = ocspResult
            this.crlResult = crlResult
        }

        @Override
        Void answer(InvocationOnMock invocation) throws Throwable {
            CertificateWrapper cert = invocation.getArgument(0, CertificateWrapper)
            cert.setIssuerCertificate(issuerCert)
            cert.setOcspStatus([mockOcspStatus(ocspResult, ocspResult == OcspResult.ACTIVE)])
            cert.setCrlStatus(mockCrlStatus(crlResult))
            return null
        }
    }
}

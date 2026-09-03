package kz.ncanode.unit.service

import groovy.xml.DOMBuilder
import kz.ncanode.common.WithTestData
import kz.ncanode.dto.crl.CrlResult
import kz.ncanode.dto.crl.CrlStatus
import kz.ncanode.dto.ocsp.OcspResult
import kz.ncanode.dto.ocsp.OcspStatus
import kz.ncanode.dto.request.XmlSignRequest
import kz.ncanode.exception.ServerException
import kz.ncanode.service.CertificateService
import kz.ncanode.service.XmlService
import kz.ncanode.wrapper.CertificateWrapper
import org.mockito.invocation.InvocationOnMock
import org.mockito.stubbing.Answer
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.mock.mockito.MockBean
import org.w3c.dom.Document
import spock.lang.Specification
import spock.lang.Unroll

import static kz.ncanode.common.SignerRequestTestData.*
import static org.mockito.Mockito.*

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class XmlServiceTest extends Specification implements WithTestData {

    private final static String XML_VALID_STRING = '<?xml version="1.0" encoding="utf-8"?><a><b>test</b></a>'
    private final static Closure<String> XML_VALID_STRING_WITH_REFERENCE = () -> "<?xml version=\"1.0\" encoding=\"utf-8\"?><!DOCTYPE a [\n" +
        "<!ATTLIST a id ID #IMPLIED> ]><a id=\"${REFERENCE_URI}\"><b>test</b></a>"
    private final static String XML_SIGNED_VALID_STRING = """
<?xml version="1.0" encoding="utf-8" standalone="no"?><a><b>test</b><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<ds:SignedInfo>
<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
<ds:Reference URI="">
<ds:Transforms>
<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
<ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"/>
</ds:Transforms>
<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
<ds:DigestValue>9KpJreFMA6K98mcu2hxdAe/vPzfl0uybYurT5DT/bTU=</ds:DigestValue>
</ds:Reference>
</ds:SignedInfo>
<ds:SignatureValue>
aAeSW+p2AfXts7PfkFPx77L5vUOs3pVW7wlGOfGayC+x0IIpwy7/O9ge4uAlgSCo2Z0IqBY9z+0q&#13;
PbX6EoaF59aE2uHkgHBuKLc4XqA4eOJERESgDcoqXp1DpjvENLGyiCbqGDumf8P5XUfUm5d7HGJy&#13;
EV8qEMLw2mIQ1alaPTy938cRQQO7fw8H2CsHrAvbtt/PabpduFfKACqbKukXDk+cR/b+XoouH3aP&#13;
aQzBvbuVekIp1OxiGHV0+2FphlGfqSLBzO66EA9zL+XQ+dxfF8cz46nNvnK4MoUtsQ/EXBjmLd7s&#13;
5Jh28f9LqZBE1iZVFyYJAaGk6CgIwgE+63GOog==
</ds:SignatureValue>
<ds:KeyInfo>
<ds:X509Data>
<ds:X509Certificate>
MIIF+zCCA+OgAwIBAgIUQnk5ChQfU1OmKUe2HtZegXQUZ9EwDQYJKoZIhvcNAQELBQAwLTELMAkG&#13;
A1UEBhMCS1oxHjAcBgNVBAMMFdKw0JrQniAzLjAgKFJTQSBURVNUKTAeFw0yMTAxMTgxMzA5MTRa&#13;
Fw0yMjAxMTgxMzA5MTRaMHkxHjAcBgNVBAMMFdCi0JXQodCi0J7QkiDQotCV0KHQojEVMBMGA1UE&#13;
BAwM0KLQldCh0KLQntCSMRgwFgYDVQQFEw9JSU4xMjM0NTY3ODkwMTExCzAJBgNVBAYTAktaMRkw&#13;
FwYDVQQqDBDQotCV0KHQotCe0JLQmNCnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA&#13;
maK+pHxaV71IlHAB023ZWaN8VSNkAAjmb9t3nci/ewuDlhblLGa/707c9yYrien3Oco4jlZ70Obz&#13;
HtDVzM3I3jFFF7crEPETLYuOgjQbJcH9B51DvzarYeqXpoU8t1gUE9BabPnsq02QUcVbCCnHgvoh&#13;
tpPVXCO86Cb/nOVKaXIl2M4Iyr16gQczCwnz5pyavLYG5cTiDywWB4YRvL0wXpNkURgl8kmUJIW+&#13;
pm1j1fyvY+5N/obZ04DQ6zpyhpf6sxk3/+sqX6eJ11KJ6FNoIlMQasXeBtXtJs8jZY7tmga2jIlg&#13;
PK4lGy4uQVCpIDkzuioxCPaz8ZA47zCSoiI7LwIDAQABo4IBxTCCAcEwDgYDVR0PAQH/BAQDAgbA&#13;
MB0GA1UdJQQWMBQGCCsGAQUFBwMEBggqgw4DAwQBATAfBgNVHSMEGDAWgBSmjBYzfLjoNWcGPl5B&#13;
V1WirzRQaDAdBgNVHQ4EFgQU4/41rdo7RcvqOj8e1I8mPcVcVW4wXgYDVR0gBFcwVTBTBgcqgw4D&#13;
AwIDMEgwIQYIKwYBBQUHAgEWFWh0dHA6Ly9wa2kuZ292Lmt6L2NwczAjBggrBgEFBQcCAjAXDBVo&#13;
dHRwOi8vcGtpLmdvdi5rei9jcHMwPAYDVR0fBDUwMzAxoC+gLYYraHR0cDovL3Rlc3QucGtpLmdv&#13;
di5rei9jcmwvbmNhX3JzYV90ZXN0LmNybDA+BgNVHS4ENzA1MDOgMaAvhi1odHRwOi8vdGVzdC5w&#13;
a2kuZ292Lmt6L2NybC9uY2FfZF9yc2FfdGVzdC5jcmwwcgYIKwYBBQUHAQEEZjBkMDgGCCsGAQUF&#13;
BzAChixodHRwOi8vdGVzdC5wa2kuZ292Lmt6L2NlcnQvbmNhX3JzYV90ZXN0LmNlcjAoBggrBgEF&#13;
BQcwAYYcaHR0cDovL3Rlc3QucGtpLmdvdi5rei9vY3NwLzANBgkqhkiG9w0BAQsFAAOCAgEAS9tP&#13;
6okU2l3cpZ73t06DZn/jHI+d9cJOk7xFDEjsX1rRe2HJKsDloOY066sOKou75Zk0/qF0ukPyZuPX&#13;
lX8vzsiPlclelkXpQTEvYV8vTnwLhhJJSFt9dNFWT3YTQDO2fpx1K+Jxu06zHQsB7UsCyFm5efKq&#13;
J6RwBw+a+SH9T8DrwuPuuVQvt8PKT/9hbK46GsLI4X46KmXSO2JmYVgcKWj5U3rmF3ZAdaMN32qK&#13;
a96uR2VYPOn75nWvTg+hDaf3RDjxufLTtfXrW857i7ngeUER8mlaINV4k09yAhFlSBtUWcDEpGKh&#13;
kxaJuDBXPYKhkWPuk3I0HOe6XLT5bo9W+hNvKKxjHkEGdKdk0MlKQyiGHSirmTsRK58ifkFMO3kS&#13;
lN1ZvM8oLLtGwkuJgPMgG5o2UX1Gg5Q/dZjwZIQ3buV1CZ5DfceH3kgLPCTCG/ae6S/EY2I1cPhr&#13;
R8jSdCitzK2huq9LYDgwZipAhLnmnIMgYY9ouCELmaG/2n1ZsHKq6s5Aylssrfkb9yowY9G+EFVZ&#13;
4dVEXO2XSFlGT2RpvutiLrLqK6iajz9iYQETd9mLKCo0lcvu7RMqfKqR0v6emTyjt2joM5Grw45e&#13;
cfruSnHhKSYvgmTKB4KqIxdUA+U763u5x37NXK2NR1cJHLaqTfqcDPMMuTK2Fjz7MIs27zQ=
</ds:X509Certificate>
</ds:X509Data>
</ds:KeyInfo>
</ds:Signature></a>
"""
    private final static String XML_SIGNED_VALID_STRING_TWO_SIGNERS = """
<?xml version="1.0" encoding="utf-8" standalone="no"?><a><b>test</b><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<ds:SignedInfo>
<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
<ds:Reference URI="">
<ds:Transforms>
<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
<ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"/>
</ds:Transforms>
<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
<ds:DigestValue>9KpJreFMA6K98mcu2hxdAe/vPzfl0uybYurT5DT/bTU=</ds:DigestValue>
</ds:Reference>
</ds:SignedInfo>
<ds:SignatureValue>
aAeSW+p2AfXts7PfkFPx77L5vUOs3pVW7wlGOfGayC+x0IIpwy7/O9ge4uAlgSCo2Z0IqBY9z+0q&#13;
PbX6EoaF59aE2uHkgHBuKLc4XqA4eOJERESgDcoqXp1DpjvENLGyiCbqGDumf8P5XUfUm5d7HGJy&#13;
EV8qEMLw2mIQ1alaPTy938cRQQO7fw8H2CsHrAvbtt/PabpduFfKACqbKukXDk+cR/b+XoouH3aP&#13;
aQzBvbuVekIp1OxiGHV0+2FphlGfqSLBzO66EA9zL+XQ+dxfF8cz46nNvnK4MoUtsQ/EXBjmLd7s&#13;
5Jh28f9LqZBE1iZVFyYJAaGk6CgIwgE+63GOog==
</ds:SignatureValue>
<ds:KeyInfo>
<ds:X509Data>
<ds:X509Certificate>
MIIF+zCCA+OgAwIBAgIUQnk5ChQfU1OmKUe2HtZegXQUZ9EwDQYJKoZIhvcNAQELBQAwLTELMAkG&#13;
A1UEBhMCS1oxHjAcBgNVBAMMFdKw0JrQniAzLjAgKFJTQSBURVNUKTAeFw0yMTAxMTgxMzA5MTRa&#13;
Fw0yMjAxMTgxMzA5MTRaMHkxHjAcBgNVBAMMFdCi0JXQodCi0J7QkiDQotCV0KHQojEVMBMGA1UE&#13;
BAwM0KLQldCh0KLQntCSMRgwFgYDVQQFEw9JSU4xMjM0NTY3ODkwMTExCzAJBgNVBAYTAktaMRkw&#13;
FwYDVQQqDBDQotCV0KHQotCe0JLQmNCnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA&#13;
maK+pHxaV71IlHAB023ZWaN8VSNkAAjmb9t3nci/ewuDlhblLGa/707c9yYrien3Oco4jlZ70Obz&#13;
HtDVzM3I3jFFF7crEPETLYuOgjQbJcH9B51DvzarYeqXpoU8t1gUE9BabPnsq02QUcVbCCnHgvoh&#13;
tpPVXCO86Cb/nOVKaXIl2M4Iyr16gQczCwnz5pyavLYG5cTiDywWB4YRvL0wXpNkURgl8kmUJIW+&#13;
pm1j1fyvY+5N/obZ04DQ6zpyhpf6sxk3/+sqX6eJ11KJ6FNoIlMQasXeBtXtJs8jZY7tmga2jIlg&#13;
PK4lGy4uQVCpIDkzuioxCPaz8ZA47zCSoiI7LwIDAQABo4IBxTCCAcEwDgYDVR0PAQH/BAQDAgbA&#13;
MB0GA1UdJQQWMBQGCCsGAQUFBwMEBggqgw4DAwQBATAfBgNVHSMEGDAWgBSmjBYzfLjoNWcGPl5B&#13;
V1WirzRQaDAdBgNVHQ4EFgQU4/41rdo7RcvqOj8e1I8mPcVcVW4wXgYDVR0gBFcwVTBTBgcqgw4D&#13;
AwIDMEgwIQYIKwYBBQUHAgEWFWh0dHA6Ly9wa2kuZ292Lmt6L2NwczAjBggrBgEFBQcCAjAXDBVo&#13;
dHRwOi8vcGtpLmdvdi5rei9jcHMwPAYDVR0fBDUwMzAxoC+gLYYraHR0cDovL3Rlc3QucGtpLmdv&#13;
di5rei9jcmwvbmNhX3JzYV90ZXN0LmNybDA+BgNVHS4ENzA1MDOgMaAvhi1odHRwOi8vdGVzdC5w&#13;
a2kuZ292Lmt6L2NybC9uY2FfZF9yc2FfdGVzdC5jcmwwcgYIKwYBBQUHAQEEZjBkMDgGCCsGAQUF&#13;
BzAChixodHRwOi8vdGVzdC5wa2kuZ292Lmt6L2NlcnQvbmNhX3JzYV90ZXN0LmNlcjAoBggrBgEF&#13;
BQcwAYYcaHR0cDovL3Rlc3QucGtpLmdvdi5rei9vY3NwLzANBgkqhkiG9w0BAQsFAAOCAgEAS9tP&#13;
6okU2l3cpZ73t06DZn/jHI+d9cJOk7xFDEjsX1rRe2HJKsDloOY066sOKou75Zk0/qF0ukPyZuPX&#13;
lX8vzsiPlclelkXpQTEvYV8vTnwLhhJJSFt9dNFWT3YTQDO2fpx1K+Jxu06zHQsB7UsCyFm5efKq&#13;
J6RwBw+a+SH9T8DrwuPuuVQvt8PKT/9hbK46GsLI4X46KmXSO2JmYVgcKWj5U3rmF3ZAdaMN32qK&#13;
a96uR2VYPOn75nWvTg+hDaf3RDjxufLTtfXrW857i7ngeUER8mlaINV4k09yAhFlSBtUWcDEpGKh&#13;
kxaJuDBXPYKhkWPuk3I0HOe6XLT5bo9W+hNvKKxjHkEGdKdk0MlKQyiGHSirmTsRK58ifkFMO3kS&#13;
lN1ZvM8oLLtGwkuJgPMgG5o2UX1Gg5Q/dZjwZIQ3buV1CZ5DfceH3kgLPCTCG/ae6S/EY2I1cPhr&#13;
R8jSdCitzK2huq9LYDgwZipAhLnmnIMgYY9ouCELmaG/2n1ZsHKq6s5Aylssrfkb9yowY9G+EFVZ&#13;
4dVEXO2XSFlGT2RpvutiLrLqK6iajz9iYQETd9mLKCo0lcvu7RMqfKqR0v6emTyjt2joM5Grw45e&#13;
cfruSnHhKSYvgmTKB4KqIxdUA+U763u5x37NXK2NR1cJHLaqTfqcDPMMuTK2Fjz7MIs27zQ=
</ds:X509Certificate>
</ds:X509Data>
</ds:KeyInfo>
</ds:Signature><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<ds:SignedInfo>
<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
<ds:SignatureMethod Algorithm="urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-512"/>
<ds:Reference URI="">
<ds:Transforms>
<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
<ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"/>
</ds:Transforms>
<ds:DigestMethod Algorithm="urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-512"/>
<ds:DigestValue>JXtgklPvmOEL7qfdrS8MaadBx7zdLgQXHgpTGfO7uGT0SZfANASQdIgIeSQ9Wjs5/VtIfmoUfs7b&#13;
TeYIs2/reA==</ds:DigestValue>
</ds:Reference>
</ds:SignedInfo>
<ds:SignatureValue>
9KSGy33AXRui1rpYXmUE4kVmAThKcwUZeuTsPoGEKJb/RSdLcxUDOIoyrtFWbJwCIGty1+V8E807&#13;
xSGxhhhnlZwS5AQHrUyFJv6yPL4pJTgRv/zj0psnbxbvDzARiLkMmm8bkpgavbE8ozVbltc82kWy&#13;
sNzF2L0oKcj/ZWDIyS0=
</ds:SignatureValue>
<ds:KeyInfo>
<ds:X509Data>
<ds:X509Certificate>
MIIEPzCCA6egAwIBAgIUD/BiEdyCvrACU/+gAPHehKvvRU8wDgYKKoMOAwoBAQIDAgUAMF0xTjBM&#13;
BgNVBAMMRdKw0JvQotCi0KvSmiDQmtCj05jQm9CQ0J3QlNCr0KDQo9Co0Ksg0J7QoNCi0JDQm9Cr&#13;
0pogKEdPU1QpIFRFU1QgMjAyMjELMAkGA1UEBhMCS1owHhcNMjIwNzI4MTIzNDQ4WhcNMjMwNzI4&#13;
MTIzNDQ4WjCBgTEiMCAGA1UEAwwZ0KLQldCh0KLQotCe0JIg0KLQldCh0KLQojEXMBUGA1UEBAwO&#13;
0KLQldCh0KLQotCe0JIxGDAWBgNVBAUTD0lJTjEyMzQ1Njc4OTAxMjELMAkGA1UEBhMCS1oxGzAZ&#13;
BgNVBCoMEtCi0JXQodCi0KLQntCS0JjQpzCBrDAjBgkqgw4DCgEBAgIwFgYKKoMOAwoBAQICAQYI&#13;
KoMOAwoBAwMDgYQABIGAs45cc1sDCYF1czWVSt0M04KEE/WO7E6i5lUK6lYiDIEa7zatJtTcIWkg&#13;
L+P0otuzypSHP1mQSktSrRTRPPpcsgkOzuOYCBY12qhZGj9rPbgguAHZcX1DtxvSz9H41/fffPEg&#13;
p++MaYHNlFTR6aFB0cRB7E3LSq9RL6+fEFoK8TujggHGMIIBwjAOBgNVHQ8BAf8EBAMCBeAwOAYD&#13;
VR0gBDEwLzAtBgYqgw4DAwIwIzAhBggrBgEFBQcCARYVaHR0cDovL3BraS5nb3Yua3ovY3BzMHcG&#13;
CCsGAQUFBwEBBGswaTAoBggrBgEFBQcwAYYcaHR0cDovL3Rlc3QucGtpLmdvdi5rei9vY3NwLzA9&#13;
BggrBgEFBQcwAoYxaHR0cDovL3Rlc3QucGtpLmdvdi5rei9jZXJ0L25jYV9nb3N0MjAyMl90ZXN0&#13;
LmNlcjBBBgNVHR8EOjA4MDagNKAyhjBodHRwOi8vdGVzdC5wa2kuZ292Lmt6L2NybC9uY2FfZ29z&#13;
dDIwMjJfdGVzdC5jcmwwQwYDVR0uBDwwOjA4oDagNIYyaHR0cDovL3Rlc3QucGtpLmdvdi5rei9j&#13;
cmwvbmNhX2dvc3QyMDIyX2RfdGVzdC5jcmwwHQYDVR0lBBYwFAYIKwYBBQUHAwQGCCqDDgMDBAEB&#13;
MB0GA1UdDgQWBBSP8GIR3IK+sAJT/6AA8d6Eq+9FTzAfBgNVHSMEGDAWgBT60ksbo6DJYf4cqFA+&#13;
aqK7RQ24ozAWBgYqgw4DAwUEDDAKBggqgw4DAwUBATAOBgoqgw4DCgEBAgMCBQADgYEANNgvC4O+&#13;
KL4OIlKZ5g1IN5A9Zw4cGTAlDM0ZkakuZqWWdxFmERyyHfzeu6XmDLfcdaBEjQgQdqQvv/DoNIXP&#13;
Xz1jFc6jMPY+eWdmDYDgJ5I6ofVsPxLsR/VyVUJcs9Ziu+OhOGUDhoeDMjnWqRq0GmAWW1TfXCsX&#13;
KR8n3tylbHk=
</ds:X509Certificate>
</ds:X509Data>
</ds:KeyInfo>
</ds:Signature></a>
"""


    private final static String XML_INVALID_STRING = '<?xml version="1.0" encoding="utf-8"?><a><b>test</b>/a>'

    @Autowired
    private XmlService xmlService

    @MockBean
    private CertificateService certificateService

    def "check parsing valid xml"() {
        when: 'parse xml from string'
        def parsed = xmlService.read(XML_VALID_STRING, false)

        then: 'parsed xml not null'
        parsed != null

        and: 'no exception thrown'
        noExceptionThrown()

        and: 'valid content'
        xmlIsValid(parsed.getDocument())
    }

    def "check parsing invalid xml"() {
        when: 'parse xml from string'
        xmlService.read(XML_INVALID_STRING, false)

        then: 'check for thrown exception'
        def e = thrown(ServerException)
        e.getCause() != null
    }

    @Unroll("#caseName")
    def "check xml signing"() {
        given: 'create request'
        def request = XmlSignRequest.builder().xml(XML_VALID_STRING).signers(signers).build()

        when: 'sign'
        def response = xmlService.sign(request)

        then: 'check'
        noExceptionThrown()
        response != null

        and: 'check signatures size'
        def signed = DOMBuilder.parse(new StringReader(response.xml))
        signed.documentElement.getElementsByTagName("ds:Signature").getLength() == expectedSignaturesCount

        where:
        caseName              | signers                                                    || expectedSignaturesCount
        'sign with old key'   | [SIGNER_REQUEST_VALID_2004()]                              || 1
        'sign with new key'   | [SIGNER_REQUEST_VALID_2015()]                              || 1
        'sign with both keys' | [SIGNER_REQUEST_VALID_2004(), SIGNER_REQUEST_VALID_2015()] || 2
    }

    @Unroll("#caseName")
    def "check xml signature appending"() {
        given: 'create request'
        def request = XmlSignRequest.builder().xml(XML_SIGNED_VALID_STRING).signers([SIGNER_REQUEST_VALID_2015()]).clearSignatures(clearSignatures).build()

        when: 'sign'
        def response = xmlService.sign(request)

        then: 'check'
        noExceptionThrown()
        response != null

        and: 'check signatures size'
        def signed = DOMBuilder.parse(new StringReader(response.xml))
        signed.documentElement.getElementsByTagName("ds:Signature").getLength() == expectedSignaturesCount

        where:
        caseName                   | clearSignatures || expectedSignaturesCount
        'without clear signatures' | false           || 2
        'with clear signatures'    | true            || 1
    }

    def "check for reference uri"() {
        given: 'create request'
        def request = XmlSignRequest.builder().xml(XML_VALID_STRING_WITH_REFERENCE()).signers([SIGNER_REQUEST_VALID_2004_WITH_REFERENCE(), SIGNER_REQUEST_VALID_2015_WITH_REFERENCE()]).build()

        when: 'sign'
        def response = xmlService.sign(request)

        then: 'check for null'
        noExceptionThrown()
        response != null

        and: 'check reference uri'
        def signed = DOMBuilder.parse(new StringReader(response.xml))
        def references = signed.documentElement.getElementsByTagName('ds:Reference')

        references.item(0).attributes.getNamedItem("URI").textContent == ('#' + REFERENCE_URI)
        references.item(1).attributes.getNamedItem("URI").textContent == ('#' + REFERENCE_URI)
    }

    def "sign by reference uri without DOCTYPE id declaration"() {
        given: 'xml with a plain Id attribute, no DTD/schema'
        def xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><document Id=\"${REFERENCE_URI}\"><name>NCANode test</name></document>".toString()
        def request = XmlSignRequest.builder().xml(xml).signers([SIGNER_REQUEST_VALID_2015_WITH_REFERENCE()]).build()

        when: 'sign'
        def response = xmlService.sign(request)

        then: 'reference resolved, no ReferenceNotInitializedException'
        noExceptionThrown()
        def signed = DOMBuilder.parse(new StringReader(response.xml))
        signed.documentElement.getElementsByTagName('ds:Reference').item(0)
            .attributes.getNamedItem('URI').textContent == ('#' + REFERENCE_URI)
    }

    @Unroll("#caseName")
    def "check xml verifying"() {
        given:
        when(certificateService.getCurrentDate()).thenReturn(date)
        when(certificateService.attachValidationData(any(), anyBoolean(), anyBoolean())).thenAnswer(new CertificateServiceAnswer(issuerCert, ocspResult, crlResult))

        when:
        def response = xmlService.verify(xml, checkOcsp, checkCrl)

        then:
        response != null

        and:
        response.valid == expectedValid
        response.signers.size() == expectedSignersSize

        where:
        caseName              | xml                                 | date               | issuerCert                   | ocspResult         | crlResult         | checkOcsp | checkCrl || expectedValid | expectedSignersSize
        'one signer'          | XML_SIGNED_VALID_STRING             | buildValidDate()   | mockIssuerCertificate(true)  | OcspResult.ACTIVE  | CrlResult.ACTIVE  | false     | false    || true          | 1
        'one signer ocsp crl' | XML_SIGNED_VALID_STRING             | buildValidDate()   | mockIssuerCertificate(true)  | OcspResult.ACTIVE  | CrlResult.ACTIVE  | true      | true     || true          | 1
        'two signers'         | XML_SIGNED_VALID_STRING_TWO_SIGNERS | buildValidDate()   | mockIssuerCertificate(true)  | OcspResult.ACTIVE  | CrlResult.ACTIVE  | false     | false    || true          | 2
        'invalid date'        | XML_SIGNED_VALID_STRING             | buildInvalidDate() | mockIssuerCertificate(false) | OcspResult.ACTIVE  | CrlResult.ACTIVE  | false     | false    || false         | 1
        'invalid ocsp'        | XML_SIGNED_VALID_STRING             | buildValidDate()   | mockIssuerCertificate(true)  | OcspResult.REVOKED | CrlResult.ACTIVE  | true      | true     || false         | 1
        'invalid crl'         | XML_SIGNED_VALID_STRING             | buildValidDate()   | mockIssuerCertificate(true)  | OcspResult.ACTIVE  | CrlResult.REVOKED | true      | true     || false         | 1
        'null issuer'         | XML_SIGNED_VALID_STRING             | buildValidDate()   | null                         | OcspResult.ACTIVE  | CrlResult.ACTIVE  | false     | false    || false         | 1
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

    private boolean xmlIsValid(Document xml) {
        xml.childNodes.length == 1 && xml.childNodes.item(0).childNodes.item(0).textContent == 'test'
    }

    private Date buildValidDate() {
        def date = mock(Date)
        when(date.after(any())).thenReturn(true)
        when(date.before(any())).thenReturn(true)
        return date
    }

    private Date buildInvalidDate() {
        def date = mock(Date)
        when(date.after(any())).thenReturn(true)
        when(date.before(any())).thenReturn(false)
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

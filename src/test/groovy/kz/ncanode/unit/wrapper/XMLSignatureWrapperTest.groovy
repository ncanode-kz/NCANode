package kz.ncanode.unit.wrapper

import kz.ncanode.common.WithTestData
import kz.ncanode.exception.ServerException
import kz.ncanode.wrapper.DocumentWrapper
import kz.ncanode.wrapper.XMLSignatureWrapper
import org.springframework.boot.test.context.SpringBootTest
import spock.lang.Specification

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class XMLSignatureWrapperTest extends Specification implements WithTestData {

    def setupSpec() {
        initializeKalkanLibrary()
    }

    def "constructing from a non-Signature element throws ServerException"() {
        given:
        def element = new DocumentWrapper('<?xml version="1.0"?><notASignature/>').getDocumentElement()

        when:
        new XMLSignatureWrapper(element)

        then:
        thrown(ServerException)
    }

    def "the three-arg constructor builds a signature with the given algorithms"() {
        given:
        def document = new DocumentWrapper('<?xml version="1.0"?><root/>').document

        when:
        def wrapper = new XMLSignatureWrapper(document,
            'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
            'http://www.w3.org/2001/10/xml-exc-c14n#')

        then:
        wrapper.xmlSignature != null
    }

    def "getCertificate is empty and check is false when the signature has no X509 data"() {
        given:
        def document = new DocumentWrapper('<?xml version="1.0"?><root/>').document
        def wrapper = new XMLSignatureWrapper(document, 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256')

        expect:
        wrapper.getCertificate().isEmpty()
        !wrapper.check()
    }
}

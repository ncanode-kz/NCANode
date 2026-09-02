package kz.ncanode.unit.wrapper

import kz.ncanode.common.WithTestData
import kz.ncanode.exception.ServerException
import kz.ncanode.wrapper.DocumentWrapper
import org.springframework.boot.test.context.SpringBootTest
import spock.lang.Specification

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class DocumentWrapperTest extends Specification implements WithTestData {

    def "parses a well-formed document and renders it back"() {
        given:
        def wrapper = new DocumentWrapper('<?xml version="1.0"?><root><child>x</child></root>')

        expect:
        wrapper.getDocumentElement().tagName == 'root'
        wrapper.toString().contains('<child>x</child>')
    }

    def "throws ServerException for malformed XML"() {
        when:
        new DocumentWrapper('<root><oops></root>')

        then:
        thrown(ServerException)
    }

    def "the record-style constructor keeps the supplied document"() {
        given:
        def source = new DocumentWrapper('<?xml version="1.0"?><a/>')

        expect:
        new DocumentWrapper(source.document).document.is(source.document)
    }
}

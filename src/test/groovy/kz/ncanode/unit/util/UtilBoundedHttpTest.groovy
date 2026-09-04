package kz.ncanode.unit.util

import kz.ncanode.util.Util
import org.apache.http.entity.ByteArrayEntity
import org.apache.http.entity.InputStreamEntity
import spock.lang.Specification

class UtilBoundedHttpTest extends Specification {

    def "readEntityBounded returns body within the limit"() {
        expect:
        Util.readEntityBounded(new ByteArrayEntity('hello'.bytes), 1024) == 'hello'.bytes
    }

    def "readEntityBounded rejects a declared Content-Length over the limit before reading"() {
        given: "a stream that blows up on any read"
        def poisoned = new InputStream() {
            int read() { throw new IllegalStateException('body must not be read') }
        }
        def entity = new InputStreamEntity(poisoned, 5_000)

        when:
        Util.readEntityBounded(entity, 1024)

        then:
        thrown(IOException)
    }

    def "readEntityBounded rejects a body that exceeds the limit while streaming"() {
        given: "chunked entity (length -1), 4 KB of data, 1 KB limit"
        def entity = new InputStreamEntity(new ByteArrayInputStream(new byte[4096]), -1)

        when:
        Util.readEntityBounded(entity, 1024)

        then:
        thrown(IOException)
    }

    def "copyEntityBounded aborts and does not overfill the sink"() {
        given:
        def entity = new InputStreamEntity(new ByteArrayInputStream(new byte[4096]), -1)
        def sink = new ByteArrayOutputStream()

        when:
        Util.copyEntityBounded(entity, sink, 1024)

        then:
        thrown(IOException)
        sink.size() <= 1024 + 64 * 1024 // одна буферизованная запись максимум
    }
}

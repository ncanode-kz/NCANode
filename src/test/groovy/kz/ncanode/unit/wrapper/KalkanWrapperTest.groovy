package kz.ncanode.unit.wrapper

import kz.ncanode.common.WithTestData
import kz.ncanode.constants.MessageConstants
import kz.ncanode.dto.request.SignerRequest
import kz.ncanode.exception.KeyException
import kz.ncanode.exception.ServerException
import kz.ncanode.util.KeyUtil
import kz.ncanode.wrapper.KalkanWrapper
import kz.ncanode.wrapper.KeyStoreWrapper
import org.mockito.MockedStatic
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.mock.mockito.SpyBean
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Unroll

import java.security.KeyStore
import java.security.KeyStoreException

import static org.mockito.Mockito.*

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class KalkanWrapperTest extends Specification implements WithTestData {

    @Shared
    final SignerRequest SIGNER_MOCK_REQUEST_1 = SignerRequest.builder()
        .key("key1")
        .password("password1")
        .keyAlias("keyAlias1")
        .build()

    @Shared
    final SignerRequest SIGNER_MOCK_REQUEST_2 = SignerRequest.builder()
        .key("key2")
        .password("password2")
        .keyAlias("keyAlias2")
        .build()

    @SpyBean
    private KalkanWrapper kalkanWrapper

    @Unroll('#caseName')
    def "read valid key"() {
        when: 'read key'
        def key = kalkanWrapper.read(rawKey, keyAlias, password)

        then: 'check key'
        key != null

        where:
        caseName                  | rawKey                         | password                                | keyAlias
        'read old key'            | KEY_INDIVIDUAL_VALID_SIGN_2004 | KEY_INDIVIDUAL_VALID_SIGN_2004_PASSWORD | null
        'read new key'            | KEY_INDIVIDUAL_VALID_2015      | KEY_INDIVIDUAL_VALID_2015_PASSWORD      | null
        'read old key with alias' | KEY_INDIVIDUAL_VALID_SIGN_2004 | KEY_INDIVIDUAL_VALID_SIGN_2004_PASSWORD | KEY_INDIVIDUAL_VALID_SIGN_2004_ALIAS
        'read new key with alias' | KEY_INDIVIDUAL_VALID_2015      | KEY_INDIVIDUAL_VALID_2015_PASSWORD      | KEY_INDIVIDUAL_VALID_2015_ALIAS
    }

    @Unroll('#caseName')
    def "read invalid key"() {
        when:
        def key = kalkanWrapper.read(rawKey, keyAlias, password)

        then: 'exception must be thrown'
        def error = thrown(KeyException)

        and: 'check exception message'
        error.message == expectedMessage

        where:
        caseName                       | rawKey                    | password                           | keyAlias          || expectedMessage
        'read key with invalid base64' | KEY_INVALID_BASE64        | KEY_INVALID_PASSWORD               | null              || MessageConstants.KEY_INVALID_BASE64
        'read invalid key'             | KEY_INVALID               | KEY_INVALID_PASSWORD               | null              || MessageConstants.KEY_INVALID_FORMAT
        'read with invalid password'   | KEY_INDIVIDUAL_VALID_2015 | KEY_INVALID_PASSWORD               | null              || MessageConstants.KEY_INVALID_PASSWORD
        'read with invalid alias'      | KEY_INDIVIDUAL_VALID_2015 | KEY_INDIVIDUAL_VALID_2015_PASSWORD | KEY_INVALID_ALIAS || KEY_INVALID_ALIAS_MESSAGE
    }

    def "read keys from signer request array"() {
        given:
        def keyStoreWrapper1 = mock(KeyStoreWrapper)
        def keyStoreWrapper2 = mock(KeyStoreWrapper)

        doReturn(keyStoreWrapper1).when(kalkanWrapper).read(SIGNER_MOCK_REQUEST_1.getKey(), SIGNER_MOCK_REQUEST_1.getKeyAlias(), SIGNER_MOCK_REQUEST_1.getPassword())
        doReturn(keyStoreWrapper2).when(kalkanWrapper).read(SIGNER_MOCK_REQUEST_2.getKey(), SIGNER_MOCK_REQUEST_2.getKeyAlias(), SIGNER_MOCK_REQUEST_2.getPassword())

        def signerRequests = [
            SIGNER_MOCK_REQUEST_1,
            SIGNER_MOCK_REQUEST_2
        ]

        when: 'read requests'
        def signers = kalkanWrapper.read(signerRequests)

        then: 'check signers'
        signers.size() == 2
        keyStoreWrapper1 != keyStoreWrapper2
        signers[0] == keyStoreWrapper1
        signers[1] == keyStoreWrapper2
    }

    def "check KeystoreException thrown in read()"() {
        when:
        try(MockedStatic<KeyStore> ks = mockStatic(KeyStore)) {
            ks.when(() -> KeyStore.getInstance("PKCS12", kalkanWrapper.getKalkanProvider())).thenThrow(new KeyStoreException())

            kalkanWrapper.read("", "", "")
        }

        then:
        def e = thrown(KeyException)
        e.getMessage() == MessageConstants.KEY_ENGINE_ERROR
    }

    def "check if aliases empty"() {
        when:
        def keystoreWrapper = kalkanWrapper.read(KEY_INDIVIDUAL_VALID_2015, null, KEY_INDIVIDUAL_VALID_2015_PASSWORD)

        try(MockedStatic<KeyUtil> ks = mockStatic(KeyUtil)) {
            ks.when(() -> KeyUtil.getAliases(keystoreWrapper.getKeyStore())).thenReturn(Collections.emptyList())
            kalkanWrapper.read(KEY_INDIVIDUAL_VALID_2015, null, KEY_INDIVIDUAL_VALID_2015_PASSWORD)
        }

        then:
        def e = thrown(KeyException)
        e.getMessage() == MessageConstants.KEY_ALIASES_NOT_FOUND
    }

    def "check KeyException for tryReadKey()"() {
        given:
        doThrow(KeyException).when(kalkanWrapper).read(anyString(), any(), anyString())
        List<SignerRequest> signers = [new SignerRequest(KEY_INDIVIDUAL_VALID_2015, KEY_INDIVIDUAL_VALID_2015_PASSWORD, null, null)]

        when:
        kalkanWrapper.read(signers)

        then:
        def e = thrown(ServerException)
        e.getMessage() == 'signers[0]: null'
    }
}

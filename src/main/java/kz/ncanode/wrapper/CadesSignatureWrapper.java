package kz.ncanode.wrapper;

import kz.gov.pki.kalkan.asn1.ASN1EncodableVector;
import kz.gov.pki.kalkan.asn1.ASN1Object;
import kz.gov.pki.kalkan.asn1.ASN1Sequence;
import kz.gov.pki.kalkan.asn1.ASN1Set;
import kz.gov.pki.kalkan.asn1.ASN1TaggedObject;
import kz.gov.pki.kalkan.asn1.DEREncodable;
import kz.gov.pki.kalkan.asn1.DERObject;
import kz.gov.pki.kalkan.asn1.DERObjectIdentifier;
import kz.gov.pki.kalkan.asn1.DEROctetString;
import kz.gov.pki.kalkan.asn1.DERSequence;
import kz.gov.pki.kalkan.asn1.DERSet;
import kz.gov.pki.kalkan.asn1.DERTaggedObject;
import kz.gov.pki.kalkan.asn1.cms.Attribute;
import kz.gov.pki.kalkan.asn1.cms.AttributeTable;
import kz.gov.pki.kalkan.asn1.cms.ContentInfo;
import kz.gov.pki.kalkan.asn1.cms.SignedData;
import kz.gov.pki.kalkan.asn1.cms.SignerInfo;
import kz.gov.pki.kalkan.asn1.ocsp.OCSPObjectIdentifiers;
import kz.gov.pki.kalkan.asn1.ocsp.OCSPResponse;
import kz.gov.pki.kalkan.asn1.ocsp.OCSPResponseStatus;
import kz.gov.pki.kalkan.asn1.ocsp.ResponseBytes;
import kz.gov.pki.kalkan.asn1.x509.AlgorithmIdentifier;
import kz.gov.pki.kalkan.asn1.x509.CertificateList;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData;
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformation;
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformationStore;
import kz.gov.pki.kalkan.tsp.TimeStampToken;
import kz.ncanode.exception.ServerException;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Hashtable;
import java.util.List;

/**
 * Достройка CMS-подписи до профилей CAdES T / LT / LTA (ETSI EN 319 122).
 *
 * <p>Формат повторяет движок {@code kz.gov.pki.ades.CadesSignatureService} из NCALayer:
 * <ul>
 *   <li>T   — unsigned-атрибут {@code id-aa-signatureTimeStampToken} (делает {@code TspService.addTspToSigner}).</li>
 *   <li>LT  — цепочка в {@code SignedData.certificates}, отзыв в {@code SignedData.crls}
 *             ({@code CertificateList} для CRL, {@code [1] OtherRevocationInfoFormat} для OCSP).</li>
 *   <li>LTA — unsigned-атрибут {@code id-aa-ets-archiveTimestampV3} ({@code 0.4.0.1733.2.4}) +
 *             {@code id-aa-ATSHashIndex-v3} ({@code 0.4.0.19122.1.5}) внутри токена.</li>
 * </ul>
 */
@Slf4j
public class CadesSignatureWrapper {

    private static final String PROVIDER = KalkanProvider.PROVIDER_NAME;

    private static final DERObjectIdentifier ID_AA_ETS_ARCHIVE_TIMESTAMP_V3 = new DERObjectIdentifier("0.4.0.1733.2.4");
    private static final DERObjectIdentifier ID_AA_ATS_HASH_INDEX_V3 = new DERObjectIdentifier("0.4.0.19122.1.5");
    private static final DERObjectIdentifier ID_RI_OCSP_RESPONSE = new DERObjectIdentifier("1.3.6.1.5.5.7.16.2");

    @Getter
    private CMSSignedData cms;

    public CadesSignatureWrapper(CMSSignedData cms) {
        this.cms = cms;
    }

    /** Подписанты в порядке следования в {@code SignerInfos}. */
    @SuppressWarnings("unchecked")
    public List<SignerInformation> signers() {
        return new ArrayList<>(cms.getSignerInfos().getSigners());
    }

    /**
     * CAdES-LT: заменяет набор сертификатов в {@code SignedData.certificates} и вшивает отзыв в
     * {@code SignedData.crls}.
     */
    public void embedValidationData(List<X509Certificate> certificates, List<byte[]> crlsDer, List<byte[]> ocspsDer) {
        try {
            if (!certificates.isEmpty()) {
                final CertStore store = CertStore.getInstance("Collection",
                    new CollectionCertStoreParameters(certificates), PROVIDER);
                cms = CMSSignedData.replaceCertificatesAndCRLs(cms, store);
            }

            if (crlsDer.isEmpty() && ocspsDer.isEmpty()) {
                return;
            }

            final ContentInfo contentInfo = ContentInfo.getInstance(ASN1Object.fromByteArray(cms.getEncoded()));
            final SignedData signedData = SignedData.getInstance(contentInfo.getContent());

            final ASN1EncodableVector revocationInfos = new ASN1EncodableVector();

            if (signedData.getCRLs() != null) {
                for (int i = 0; i < signedData.getCRLs().size(); ++i) {
                    revocationInfos.add(signedData.getCRLs().getObjectAt(i));
                }
            }
            for (final byte[] crl : crlsDer) {
                revocationInfos.add(CertificateList.getInstance(ASN1Object.fromByteArray(crl)));
            }
            for (final byte[] ocsp : ocspsDer) {
                final ASN1EncodableVector other = new ASN1EncodableVector();
                other.add(ID_RI_OCSP_RESPONSE);
                other.add(fullOcspResponse(ocsp));
                revocationInfos.add(new DERTaggedObject(false, 1, new DERSequence(other)));
            }

            final SignedData updated = new SignedData(
                signedData.getDigestAlgorithms(),
                signedData.getEncapContentInfo(),
                signedData.getCertificates(),
                new DERSet(revocationInfos),
                signedData.getSignerInfos());

            cms = new CMSSignedData(new ContentInfo(contentInfo.getContentType(), updated).getDEREncoded());
        } catch (Exception e) {
            log.error("CAdES-LT validation data embedding error", e);
            throw new ServerException("CAdES-LT validation data embedding error", e);
        }
    }

    /**
     * DER-кодированный {@code OCSPResponse} для {@code EncapsulatedOCSPValue}.
     * Если на входе уже полный {@code OCSPResponse} — возвращается как есть, иначе оборачивается
     * bare {@code BasicOCSPResponse} в {@code OCSPResponse{successful, ...}}.
     */
    private static DEREncodable fullOcspResponse(byte[] der) throws Exception {
        final DERObject parsed = ASN1Object.fromByteArray(der);
        try {
            return OCSPResponse.getInstance(parsed);
        } catch (RuntimeException notFullResponse) {
            final ResponseBytes responseBytes = new ResponseBytes(
                OCSPObjectIdentifiers.id_pkix_ocsp_basic, new DEROctetString(der));
            return new OCSPResponse(new OCSPResponseStatus(0), responseBytes);
        }
    }

    /**
     * CAdES-LTA: добавляет {@code id-aa-ets-archiveTimestampV3} каждому подписанту.
     *
     * @param digestOid   OID алгоритма хэширования архивной метки (совпадает с политикой TSA)
     * @param timestamper функция: (imprint-данные, OID алгоритма) → DER TimeStampToken
     */
    public void addArchiveTimestamps(String digestOid, ArchiveTimestamper timestamper) {
        try {
            final List<SignerInformation> updated = new ArrayList<>();

            for (final SignerInformation signer : signers()) {
                final Attribute hashIndex = buildAtsHashIndex(signer, digestOid);
                final byte[] imprintInput = archiveTimestampInput(signer, digestOid, hashIndex);
                final byte[] tokenDer = timestamper.timestamp(imprintInput, digestOid);
                final TimeStampToken tokenWithIndex = embedHashIndex(new TimeStampToken(new CMSSignedData(tokenDer)), hashIndex);

                final Attribute archive = new Attribute(ID_AA_ETS_ARCHIVE_TIMESTAMP_V3,
                    new DERSet(ASN1Object.fromByteArray(tokenWithIndex.getEncoded())));
                updated.add(addSeparateUnsignedAttribute(signer, archive));
            }

            cms = CMSSignedData.replaceSigners(cms, new SignerInformationStore(updated));
        } catch (Exception e) {
            log.error("CAdES-LTA archive timestamp error", e);
            throw new ServerException("CAdES-LTA archive timestamp error", e);
        }
    }

    @FunctionalInterface
    public interface ArchiveTimestamper {
        byte[] timestamp(byte[] imprintData, String digestOid);
    }

    // --- ATSHashIndex-v3 / archive-timestamp-v3 imprint (ETSI EN 319 122-1 §5.5.3) ---

    private Attribute buildAtsHashIndex(SignerInformation signer, String digestOid) throws Exception {
        final SignedData signedData = SignedData.getInstance(
            ContentInfo.getInstance(ASN1Object.fromByteArray(cms.getEncoded())).getContent());

        final ASN1EncodableVector index = new ASN1EncodableVector();
        index.add(new AlgorithmIdentifier(new DERObjectIdentifier(digestOid)));
        index.add(new DERSequence(hashesOf(signedData.getCertificates(), digestOid)));
        index.add(new DERSequence(hashesOf(signedData.getCRLs(), digestOid)));
        index.add(new DERSequence(unsignedAttrValueHashes(signer, digestOid)));

        return new Attribute(ID_AA_ATS_HASH_INDEX_V3, new DERSet(new DERSequence(index)));
    }

    private ASN1EncodableVector hashesOf(ASN1Set set, String digestOid) throws Exception {
        final ASN1EncodableVector hashes = new ASN1EncodableVector();
        if (set == null) {
            return hashes;
        }
        for (int i = 0; i < set.size(); ++i) {
            final byte[] der = set.getObjectAt(i).getDERObject().getDEREncoded();
            hashes.add(new DEROctetString(digest(der, digestOid)));
        }
        return hashes;
    }

    private ASN1EncodableVector unsignedAttrValueHashes(SignerInformation signer, String digestOid) throws Exception {
        final ASN1EncodableVector hashes = new ASN1EncodableVector();
        final AttributeTable unsigned = signer.getUnsignedAttributes();
        if (unsigned == null) {
            return hashes;
        }
        final ASN1EncodableVector attributes = unsigned.toASN1EncodableVector();
        for (int i = 0; i < attributes.size(); ++i) {
            final Attribute attribute = Attribute.getInstance(attributes.get(i));
            final byte[] type = attribute.getAttrType().getDERObject().getDEREncoded();
            for (int j = 0; j < attribute.getAttrValues().size(); ++j) {
                final byte[] value = attribute.getAttrValues().getObjectAt(j).getDERObject().getDEREncoded();
                final byte[] concat = new byte[type.length + value.length];
                System.arraycopy(type, 0, concat, 0, type.length);
                System.arraycopy(value, 0, concat, type.length, value.length);
                hashes.add(new DEROctetString(digest(concat, digestOid)));
            }
        }
        return hashes;
    }

    private byte[] archiveTimestampInput(SignerInformation signer, String digestOid, Attribute hashIndex) throws Exception {
        final SignedData signedData = SignedData.getInstance(
            ContentInfo.getInstance(ASN1Object.fromByteArray(cms.getEncoded())).getContent());

        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(signedData.getEncapContentInfo().getContentType().getDEREncoded());

        final Object content = cms.getSignedContent() != null ? cms.getSignedContent().getContent() : null;
        final byte[] contentBytes = content instanceof byte[] ? (byte[]) content : new byte[0];
        out.write(digest(contentBytes, digestOid));

        final ASN1Sequence signerInfo = rawSignerInfo(signedData, signer);
        for (int i = 0; i < signerInfo.size(); ++i) {
            final DERObject element = signerInfo.getObjectAt(i).getDERObject();
            if (!(element instanceof ASN1TaggedObject) || ((ASN1TaggedObject) element).getTagNo() != 1) {
                out.write(element.getDEREncoded());
            }
        }

        out.write(hashIndex.getAttrValues().getObjectAt(0).getDERObject().getDEREncoded());
        return out.toByteArray();
    }

    private static ASN1Sequence rawSignerInfo(SignedData signedData, SignerInformation signer) {
        try {
            final byte[] wantSid = signer.toSignerInfo().getSID().getDERObject().getDEREncoded();
            final ASN1Set signerInfos = signedData.getSignerInfos();
            for (int i = 0; i < signerInfos.size(); ++i) {
                final ASN1Sequence candidate = (ASN1Sequence) signerInfos.getObjectAt(i).getDERObject();
                final byte[] sid = SignerInfo.getInstance(candidate).getSID().getDERObject().getDEREncoded();
                if (Arrays.equals(sid, wantSid)) {
                    return candidate;
                }
            }
            throw new ServerException("SignerInfo not found for archive timestamp");
        } catch (Exception e) {
            throw new ServerException("Cannot locate raw SignerInfo", e);
        }
    }

    private static TimeStampToken embedHashIndex(TimeStampToken token, Attribute hashIndex) throws Exception {
        final CMSSignedData tst = token.toCMSSignedData();
        @SuppressWarnings("unchecked")
        final SignerInformation tsSigner = (SignerInformation) tst.getSignerInfos().getSigners().iterator().next();
        final SignerInformation modified = mergeUnsignedAttribute(tsSigner, hashIndex);
        final CMSSignedData updatedTst = CMSSignedData.replaceSigners(tst,
            new SignerInformationStore(Collections.singletonList(modified)));
        return new TimeStampToken(updatedTst);
    }

    private static SignerInformation mergeUnsignedAttribute(SignerInformation signer, Attribute attribute) {
        final AttributeTable existing = signer.getUnsignedAttributes();
        final Hashtable<DERObjectIdentifier, Attribute> table =
            existing != null ? new Hashtable<>(existing.toHashtable()) : new Hashtable<>();
        table.put(attribute.getAttrType(), attribute);
        return SignerInformation.replaceUnsignedAttributes(signer, new AttributeTable(table));
    }

    private static SignerInformation addSeparateUnsignedAttribute(SignerInformation signer, Attribute attribute) {
        final AttributeTable existing = signer.getUnsignedAttributes();
        final ASN1EncodableVector attributes = existing != null
            ? existing.toASN1EncodableVector() : new ASN1EncodableVector();
        attributes.add(attribute);
        return SignerInformation.replaceUnsignedAttributes(signer, new AttributeTable(new DERSet(attributes)));
    }

    private static byte[] digest(byte[] data, String digestOid) throws Exception {
        return MessageDigest.getInstance(digestOid, PROVIDER).digest(data);
    }
}

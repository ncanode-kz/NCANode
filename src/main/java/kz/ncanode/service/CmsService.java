package kz.ncanode.service;

import kz.gov.pki.kalkan.asn1.DERObjectIdentifier;
import kz.gov.pki.kalkan.asn1.DERSet;
import kz.gov.pki.kalkan.asn1.cms.Attribute;
import kz.gov.pki.kalkan.asn1.cms.AttributeTable;
import kz.gov.pki.kalkan.asn1.cms.CMSAttributes;
import kz.gov.pki.kalkan.asn1.cms.Time;
import kz.gov.pki.kalkan.asn1.pkcs.PKCSObjectIdentifiers;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.jce.provider.cms.*;
import kz.gov.pki.kalkan.tsp.TimeStampToken;
import kz.gov.pki.kalkan.tsp.TimeStampTokenInfo;
import kz.gov.pki.kalkan.util.encoders.Hex;
import kz.ncanode.dto.ades.AdesLevel;
import kz.ncanode.dto.ades.AdesValidationData;
import kz.ncanode.dto.cms.CmsSignerInfo;
import kz.ncanode.dto.request.CmsCreateRequest;
import kz.ncanode.dto.request.SignerRequest;
import kz.ncanode.dto.response.CmsDataResponse;
import kz.ncanode.dto.response.CmsResponse;
import kz.ncanode.dto.response.CmsVerificationResponse;
import kz.ncanode.dto.tsp.TsaPolicy;
import kz.ncanode.dto.tsp.TspInfo;
import kz.ncanode.exception.ClientException;
import kz.ncanode.exception.ServerException;
import kz.ncanode.util.KalkanUtil;
import kz.ncanode.util.Util;
import kz.ncanode.wrapper.CadesSignatureWrapper;
import kz.ncanode.wrapper.CertificateWrapper;
import kz.ncanode.wrapper.KalkanWrapper;
import kz.ncanode.wrapper.KeyStoreWrapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.cert.*;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
@Service
public class CmsService {

    private final KalkanWrapper kalkanWrapper;
    private final TspService tspService;
    private final  CertificateService certificateService;

    /**
     * Создает подписанный CMS
     *
     * @param cmsCreateRequest
     * @return
     */
    public CmsResponse create(CmsCreateRequest cmsCreateRequest) {
        try {
            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
            val data = Base64.getDecoder().decode(cmsCreateRequest.getData());

            CMSProcessable cmsData = new CMSProcessableByteArray(data);
            List<X509Certificate> certificates = new ArrayList<>();

            addSignersToCmsGenerator(generator, data, certificates, cmsCreateRequest.getSigners(),
                cmsCreateRequest.getCadesLevel() != null);

            CertStore chainStore = CertStore.getInstance(
                "Collection",
                new CollectionCertStoreParameters(
                    // если происходит повторная подпись, сертификаты могут дублироваться.
                    // добавим в chainStore только уникальные сертификаты.
                    certificates
                ),
                KalkanProvider.PROVIDER_NAME
            );

            generator.addCertificatesAndCRLs(chainStore);
            CMSSignedData signed = generator.generate(cmsData, !cmsCreateRequest.isDetached(), KalkanProvider.PROVIDER_NAME);

            if (cmsCreateRequest.getCadesLevel() != null) {
                signed = applyCadesLevel(signed, certificates, cmsCreateRequest.getCadesLevel(),
                    tsaPolicyId(cmsCreateRequest.getTsaPolicy()));

                return CmsResponse.builder()
                    .cms(Base64.getEncoder().encodeToString(signed.getEncoded()))
                    .build();
            }

            // TSP
            if (cmsCreateRequest.isWithTsp()) {
                String useTsaPolicy = Optional.ofNullable(cmsCreateRequest.getTsaPolicy()).map(TsaPolicy::getPolicyId)
                    .orElse(TsaPolicy.TSA_GOST2015_POLICY.getPolicyId());

                SignerInformationStore signerStore = signed.getSignerInfos();
                List<SignerInformation> signers = new ArrayList<>();

                int i = 0;

                for (Object signer : signerStore.getSigners()) {
                    X509Certificate cert = certificates.get(i++);
                    signers.add(tspService.addTspToSigner((SignerInformation) signer, cert, useTsaPolicy));
                }

                signed = CMSSignedData.replaceSigners(signed, new SignerInformationStore(signers));
            }

            return CmsResponse.builder()
                .cms(Base64.getEncoder().encodeToString(signed.getEncoded()))
                .build();
        } catch (ClientException e) {
            throw e;
        } catch (Exception e) {
            throw new ServerException(e.getMessage(), e);
        }
    }

    /**
     * Добавляет подписи уже в существующий CMS
     *
     * @param cmsCreateRequest
     * @return
     */
    public CmsResponse addSigners(CmsCreateRequest cmsCreateRequest) {
        try {
            if (cmsCreateRequest.getCms() == null || cmsCreateRequest.getCms().isEmpty()) {
                throw new ClientException("CMS argument not specified");
            }

            if (cmsCreateRequest.getCadesLevel() != null) {
                throw new ClientException("CAdES profile (cadesLevel) is only supported for a fresh signature on /cms/sign");
            }

            val decodedCms = Base64.getDecoder().decode(cmsCreateRequest.getCms());

            var cms = new CMSSignedData(decodedCms);
            byte[] decodedData = null;

            if (cms.getSignedContent() == null) {
                if (cmsCreateRequest.getData() == null || cmsCreateRequest.getData().isEmpty()) {
                    throw new ClientException("Data must be specifieed for detached CMS");
                }

                decodedData = Base64.getDecoder().decode(cmsCreateRequest.getData());

                cms = new CMSSignedData(new CMSProcessableByteArray(decodedData), decodedCms);
            } else {
                try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
                    cms.getSignedContent().write(out);
                    decodedData = out.toByteArray();
                }
            }

            CMSProcessable cmsData = new CMSProcessableByteArray(decodedData);

            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
            generator.addSigners(cms.getSignerInfos());

            val certificates = getCertificatesFromCmsSignedData(cms);

            addSignersToCmsGenerator(generator, decodedData, certificates, cmsCreateRequest.getSigners(), false);

            CertStore chainStore = CertStore.getInstance(
                "Collection",
                new CollectionCertStoreParameters(
                    certificates.stream().distinct().collect(Collectors.toList())
                ),
                KalkanProvider.PROVIDER_NAME
            );
            generator.addCertificatesAndCRLs(chainStore);
            CMSSignedData signed = generator.generate(cmsData, !cmsCreateRequest.isDetached(), KalkanProvider.PROVIDER_NAME);

            // TSP
            if (cmsCreateRequest.isWithTsp()) {
                String useTsaPolicy = Optional.ofNullable(cmsCreateRequest.getTsaPolicy()).map(TsaPolicy::getPolicyId)
                    .orElse(TsaPolicy.TSA_GOST2015_POLICY.getPolicyId());

                SignerInformationStore signerStore = signed.getSignerInfos();
                List<SignerInformation> signers = new ArrayList<>();

                int i = 0;
                for (Object signer : signerStore.getSigners()) {
                    X509Certificate cert = certificates.get(i++);

                    //Нельзя перезатирать TSP у предыдущих подписантов
                    boolean isCurrentSignerSameAsPrevious = isSignerSameAsPrevious((SignerInformation) signer, cms);
                    if(isCurrentSignerSameAsPrevious) {
                        //Старых подписантов оставляем без изменений
                        signers.add((SignerInformation)signer);
                    }
                    else {
                        //Новым подписантам устанавливаем TSP
                        signers.add(tspService.addTspToSigner((SignerInformation) signer, cert, useTsaPolicy));
                    }
                }

                signed = CMSSignedData.replaceSigners(signed, new SignerInformationStore(signers));
            }

            return CmsResponse.builder()
                .cms(Base64.getEncoder().encodeToString(signed.getEncoded()))
                .build();
        } catch (ClientException e) {
            throw e;
        } catch (Exception e) {
            throw new ServerException(e.getMessage(), e);
        }
    }

    private static boolean isSignerSameAsPrevious(SignerInformation signer, CMSSignedData cms) {
        boolean isCurrentSignerSameAsPrevious = false;
        for(Object obj : cms.getSignerInfos().getSigners()) {
            SignerInformation prevSignerInfo = (SignerInformation)obj;
            if (prevSignerInfo.getSID().equals(signer.getSID())) {
                isCurrentSignerSameAsPrevious = true;
            }
        }
        return isCurrentSignerSameAsPrevious;
    }

    /**
     * Проверяет подписанный CMS
     *
     * @param signedCms
     * @param detachedData
     * @param checkOcsp
     * @param checkCrl
     * @return
     */
    public CmsVerificationResponse verify(String signedCms, String detachedData, boolean checkOcsp, boolean checkCrl) {
        try {
            CMSSignedData cms = new CMSSignedData(Base64.getDecoder().decode(signedCms.getBytes(StandardCharsets.UTF_8)));

            if (detachedData != null && cms.getSignedContent() == null) {
                cms = new CMSSignedData(new CMSProcessableByteArray(Base64.getDecoder().decode(detachedData)),
                    Base64.getDecoder().decode(signedCms));
            }

            CertStore certStore = cms.getCertificatesAndCRLs("Collection", KalkanProvider.PROVIDER_NAME);
            val signerIt = cms.getSignerInfos().getSigners().iterator();

            final List<CmsSignerInfo> signers = new ArrayList<>();

            boolean valid = true;

            val currentDate = certificateService.getCurrentDate();

            while (signerIt.hasNext()) {
                var signerInfoBuilder = CmsSignerInfo.builder();

                var signer = (SignerInformation) signerIt.next();
                X509CertSelector signerConstraints = signer.getSID();
                var certCollection = certStore.getCertificates(signerConstraints);

                var certIt = certCollection.iterator();

                while (certIt.hasNext()) {
                    CertificateWrapper cert = new CertificateWrapper((X509Certificate) certIt.next());

                    certificateService.attachValidationData(cert, checkOcsp, checkCrl);

                    if (!signer.verify(cert.getPublicKey(), KalkanProvider.PROVIDER_NAME) || !cert.isValid(currentDate, checkOcsp, checkCrl)) {
                        valid = false;
                    }

                    signerInfoBuilder.certificate(cert.toCertificateInfo(currentDate, checkOcsp, checkCrl));
                }

                // TSP Checking
                if (signer.getUnsignedAttributes() != null) {
                    var attrs = signer.getUnsignedAttributes().toHashtable();

                    if (attrs.containsKey(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken)) {
                        Attribute attr = null;
                        Object obj = attrs.get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
                        if(obj instanceof Vector) {
                            attr = (Attribute)( ((Vector)obj).get(0) );
                        }
                        else {
                            attr = (Attribute)obj;
                        }

                        if (attr.getAttrValues().size() != 1) {
                            throw new Exception("Too many TSP tokens");
                        }

                        CMSSignedData tspCms = new CMSSignedData(attr.getAttrValues().getObjectAt(0).getDERObject().getEncoded());
                        TimeStampTokenInfo tspi = tspService.info(tspCms).orElseThrow();

                        try {
                            TspInfo tspInfo = TspInfo.builder()
                                .serialNumber(new String(Hex.encode(tspi.getSerialNumber().toByteArray())))
                                .genTime(tspi.getGenTime())
                                .policy(tspi.getPolicy())
                                .tsa(Optional.ofNullable(tspi.getTsa()).map(Object::toString).orElse(null))
                                .tspHashAlgorithm(KalkanUtil.getHashingAlgorithmByOID(tspi.getMessageImprintAlgOID()))
                                .hash(new String(Hex.encode(tspi.getMessageImprintDigest())))
                                .build();

                            signerInfoBuilder.tsp(tspInfo);
                        } catch (Exception e) {
                            log.warn(e.getMessage(), e);
                        }

                    }
                }

                signers.add(signerInfoBuilder.build());
            }

            return CmsVerificationResponse.builder()
                .valid(valid)
                .signers(signers)
                .build();
        } catch (Exception e) {
            throw new ClientException(e.getMessage(), e);
        }
    }

    /**
     * Извлекает данные из CMS если они есть
     *
     * @param signedCms
     * @return
     */
    public CmsDataResponse extract(String signedCms) {
        try {
            val cms = new CMSSignedData(Base64.getDecoder().decode(signedCms));

            if (cms.getSignedContent() == null) {
                throw new ClientException("CMS doesn't have signed content");
            }

            try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
                cms.getSignedContent().write(out);
                return CmsDataResponse.builder()
                    .data(Base64.getEncoder().encodeToString(out.toByteArray()))
                    .build();
            }
        } catch (CMSException|IOException e) {
            throw new ServerException(e.getMessage(), e);
        }
    }

    private List<X509Certificate> getCertificatesFromCmsSignedData(CMSSignedData cms) throws
        NoSuchAlgorithmException,
        NoSuchProviderException,
        CMSException,
        CertStoreException
    {
        List<X509Certificate> certs = new ArrayList<>();
        SignerInformationStore signers = cms.getSignerInfos();
        CertStore clientCerts = cms.getCertificatesAndCRLs("Collection", KalkanProvider.PROVIDER_NAME);

        for (var signerObj : signers.getSigners()) {
            SignerInformation signer = (SignerInformation) signerObj;
            X509CertSelector signerConstraints = signer.getSID();
            Collection<? extends Certificate> certCollection = clientCerts.getCertificates(signerConstraints);

            for (Certificate certificate : certCollection) {
                X509Certificate cert = (X509Certificate) certificate;
                certs.add(cert);
            }
        }

        return certs;
    }

    private void addSignersToCmsGenerator(CMSSignedDataGenerator generator, byte[] decodedData, List<X509Certificate> certificates, List<SignerRequest> signers, boolean cades) {
        try {
            for (KeyStoreWrapper ks : kalkanWrapper.read(signers)) {
                CertificateWrapper cert = ks.getCertificate();
                val privateKey = ks.getPrivateKey();

                Signature sig = Signature.getInstance(cert.getX509Certificate().getSigAlgName(), kalkanWrapper.getKalkanProvider());
                sig.initSign(privateKey);
                sig.update(decodedData);

                String digestOid = Util.getDigestAlgorithmOidBYSignAlgorithmOid(cert.getX509Certificate().getSigAlgOID());

                if (cades) {
                    generator.addSigner(privateKey, cert.getX509Certificate(), digestOid,
                        cadesSignedAttributes(cert.getX509Certificate()), null);
                } else {
                    generator.addSigner(privateKey, cert.getX509Certificate(), digestOid);
                }

                certificates.add(cert.getX509Certificate());
            }
        } catch (ClientException e) {
            throw e;
        } catch (Exception e) {
            throw new ServerException(e.getMessage(), e);
        }
    }

    /**
     * Обязательный signed-атрибут CAdES-B: {@code id-aa-signingCertificateV2} (ESSCertIDv2, SHA-256
     * хэш сертификата) + {@code signingTime}.
     *
     * ponytail: {@code id-aa-CMS-algorithm-protection} пока не добавляем — не обязателен для baseline-B,
     * добавить если потребуется защита от подмены алгоритма.
     */
    private AttributeTable cadesSignedAttributes(X509Certificate certificate) {
        Attribute signingCertificate = KalkanUtil.signingCertificateV2Attribute(certificate);
        Attribute signingTime = new Attribute(CMSAttributes.signingTime, new DERSet(new Time(new Date())));

        Hashtable<DERObjectIdentifier, Attribute> table = new Hashtable<>();
        table.put(signingCertificate.getAttrType(), signingCertificate);
        table.put(signingTime.getAttrType(), signingTime);

        return new AttributeTable(table);
    }

    private static String tsaPolicyId(TsaPolicy policy) {
        return Optional.ofNullable(policy).map(TsaPolicy::getPolicyId)
            .orElse(TsaPolicy.TSA_GOST2015_POLICY.getPolicyId());
    }

    /**
     * Достраивает CMS до профиля CAdES: B → T → LT → LTA (каждый следующий включает предыдущий).
     *
     * @param signed       базовый CMS (уровень B)
     * @param signerCerts  сертификаты подписантов в порядке следования {@code SignerInfos}
     * @param level        целевой уровень
     * @param tsaPolicyId  OID политики TSA
     */
    private CMSSignedData applyCadesLevel(CMSSignedData signed, List<X509Certificate> signerCerts,
                                          AdesLevel level, String tsaPolicyId) throws Exception {
        if (level == AdesLevel.B) {
            return signed;
        }

        // T: метка времени каждому подписанту без неё
        List<SignerInformation> timestamped = new ArrayList<>();
        List<SignerInformation> signers = new ArrayList<>(signed.getSignerInfos().getSigners());

        for (int i = 0; i < signers.size(); i++) {
            SignerInformation signer = signers.get(i);
            timestamped.add(extractSignatureTimeStamp(signer) != null
                ? signer
                : tspService.addTspToSigner(signer, signerCerts.get(i), tsaPolicyId));
        }

        signed = CMSSignedData.replaceSigners(signed, new SignerInformationStore(timestamped));

        if (level == AdesLevel.T) {
            return signed;
        }

        // LT: цепочки и данные отзыва
        CadesSignatureWrapper cades = new CadesSignatureWrapper(signed);
        List<SignerInformation> current = cades.signers();

        List<X509Certificate> allCerts = new ArrayList<>();
        List<byte[]> crls = new ArrayList<>();
        List<byte[]> ocsps = new ArrayList<>();

        signerCerts.forEach(c -> addDistinct(allCerts, c));

        for (int i = 0; i < signerCerts.size(); i++) {
            TimeStampToken token = extractSignatureTimeStamp(current.get(i));
            AdesValidationData data = certificateService.collectAdesValidationData(
                new CertificateWrapper(signerCerts.get(i)),
                token != null ? tspService.extractCertificates(token) : List.of());

            data.certificates().forEach(c -> addDistinct(allCerts, c));
            data.crls().forEach(c -> addDistinct(crls, c));
            data.ocsps().forEach(o -> addDistinct(ocsps, o));
        }

        cades.embedValidationData(allCerts, crls, ocsps);

        if (level == AdesLevel.LT) {
            return cades.getCms();
        }

        // LTA: архивная метка времени
        cades = new CadesSignatureWrapper(cades.getCms());
        String archiveDigestOid = KalkanUtil.getXadesTspImprintDigest(signerCerts.get(0).getSigAlgOID());
        cades.addArchiveTimestamps(archiveDigestOid, (imprintData, digestOid) -> {
            try {
                return tspService.create(imprintData, digestOid, tsaPolicyId).getEncoded();
            } catch (IOException e) {
                throw new ServerException("Archive timestamp token encoding error", e);
            }
        });

        return cades.getCms();
    }

    private static TimeStampToken extractSignatureTimeStamp(SignerInformation signer) {
        if (signer.getUnsignedAttributes() == null) {
            return null;
        }
        Attribute attribute = signer.getUnsignedAttributes().get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
        if (attribute == null) {
            return null;
        }
        try {
            return new TimeStampToken(new CMSSignedData(
                attribute.getAttrValues().getObjectAt(0).getDERObject().getEncoded()));
        } catch (Exception e) {
            return null;
        }
    }

    private static void addDistinct(List<byte[]> list, byte[] value) {
        if (list.stream().noneMatch(existing -> Arrays.equals(existing, value))) {
            list.add(value);
        }
    }

    private static void addDistinct(List<X509Certificate> list, X509Certificate value) {
        try {
            byte[] encoded = value.getEncoded();
            for (X509Certificate existing : list) {
                if (Arrays.equals(existing.getEncoded(), encoded)) {
                    return;
                }
            }
        } catch (CertificateEncodingException ignored) {
            // добавим как есть
        }
        list.add(value);
    }
}

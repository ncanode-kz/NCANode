package kz.ncanode.service;

import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.jce.provider.cms.*;
import kz.gov.pki.kalkan.tsp.TimeStampToken;
import kz.ncanode.dto.ades.AdesLevel;
import kz.ncanode.dto.ades.AdesValidationData;
import kz.ncanode.dto.pdf.PdfSignerInfo;
import kz.ncanode.dto.request.PdfSignRequest;
import kz.ncanode.dto.request.PdfVerifyRequest;
import kz.ncanode.dto.response.PdfSignResponse;
import kz.ncanode.dto.response.PdfVerificationResponse;
import kz.ncanode.dto.tsp.TsaPolicy;
import kz.ncanode.exception.ClientException;
import kz.ncanode.exception.NoSignaturesFoundException;
import kz.ncanode.exception.ServerOp;
import kz.ncanode.util.KalkanUtil;
import kz.ncanode.wrapper.CertificateWrapper;
import kz.ncanode.wrapper.KeyStoreWrapper;
import kz.ncanode.wrapper.KalkanWrapper;
import kz.ncanode.wrapper.PadesLtvBuilder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.cos.COSName;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.*;

@Slf4j
@RequiredArgsConstructor
@Service
public class PdfService {

	private final KalkanWrapper kalkanWrapper;
	private final TspService tspService;
	private final CertificateService certificateService;
	private final AdesVerificationService adesVerificationService;

	/**
	 * Signs a PDF document with digital signature
	 *
	 * @param pdfSignRequest PDF signing request
	 * @return Signed PDF response
	 */
	public PdfSignResponse sign(PdfSignRequest pdfSignRequest) {
		return ServerOp.call("Error signing PDF", () -> {
			byte[] pdfBytes = Base64.getDecoder().decode(pdfSignRequest.getPdf());

			final AdesLevel level = pdfSignRequest.getPadesLevel();
			final boolean pades = level != null;
			// PAdES-T достигается меткой времени независимо от флага withTsp
			final boolean withTsp = pdfSignRequest.isWithTsp() || (pades && level.isAtLeast(AdesLevel.T));
			final String tsaPolicyId = tsaPolicyId(pdfSignRequest.getTsaPolicy());

			// PDFBox allows only one pending signature per save, so each signer is applied
			// in its own load -> addSignature -> saveIncremental cycle.
			for (PdfSignRequest.PdfSigner pdfSigner : pdfSignRequest.getSigners()) {
				var keyStoreWrapper = kalkanWrapper.read(List.of(pdfSigner.getSigner())).get(0);

				try (PDDocument document = PDDocument.load(new ByteArrayInputStream(pdfBytes))) {
					PDSignature signature = new PDSignature();
					signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
					signature.setSubFilter(PDSignature.SUBFILTER_ETSI_CADES_DETACHED); // ETSI CADES
					// signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
					signature.setName(
							keyStoreWrapper.getCertificate().getX509Certificate().getSubjectX500Principal().getName());
					signature.setLocation(pdfSigner.getLocation());
					signature.setReason(pdfSigner.getReason());
					signature.setContactInfo(pdfSigner.getContactInfo());
					signature.setSignDate(Calendar.getInstance());

					document.addSignature(signature, new PdfSignatureInterface(keyStoreWrapper, withTsp, tsaPolicyId, pades));

					ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
					document.saveIncremental(outputStream);
					pdfBytes = outputStream.toByteArray();
				}
			}

			if (pades && level.isAtLeast(AdesLevel.LT)) {
				pdfBytes = addDocumentSecurityStore(pdfBytes);

				if (level.isAtLeast(AdesLevel.LTA)) {
					pdfBytes = addDocumentTimestamp(pdfBytes, tsaPolicyId);
					pdfBytes = addDocumentSecurityStore(pdfBytes);
				}
			}

			return PdfSignResponse.builder()
					.pdf(Base64.getEncoder().encodeToString(pdfBytes))
					.build();
		});
	}

	private static String tsaPolicyId(TsaPolicy policy) {
		return Optional.ofNullable(policy).map(TsaPolicy::getPolicyId)
				.orElse(TsaPolicy.TSA_GOST2015_POLICY.getPolicyId());
	}

	/**
	 * Достраивает подписанный PDF до PAdES-LT / LTA.
	 */
	public PdfSignResponse extend(kz.ncanode.dto.request.PdfExtendRequest request) {
		return ServerOp.call("Error extending PDF", () -> {
			if (!request.getPadesLevel().isAtLeast(AdesLevel.LT)) {
				throw new ClientException("PAdES extension supports only LT and LTA; sign at B or T level");
			}

			byte[] pdfBytes = Base64.getDecoder().decode(request.getPdf());
			String tsaPolicyId = tsaPolicyId(request.getTsaPolicy());

			pdfBytes = addDocumentSecurityStore(pdfBytes);

			if (request.getPadesLevel().isAtLeast(AdesLevel.LTA)) {
				pdfBytes = addDocumentTimestamp(pdfBytes, tsaPolicyId);
				pdfBytes = addDocumentSecurityStore(pdfBytes);
			}

			return PdfSignResponse.builder()
					.pdf(Base64.getEncoder().encodeToString(pdfBytes))
					.build();
		});
	}

	/**
	 * PAdES-LT: собирает по каждой подписи PDF цепочку и данные отзыва и пишет {@code /DSS} + {@code /VRI}.
	 */
	private byte[] addDocumentSecurityStore(byte[] pdfBytes) throws Exception {
		try (PDDocument document = PDDocument.load(new ByteArrayInputStream(pdfBytes))) {
			PadesLtvBuilder ltv = new PadesLtvBuilder(document);

			for (PDSignature signature : document.getSignatureDictionaries()) {
				byte[] cmsBytes = signature.getContents(pdfBytes);
				if (cmsBytes == null || cmsBytes.length == 0) {
					continue;
				}

				CMSSignedData cms = new CMSSignedData(cmsBytes);
				CertStore certStore = cms.getCertificatesAndCRLs("Collection", KalkanProvider.PROVIDER_NAME);

				for (Object signerObj : cms.getSignerInfos().getSigners()) {
					SignerInformation signer = (SignerInformation) signerObj;
					Collection<? extends Certificate> found = certStore.getCertificates(signer.getSID());
					if (found.isEmpty()) {
						continue;
					}

					X509Certificate signerCert = (X509Certificate) found.iterator().next();
					AdesValidationData data = certificateService.collectAdesValidationData(
							new CertificateWrapper(signerCert),
							tspService.extractCertificates(extractSignatureTimeStamp(signer)));

					ltv.addSignature(sha1Hex(cmsBytes), data);
				}
			}

			ltv.write();

			ByteArrayOutputStream out = new ByteArrayOutputStream();
			document.saveIncremental(out);
			return out.toByteArray();
		}
	}

	/**
	 * PAdES-LTA: добавляет ревизию с подписью {@code /DocTimeStamp} ({@code /SubFilter /ETSI.RFC3161}).
	 */
	private byte[] addDocumentTimestamp(byte[] pdfBytes, String tsaPolicyId) throws Exception {
		try (PDDocument document = PDDocument.load(new ByteArrayInputStream(pdfBytes))) {
			PDSignature timestamp = new PDSignature();
			timestamp.setType(COSName.getPDFName("DocTimeStamp"));
			timestamp.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
			timestamp.setSubFilter(COSName.getPDFName("ETSI.RFC3161"));

			SignatureOptions options = new SignatureOptions();
			options.setPreferredSignatureSize(SignatureOptions.DEFAULT_SIGNATURE_SIZE * 2);

			document.addSignature(timestamp, content -> {
				try {
					byte[] data = content.readAllBytes();
					TimeStampToken token = tspService.create(data,
							KalkanUtil.getTspImprintDigestForPolicy(tsaPolicyId), tsaPolicyId);
					return token.getEncoded();
				} catch (Exception e) {
					throw new IOException("Document timestamp failed", e);
				}
			}, options);

			ByteArrayOutputStream out = new ByteArrayOutputStream();
			document.saveIncremental(out);
			options.close();
			return out.toByteArray();
		}
	}

	private static TimeStampToken extractSignatureTimeStamp(SignerInformation signer) {
		if (signer.getUnsignedAttributes() == null) {
			return null;
		}
		var attribute = signer.getUnsignedAttributes()
				.get(kz.gov.pki.kalkan.asn1.pkcs.PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
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

	private static String sha1Hex(byte[] data) throws Exception {
		byte[] hash = MessageDigest.getInstance("SHA-1", KalkanProvider.PROVIDER_NAME).digest(data);
		StringBuilder sb = new StringBuilder(hash.length * 2);
		for (byte b : hash) {
			sb.append(String.format(Locale.ROOT, "%02X", b));
		}
		return sb.toString();
	}

	/**
	 * Verifies digital signatures in a PDF document
	 *
	 * @param pdfVerifyRequest PDF verification request
	 * @return PDF verification response
	 */
	public PdfVerificationResponse verify(PdfVerifyRequest pdfVerifyRequest) {
		return ServerOp.call("Error verifying PDF", () -> {
			byte[] pdfBytes = Base64.getDecoder().decode(pdfVerifyRequest.getPdf());

			// Load PDF document
			PDDocument document = PDDocument.load(new ByteArrayInputStream(pdfBytes));

			List<PdfSignerInfo> signerInfos = new ArrayList<>();
			boolean allValid = true;

			Date currentDate = certificateService.getCurrentDate();

			// Get all signatures
			List<PDSignature> signatures = document.getSignatureDictionaries();

			// Check if PDF has any signatures
			if (signatures.isEmpty()) {
				throw new NoSignaturesFoundException("PDF document contains no digital signatures");
			}

			boolean hasDss = document.getDocumentCatalog().getCOSObject()
					.getDictionaryObject(COSName.getPDFName("DSS")) != null;
			boolean hasDocTimestamp = signatures.stream().anyMatch(PdfService::isDocumentTimestamp);
			var embeddedRevocation = extractDssRevocation(document);

			for (PDSignature signature : signatures) {
				if (isDocumentTimestamp(signature)) {
					continue; // /DocTimeStamp — метка документа, не подпись
				}

				PdfSignerInfo signerInfo = verifySignature(signature, pdfVerifyRequest, pdfBytes, currentDate,
						hasDss, hasDocTimestamp, embeddedRevocation);
				signerInfos.add(signerInfo);

				if (!signerInfo.isValid()) {
					allValid = false;
				}
			}

			document.close();

			return PdfVerificationResponse.builder()
					.valid(allValid)
					.signers(signerInfos)
					.build();
		});
	}

	/**
	 * Verifies a single PDSignature using the original PDF bytes and
	 * CertificateService.
	 *
	 * @param signature        PDSignature dictionary from the PDF
	 * @param pdfVerifyRequest user request (contains revocation settings)
	 * @param originalPdfBytes the exact original PDF bytes that were verified/sent
	 */
	private static boolean isDocumentTimestamp(PDSignature signature) {
		return "DocTimeStamp".equals(signature.getCOSObject().getNameAsString(COSName.TYPE));
	}

	private static X509Certificate firstCert(Collection<? extends Certificate> certs) {
		return certs == null || certs.isEmpty() ? null : (X509Certificate) certs.iterator().next();
	}

	private static boolean essCertHashValid(SignerInformation signer, CertificateWrapper cert) {
		return KalkanUtil.signingCertificateV2HashMatches(signer, cert == null ? null : cert.getX509Certificate());
	}

	/** Извлекает CRL/OCSP из словаря {@code /DSS} документа. */
	private static AdesVerificationService.EmbeddedRevocation extractDssRevocation(PDDocument document) {
		List<java.security.cert.X509CRL> crls = new java.util.ArrayList<>();
		List<byte[]> ocspResponses = new java.util.ArrayList<>();
		try {
			var dss = (org.apache.pdfbox.cos.COSDictionary) document.getDocumentCatalog().getCOSObject()
					.getDictionaryObject(COSName.getPDFName("DSS"));
			if (dss == null) {
				return AdesVerificationService.EmbeddedRevocation.empty();
			}
			var cf = java.security.cert.CertificateFactory.getInstance("X.509", KalkanProvider.PROVIDER_NAME);
			var crlArray = (org.apache.pdfbox.cos.COSArray) dss.getDictionaryObject(COSName.getPDFName("CRLs"));
			if (crlArray != null) {
				for (int i = 0; i < crlArray.size(); i++) {
					var stream = (org.apache.pdfbox.cos.COSStream) crlArray.getObject(i);
					try (var in = stream.createInputStream()) {
						crls.add((java.security.cert.X509CRL) cf.generateCRL(in));
					}
				}
			}
			var ocspArray = (org.apache.pdfbox.cos.COSArray) dss.getDictionaryObject(COSName.getPDFName("OCSPs"));
			if (ocspArray != null) {
				for (int i = 0; i < ocspArray.size(); i++) {
					var stream = (org.apache.pdfbox.cos.COSStream) ocspArray.getObject(i);
					try (var in = stream.createInputStream()) {
						ocspResponses.add(in.readAllBytes());
					}
				}
			}
		} catch (Exception e) {
			log.warn("Cannot extract /DSS revocation: {}", e.getMessage());
		}
		return new AdesVerificationService.EmbeddedRevocation(crls, ocspResponses);
	}

	private PdfSignerInfo verifySignature(PDSignature signature,
			PdfVerifyRequest pdfVerifyRequest,
			byte[] originalPdfBytes,
			Date currentDate,
			boolean hasDss,
			boolean hasDocTimestamp,
			AdesVerificationService.EmbeddedRevocation embeddedRevocation) {
		try {
			// 1) Extract raw CMS (the /Contents) and the signed content (ByteRange)
			byte[] signatureContent = signature.getContents();
			if (signatureContent == null || signatureContent.length == 0) {
				return PdfSignerInfo.builder()
						.valid(false)
						.reason("Empty signature contents")
						.build();
			}

			byte[] signedContent;
			try (InputStream is = new ByteArrayInputStream(originalPdfBytes)) {
				signedContent = signature.getSignedContent(is); // uses /ByteRange internally
			}

			// 2) Parse CMS and iterate signer infos
			CMSSignedData signedData = new CMSSignedData(new CMSProcessableByteArray(signedContent), signatureContent);
			SignerInformationStore signerStore = signedData.getSignerInfos();
			@SuppressWarnings("unchecked")
			Collection<SignerInformation> signers = signerStore.getSigners();

			boolean withOcsp = pdfVerifyRequest.getRevocationCheck()
					.contains(kz.ncanode.dto.certificate.CertificateRevocation.OCSP);
			boolean withCrl = pdfVerifyRequest.getRevocationCheck()
					.contains(kz.ncanode.dto.certificate.CertificateRevocation.CRL);

			// один подписант на PDF-подпись
			SignerInformation si = signers.isEmpty() ? null : signers.iterator().next();

			CertStore certStore = signedData.getCertificatesAndCRLs("Collection", KalkanProvider.PROVIDER_NAME);
			X509Certificate x509 = si == null ? null : firstCert(certStore.getCertificates(si.getSID()));

			CertificateWrapper certificateWrapper = null;
			boolean cmsOk = false;
			String digestAlgReported = null;

			var signatureTimestamp = si == null ? Optional.<TimeStampToken>empty()
					: adesVerificationService.verifiedTimestamp(extractSignatureTimeStamp(si), si.getSignature());
			Date bestSignatureTime = adesVerificationService.bestSignatureTime(signatureTimestamp, currentDate);
			var adesLevel = adesVerificationService.detectLevel(signatureTimestamp.isPresent(), hasDss, hasDocTimestamp);
			var tspInfo = signatureTimestamp.map(t -> adesVerificationService.toTspInfo(t.getTimeStampInfo())).orElse(null);

			if (x509 != null) {
				cmsOk = si.verify(x509.getPublicKey(), KalkanProvider.PROVIDER_NAME);
				certificateWrapper = new CertificateWrapper(x509);
				certificateService.attachValidationData(certificateWrapper, withOcsp, withCrl);
				try {
					digestAlgReported = si.getDigestAlgOID();
				} catch (Exception ignored) {
					// leave null
				}
			}

			var revocation = certificateWrapper == null
					? AdesVerificationService.RevocationOutcome.MISSING
					: adesVerificationService.checkRevocation(certificateWrapper, bestSignatureTime,
							embeddedRevocation, withOcsp, withCrl);

			var report = adesVerificationService.grade(x509 != null, cmsOk,
					essCertHashValid(si, certificateWrapper), signatureTimestamp.isPresent(),
					signatureTimestamp.isPresent(), certificateWrapper, bestSignatureTime, revocation);

			return PdfSignerInfo.builder()
					.valid(report.isValid())
					.reason(signature.getReason())
					.location(signature.getLocation())
					.contactInfo(signature.getContactInfo())
					.signDate(signature.getSignDate() != null ? signature.getSignDate().getTime() : null)
					.certificate(certificateWrapper != null
							? certificateWrapper.toCertificateInfo(bestSignatureTime, withOcsp, withCrl)
							: null)
					.adesLevel(adesLevel)
					.tsp(tspInfo)
					.bestSignatureTime(certificateWrapper != null ? bestSignatureTime : null)
					.status(report.status())
					.subIndication(report.subIndication())
					.signatureAlgorithm(signature.getSubFilter())
					.digestAlgorithm(digestAlgReported != null ? digestAlgReported : "unknown")
					.build();

		} catch (Exception e) {
			log.error("Error verifying signature", e);
			return PdfSignerInfo.builder()
					.valid(false)
					.reason("Verification error: " + e.getMessage())
					.build();
		}
	}

	/**
	 * Custom signature interface for PDFBox
	 */
	private class PdfSignatureInterface implements SignatureInterface {
		private final KeyStoreWrapper keyStoreWrapper;
		private final boolean withTsp;
		private final String tsaPolicyId;
		private final boolean pades;

		public PdfSignatureInterface(KeyStoreWrapper keyStoreWrapper, boolean withTsp, String tsaPolicyId, boolean pades) {
			this.keyStoreWrapper = keyStoreWrapper;
			this.withTsp = withTsp;
			this.tsaPolicyId = tsaPolicyId;
			this.pades = pades;
		}

		@Override
		public byte[] sign(InputStream content) throws IOException {
			try {
				X509Certificate cert = keyStoreWrapper.getCertificate().getX509Certificate();
				PrivateKey privateKey = keyStoreWrapper.getPrivateKey();

				byte[] contentBytes = content.readAllBytes();

				// Create CMS signed data
				CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

				String digestOid = kz.ncanode.util.Util.getDigestAlgorithmOidBYSignAlgorithmOid(cert.getSigAlgOID());

				if (pades) {
					// PAdES-B: обязательный signed-атрибут id-aa-signingCertificateV2
					var table = new java.util.Hashtable<kz.gov.pki.kalkan.asn1.DERObjectIdentifier, kz.gov.pki.kalkan.asn1.cms.Attribute>();
					var scv2 = KalkanUtil.signingCertificateV2Attribute(cert);
					table.put(scv2.getAttrType(), scv2);
					generator.addSigner(privateKey, cert, digestOid,
							new kz.gov.pki.kalkan.asn1.cms.AttributeTable(table), null);
				} else {
					generator.addSigner(privateKey, cert, digestOid);
				}

				// Add certificates
				List<X509Certificate> certList = Arrays.asList(cert);
				CertStore certStore = CertStore.getInstance(
						"Collection",
						new CollectionCertStoreParameters(certList),
						KalkanProvider.PROVIDER_NAME);
				generator.addCertificatesAndCRLs(certStore);

				// Generate CMS
				CMSSignedData signedData = generator.generate(new CMSProcessableByteArray(contentBytes), false,
						KalkanProvider.PROVIDER_NAME);

				// Add TSP if requested
				if (withTsp) {
					SignerInformationStore signerStore = signedData.getSignerInfos();
					List<SignerInformation> signers = new ArrayList<>();

					for (Object signer : signerStore.getSigners()) {
						signers.add(tspService.addTspToSigner((SignerInformation) signer, cert, tsaPolicyId));
					}

					signedData = CMSSignedData.replaceSigners(signedData, new SignerInformationStore(signers));
				}

				return signedData.getEncoded();

			} catch (Exception e) {
				log.error("Error creating signature", e);
				throw new IOException("Error creating signature", e);
			}
		}
	}
}

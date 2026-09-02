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
import kz.ncanode.exception.ServerException;
import kz.ncanode.exception.NoSignaturesFoundException;
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

	/**
	 * Signs a PDF document with digital signature
	 *
	 * @param pdfSignRequest PDF signing request
	 * @return Signed PDF response
	 */
	public PdfSignResponse sign(PdfSignRequest pdfSignRequest) {
		try {
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

		} catch (ClientException e) {
			throw e;
		} catch (Exception e) {
			log.error("Error signing PDF", e);
			throw new ServerException("Error signing PDF: " + e.getMessage(), e);
		}
	}

	private static String tsaPolicyId(TsaPolicy policy) {
		return Optional.ofNullable(policy).map(TsaPolicy::getPolicyId)
				.orElse(TsaPolicy.TSA_GOST2015_POLICY.getPolicyId());
	}

	/**
	 * PAdES-LT: собирает по каждой подписи PDF цепочку и данные отзыва и пишет {@code /DSS} + {@code /VRI}.
	 */
	private byte[] addDocumentSecurityStore(byte[] pdfBytes) throws IOException {
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
		} catch (ClientException e) {
			throw e;
		} catch (Exception e) {
			throw new ServerException("Cannot add /DSS document security store: " + e.getMessage(), e);
		}
	}

	/**
	 * PAdES-LTA: добавляет ревизию с подписью {@code /DocTimeStamp} ({@code /SubFilter /ETSI.RFC3161}).
	 */
	private byte[] addDocumentTimestamp(byte[] pdfBytes, String tsaPolicyId) throws IOException {
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
		} catch (Exception e) {
			throw new ServerException("Cannot add document timestamp: " + e.getMessage(), e);
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
		try {
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

			for (PDSignature signature : signatures) {
				PdfSignerInfo signerInfo = verifySignature(signature, pdfVerifyRequest, pdfBytes, currentDate);
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

		} catch (NoSignaturesFoundException e) {
			throw e;
		} catch (Exception e) {
			throw new ServerException("Error verifying PDF: " + e.getMessage(), e);
		}
	}

	/**
	 * Verifies a single PDSignature using the original PDF bytes and
	 * CertificateService.
	 *
	 * @param signature        PDSignature dictionary from the PDF
	 * @param pdfVerifyRequest user request (contains revocation settings)
	 * @param originalPdfBytes the exact original PDF bytes that were verified/sent
	 */
	private PdfSignerInfo verifySignature(PDSignature signature,
			PdfVerifyRequest pdfVerifyRequest,
			byte[] originalPdfBytes,
			Date currentDate) {
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

			boolean valid = false;
			CertificateWrapper certificateWrapper = null;
			String digestAlgReported = null;

			for (SignerInformation si : signers) {
				// Load signer certificate from CMS bag
				CertStore certStore = signedData.getCertificatesAndCRLs("Collection", KalkanProvider.PROVIDER_NAME);
				Collection<? extends Certificate> certCollection = certStore.getCertificates(si.getSID());

				if (certCollection == null || certCollection.isEmpty()) {
					continue;
				}

				X509Certificate x509 = (X509Certificate) certCollection.iterator().next();

				// 3) Cryptographic verification of CMS signature using Kalkan provider
				boolean cmsOk = si.verify(x509.getPublicKey(), KalkanProvider.PROVIDER_NAME);
				if (!cmsOk) {
					continue;
				}

				// 4) Trust + revocation validation via your CertificateService
				certificateWrapper = new CertificateWrapper(x509);
				boolean withOcsp = pdfVerifyRequest.getRevocationCheck()
						.contains(kz.ncanode.dto.certificate.CertificateRevocation.OCSP);
				boolean withCrl = pdfVerifyRequest.getRevocationCheck()
						.contains(kz.ncanode.dto.certificate.CertificateRevocation.CRL);

				certificateService.attachValidationData(certificateWrapper, withOcsp, withCrl);

				boolean chainAndRevoOk = certificateWrapper.isValid(currentDate, withOcsp, withCrl);
				if (!chainAndRevoOk) {
					// Keep looping if multiple signer infos exist; otherwise report invalid
					continue;
				}

				// If we reached here → both CMS signature and trust checks are OK
				valid = true;

				// 5) Record digest OID (if you want to surface it)
				try {
					digestAlgReported = si.getDigestAlgOID();
				} catch (Exception ignored) {
					// leave null if not available
				}
				break;
			}

			return PdfSignerInfo.builder()
					.valid(valid)
					.reason(signature.getReason())
					.location(signature.getLocation())
					.contactInfo(signature.getContactInfo())
					.signDate(signature.getSignDate() != null ? signature.getSignDate().getTime() : null)
					.certificate(certificateWrapper != null
							? certificateWrapper.toCertificateInfo(
									currentDate,
									pdfVerifyRequest.getRevocationCheck().contains(
											kz.ncanode.dto.certificate.CertificateRevocation.OCSP),
									pdfVerifyRequest.getRevocationCheck().contains(
											kz.ncanode.dto.certificate.CertificateRevocation.CRL))
							: null)
					// Keep your current semantics:
					// - signatureAlgorithm shows PDF SubFilter (structure-level)
					// - digestAlgorithm shows CMS digest OID (crypto-level)
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
					var attr = KalkanUtil.signingCertificateV2Attribute(cert);
					table.put(attr.getAttrType(), attr);
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

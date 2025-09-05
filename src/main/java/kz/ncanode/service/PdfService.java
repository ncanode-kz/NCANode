package kz.ncanode.service;

import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.jce.provider.cms.*;
import kz.ncanode.dto.pdf.PdfSignerInfo;
import kz.ncanode.dto.request.PdfSignRequest;
import kz.ncanode.dto.request.PdfVerifyRequest;
import kz.ncanode.dto.response.PdfSignResponse;
import kz.ncanode.dto.response.PdfVerificationResponse;
import kz.ncanode.dto.tsp.TsaPolicy;
import kz.ncanode.exception.ServerException;
import kz.ncanode.exception.NoSignaturesFoundException;
import kz.ncanode.wrapper.CertificateWrapper;
import kz.ncanode.wrapper.KeyStoreWrapper;
import kz.ncanode.wrapper.KalkanWrapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
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

			// Load PDF document
			PDDocument document = PDDocument.load(new ByteArrayInputStream(pdfBytes));

			// Apply PDF signers
			for (PdfSignRequest.PdfSigner pdfSigner : pdfSignRequest.getSigners()) {
				var keyStoreWrapper = kalkanWrapper.read(List.of(pdfSigner.getSigner())).get(0);

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

				document.addSignature(signature, new PdfSignatureInterface(keyStoreWrapper, pdfSignRequest.isWithTsp(),
						pdfSignRequest.getTsaPolicy()));
			}

			// Save signed PDF
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
			document.saveIncremental(outputStream);
			document.close();

			return PdfSignResponse.builder()
					.pdf(Base64.getEncoder().encodeToString(outputStream.toByteArray()))
					.build();

		} catch (Exception e) {
			log.error("Error signing PDF", e);
			throw new ServerException("Error signing PDF: " + e.getMessage(), e);
		}
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

			// Get all signatures
			List<PDSignature> signatures = document.getSignatureDictionaries();

			// Check if PDF has any signatures
			if (signatures.isEmpty()) {
				throw new NoSignaturesFoundException("PDF document contains no digital signatures");
			}

			for (PDSignature signature : signatures) {
				PdfSignerInfo signerInfo = verifySignature(signature, pdfVerifyRequest, pdfBytes);
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
			byte[] originalPdfBytes) {
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

				boolean chainAndRevoOk = certificateWrapper.isValid(new Date(), withOcsp, withCrl);
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
									new Date(),
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
		private final TsaPolicy tsaPolicy;

		public PdfSignatureInterface(KeyStoreWrapper keyStoreWrapper, boolean withTsp, TsaPolicy tsaPolicy) {
			this.keyStoreWrapper = keyStoreWrapper;
			this.withTsp = withTsp;
			this.tsaPolicy = tsaPolicy;
		}

		@Override
		public byte[] sign(InputStream content) throws IOException {
			try {
				X509Certificate cert = keyStoreWrapper.getCertificate().getX509Certificate();
				PrivateKey privateKey = keyStoreWrapper.getPrivateKey();

				// Convert InputStream to byte array
				ByteArrayOutputStream baos = new ByteArrayOutputStream();
				byte[] buffer = new byte[1024];
				int length;
				while ((length = content.read(buffer)) != -1) {
					baos.write(buffer, 0, length);
				}
				byte[] contentBytes = baos.toByteArray();

				// Create CMS signed data
				CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

				// Add signer using the same pattern as CmsService
				generator.addSigner(privateKey, cert,
						kz.ncanode.util.Util.getDigestAlgorithmOidBYSignAlgorithmOid(cert.getSigAlgOID()));

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
					String useTsaPolicy = Optional.ofNullable(tsaPolicy).map(TsaPolicy::getPolicyId)
							.orElse(TsaPolicy.TSA_GOST2015_POLICY.getPolicyId());

					SignerInformationStore signerStore = signedData.getSignerInfos();
					List<SignerInformation> signers = new ArrayList<>();

					for (Object signer : signerStore.getSigners()) {
						signers.add(tspService.addTspToSigner((SignerInformation) signer, cert, useTsaPolicy));
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

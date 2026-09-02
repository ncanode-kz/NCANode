package kz.ncanode.service;

import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.ocsp.BasicOCSPResp;
import kz.gov.pki.kalkan.ocsp.OCSPResp;
import kz.gov.pki.kalkan.ocsp.RevokedStatus;
import kz.gov.pki.kalkan.ocsp.SingleResp;
import kz.gov.pki.kalkan.tsp.TimeStampToken;
import kz.gov.pki.kalkan.tsp.TimeStampTokenInfo;
import kz.gov.pki.kalkan.util.encoders.Hex;
import kz.ncanode.dto.ades.AdesLevel;
import kz.ncanode.dto.ades.AdesSubIndication;
import kz.ncanode.dto.ades.AdesValidationStatus;
import kz.ncanode.dto.crl.CrlResult;
import kz.ncanode.dto.ocsp.OcspResult;
import kz.ncanode.dto.tsp.TspInfo;
import kz.ncanode.util.KalkanUtil;
import kz.ncanode.wrapper.CertificateWrapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.util.Date;
import java.util.List;
import java.util.Optional;

/**
 * Общая логика проверки AdES-профилей (XAdES / CAdES / PAdES): проверка меток времени,
 * определение уровня, «доказанное время подписи», POE-логика по дате отзыва, использование
 * вшитых в подпись CRL/OCSP и грейдинг статуса (упрощённый ETSI EN 319 102-1).
 *
 * <p>Не полный ETSI: без построения цепочки индикаций всех проверок, без проверки самих
 * archive-timestamp (только парсинг + genTime).
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AdesVerificationService {

    private final TspService tspService;

    public enum RevocationOutcome {
        GOOD, REVOKED_BEFORE_SIGNING, REVOKED_AFTER_SIGNING, UNKNOWN, MISSING, SKIPPED
    }

    /** Вшитые в подпись данные отзыва. */
    public record EmbeddedRevocation(List<X509CRL> crls, List<byte[]> ocspResponses) {
        public static EmbeddedRevocation empty() {
            return new EmbeddedRevocation(List.of(), List.of());
        }
    }

    /** Итог проверки одной подписи. */
    public record AdesSignatureReport(AdesValidationStatus status, AdesSubIndication subIndication, String message) {
        public boolean isValid() {
            return status == AdesValidationStatus.VALID;
        }
    }

    // --- метки времени ---

    /**
     * Возвращает метку времени, если она валидна и покрывает {@code timestampedData}.
     */
    public Optional<TimeStampToken> verifiedTimestamp(TimeStampToken token, byte[] timestampedData) {
        if (token == null || !tspService.verify(token, timestampedData)) {
            return Optional.empty();
        }
        return Optional.of(token);
    }

    public Date bestSignatureTime(Optional<TimeStampToken> verifiedSignatureTimestamp, Date fallback) {
        return verifiedSignatureTimestamp
            .map(token -> token.getTimeStampInfo().getGenTime())
            .orElse(fallback);
    }

    public AdesLevel detectLevel(boolean hasVerifiedTimestamp, boolean hasValidationData, boolean hasArchiveTimestamp) {
        if (hasArchiveTimestamp) {
            return AdesLevel.LTA;
        }
        if (hasValidationData) {
            return AdesLevel.LT;
        }
        if (hasVerifiedTimestamp) {
            return AdesLevel.T;
        }
        return AdesLevel.B;
    }

    public TspInfo toTspInfo(TimeStampTokenInfo info) {
        return TspInfo.builder()
            .serialNumber(new String(Hex.encode(info.getSerialNumber().toByteArray())))
            .genTime(info.getGenTime())
            .policy(info.getPolicy())
            .tsa(Optional.ofNullable(info.getTsa()).map(Object::toString).orElse(null))
            .tspHashAlgorithm(KalkanUtil.getHashingAlgorithmByOID(info.getMessageImprintAlgOID()))
            .hash(new String(Hex.encode(info.getMessageImprintDigest())))
            .build();
    }

    // --- отзыв ---

    /**
     * POE по дате отзыва: сертификат отозван, но дата отзыва позже доказанного времени подписи →
     * на момент подписи он был действителен.
     */
    public boolean revocationAcceptable(CertificateWrapper cert, Date bestSignatureTime) {
        if (cert.getCrlStatus() == null || cert.getCrlStatus().getResult() != CrlResult.REVOKED) {
            return true;
        }
        Date revocationDate = cert.getCrlStatus().getRevocationDate();
        return revocationDate != null && revocationDate.after(bestSignatureTime);
    }

    /**
     * Проверка отзыва сертификата подписанта на доказанное время подписи с приоритетом вшитых данных.
     *
     * @param signer            сертификат подписанта (с прикреплёнными онлайн-статусами)
     * @param bestSignatureTime доказанное время подписи
     * @param embedded          вшитые в подпись CRL/OCSP
     * @param checkOcsp         запрошена ли проверка OCSP
     * @param checkCrl          запрошена ли проверка CRL
     */
    public RevocationOutcome checkRevocation(CertificateWrapper signer, Date bestSignatureTime,
                                             EmbeddedRevocation embedded, boolean checkOcsp, boolean checkCrl) {
        if (!checkOcsp && !checkCrl) {
            return RevocationOutcome.SKIPPED;
        }

        final BigInteger serial = signer.getX509Certificate().getSerialNumber();
        final java.util.EnumSet<RevocationOutcome> seen = java.util.EnumSet.noneOf(RevocationOutcome.class);

        for (byte[] der : embedded.ocspResponses()) {
            RevocationOutcome outcome = fromEmbeddedOcsp(der, serial, bestSignatureTime);
            if (outcome != null) {
                seen.add(outcome);
            }
        }

        for (X509CRL crl : embedded.crls()) {
            if (!crl.getIssuerX500Principal().equals(signer.getIssuerX500Principal())) {
                continue;
            }
            var revoked = crl.getRevokedCertificate(signer.getX509Certificate());
            if (revoked == null) {
                seen.add(RevocationOutcome.GOOD);
            } else {
                seen.add(revoked.getRevocationDate() != null && revoked.getRevocationDate().after(bestSignatureTime)
                    ? RevocationOutcome.REVOKED_AFTER_SIGNING : RevocationOutcome.REVOKED_BEFORE_SIGNING);
            }
        }

        if (checkOcsp && signer.getOcspStatus() != null) {
            for (var status : signer.getOcspStatus()) {
                if (status.getResult() == OcspResult.REVOKED) {
                    seen.add(status.getRevocationTime() != null && status.getRevocationTime().after(bestSignatureTime)
                        ? RevocationOutcome.REVOKED_AFTER_SIGNING : RevocationOutcome.REVOKED_BEFORE_SIGNING);
                } else if (status.getResult() == OcspResult.ACTIVE) {
                    seen.add(RevocationOutcome.GOOD);
                }
            }
        }

        if (checkCrl && signer.getCrlStatus() != null) {
            if (signer.getCrlStatus().getResult() == CrlResult.REVOKED) {
                Date d = signer.getCrlStatus().getRevocationDate();
                seen.add(d != null && d.after(bestSignatureTime)
                    ? RevocationOutcome.REVOKED_AFTER_SIGNING : RevocationOutcome.REVOKED_BEFORE_SIGNING);
            } else if (signer.getCrlStatus().getResult() == CrlResult.ACTIVE) {
                seen.add(RevocationOutcome.GOOD);
            }
        }

        // самый строгий исход выигрывает
        for (RevocationOutcome o : List.of(RevocationOutcome.REVOKED_BEFORE_SIGNING,
                RevocationOutcome.REVOKED_AFTER_SIGNING, RevocationOutcome.UNKNOWN, RevocationOutcome.GOOD)) {
            if (seen.contains(o)) {
                return o;
            }
        }
        return RevocationOutcome.MISSING;
    }

    private RevocationOutcome fromEmbeddedOcsp(byte[] responseDer, BigInteger serial, Date bestSignatureTime) {
        try {
            OCSPResp resp = new OCSPResp(responseDer);
            if (resp.getStatus() != 0) {
                return null;
            }
            BasicOCSPResp basic = (BasicOCSPResp) resp.getResponseObject();
            for (SingleResp single : basic.getResponses()) {
                if (!serial.equals(single.getCertID().getSerialNumber())) {
                    continue;
                }
                Object status = single.getCertStatus();
                if (status == null) {
                    return RevocationOutcome.GOOD;
                }
                if (status instanceof RevokedStatus revoked) {
                    return revoked.getRevocationTime() != null && revoked.getRevocationTime().after(bestSignatureTime)
                        ? RevocationOutcome.REVOKED_AFTER_SIGNING : RevocationOutcome.REVOKED_BEFORE_SIGNING;
                }
                return RevocationOutcome.UNKNOWN;
            }
        } catch (Exception e) {
            log.warn("Cannot parse embedded OCSP response: {}", e.getMessage());
        }
        return null;
    }

    // --- грейдинг ---

    /**
     * Итоговый статус проверки подписи по ETSI-подобной логике.
     *
     * @param signerCertificatePresent    найден ли сертификат подписанта
     * @param cryptographicallyValid      верна ли крипто-подпись
     * @param signingCertificateHashValid совпадает ли хеш в SigningCertificateV2 ({@code true}, если не проверяется)
     * @param signatureTimestampPresent   есть ли метка времени
     * @param signatureTimestampValid     валидна ли метка времени
     * @param signerCertificate           сертификат подписанта (с прикреплённым издателем)
     * @param bestSignatureTime           доказанное время подписи
     * @param revocation                  результат проверки отзыва
     */
    public AdesSignatureReport grade(boolean signerCertificatePresent, boolean cryptographicallyValid,
                                     boolean signingCertificateHashValid, boolean signatureTimestampPresent,
                                     boolean signatureTimestampValid, CertificateWrapper signerCertificate,
                                     Date bestSignatureTime, RevocationOutcome revocation) {
        if (!signerCertificatePresent || signerCertificate == null) {
            return report(AdesValidationStatus.INDETERMINATE, AdesSubIndication.NO_SIGNING_CERTIFICATE_FOUND,
                "Signer certificate not found");
        }
        if (!cryptographicallyValid) {
            return report(AdesValidationStatus.INVALID, AdesSubIndication.SIG_CRYPTO_FAILURE,
                "Signature value does not verify");
        }
        if (!signingCertificateHashValid) {
            return report(AdesValidationStatus.INVALID, AdesSubIndication.CERT_HASH_MISMATCH,
                "SigningCertificateV2 digest does not match the signer certificate");
        }
        if (signatureTimestampPresent && !signatureTimestampValid) {
            return report(AdesValidationStatus.INDETERMINATE, AdesSubIndication.TIMESTAMP_INVALID,
                "Signature timestamp failed verification");
        }
        if (!signerCertificate.isDateValid(bestSignatureTime)) {
            return report(AdesValidationStatus.INDETERMINATE, AdesSubIndication.OUT_OF_BOUNDS_NO_POE,
                "Signer certificate outside its validity period at " + bestSignatureTime);
        }
        if (signerCertificate.getIssuerCertificate() == null
            || !signerCertificate.getIssuerCertificate().isDateValid(bestSignatureTime)) {
            return report(AdesValidationStatus.INDETERMINATE, AdesSubIndication.CHAIN_INCOMPLETE,
                "No trusted issuer certificate for the signer");
        }
        return switch (revocation) {
            case REVOKED_BEFORE_SIGNING -> report(AdesValidationStatus.INVALID, AdesSubIndication.CERT_REVOKED,
                "Signer certificate was revoked before the proven signing time");
            case REVOKED_AFTER_SIGNING, GOOD, SKIPPED -> report(AdesValidationStatus.VALID, null, "OK");
            case MISSING -> report(AdesValidationStatus.INDETERMINATE, AdesSubIndication.REVOCATION_DATA_MISSING,
                "No revocation data covering " + bestSignatureTime);
            case UNKNOWN -> report(AdesValidationStatus.INDETERMINATE, AdesSubIndication.REVOCATION_DATA_MISSING,
                "Revocation status unknown for the signer certificate");
        };
    }

    /** Совместимость с прежним булевым API. */
    public boolean signerCertificateValid(CertificateWrapper cert, Date bestSignatureTime,
                                          boolean timestamped, boolean checkOcsp, boolean checkCrl) {
        if (timestamped) {
            return cert.isDateValid(bestSignatureTime)
                && cert.getIssuerCertificate() != null
                && cert.getIssuerCertificate().isDateValid(bestSignatureTime)
                && revocationAcceptable(cert, bestSignatureTime);
        }
        return cert.isValid(bestSignatureTime, checkOcsp, checkCrl);
    }

    private static AdesSignatureReport report(AdesValidationStatus status, AdesSubIndication sub, String message) {
        return new AdesSignatureReport(status, sub, message);
    }
}

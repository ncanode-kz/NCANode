package kz.ncanode.dto.tsp;

import kz.gov.pki.kalkan.asn1.knca.KNCAObjectIdentifiers;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public enum TsaPolicy {
    TSA_GOST2015_POLICY(KNCAObjectIdentifiers.tsa_gost2015_policy.getId()),
    TSA_GOST_POLICY(KNCAObjectIdentifiers.tsa_gost_policy.getId()),
    TSA_GOSTGT_POLICY(KNCAObjectIdentifiers.tsa_gostgt_policy.getId()),

    ;

    @Getter
    private final String policyId;
}

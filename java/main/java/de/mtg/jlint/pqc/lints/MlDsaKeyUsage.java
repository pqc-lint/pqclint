package de.mtg.jlint.pqc.lints;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;

import de.mtg.jlint.pqc.util.PQCUtils;
import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "e_ml_dsa_key_usage",
        description = "A certificate with an ML-DSA public key must only have one or more of the following key usage values: digitalSignature, nonRepudiation, keyCertSign, cRLSign",
        citation = "Section 5, Internet X.509 Public Key Infrastructure: Algorithm Identifiers for ML-DSA, https://www.ietf.org/archive/id/draft-ietf-lamps-dilithium-certificates-04.txt",
        source = Source.PQC,
        effectiveDate = EffectiveDate.ZERO)
public class MlDsaKeyUsage implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        byte[] rawKeyUsage = certificate.getExtensionValue(Extension.keyUsage.getId());

        KeyUsage keyUsage = KeyUsage.getInstance(ASN1OctetString.getInstance(rawKeyUsage).getOctets());

        if (keyUsage.hasUsages(KeyUsage.keyEncipherment)) {
            return LintResult.of(Status.ERROR);
        }
        if (keyUsage.hasUsages(KeyUsage.keyAgreement)) {
            return LintResult.of(Status.ERROR);
        }
        if (keyUsage.hasUsages(KeyUsage.dataEncipherment)) {
            return LintResult.of(Status.ERROR);
        }
        if (keyUsage.hasUsages(KeyUsage.decipherOnly)) {
            return LintResult.of(Status.ERROR);
        }
        if (keyUsage.hasUsages(KeyUsage.encipherOnly)) {
            return LintResult.of(Status.ERROR);
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return PQCUtils.isPublicKeyMLDSA(certificate) && Utils.hasKeyUsageExtension(certificate);
    }

}

package de.mtg.jlint.pqc.lints;

import java.security.cert.X509Certificate;

import de.mtg.jlint.pqc.util.ExternalLintUtils;
import de.mtg.jlint.pqc.util.PQCUtils;
import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;

@Lint(
        name = "e_ml_kem_ek_encoding",
        description = "An ML-KEM encryption key must be correctly encoded.",
        citation = "https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.ipd.pdf",
        source = Source.PQC,
        effectiveDate = EffectiveDate.ZERO)
public class MlKemEkEncoding implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {
        return ExternalLintUtils.getLintResult("e_ml_kem_ek_encoding", certificate, LintResult.of(Status.ERROR));
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return PQCUtils.isPublicKeyMLKEM(certificate);
    }

}

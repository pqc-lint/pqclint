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
        name = "e_ml_kem_ek_matrix_entry_frequency",
        description = "The matrix expanded from the seed, that is contained in the ML-KEM encapsulation key must not have too many occurrences of the same element.",
        citation = "https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.ipd.pdf",
        source = Source.PQC,
        effectiveDate = EffectiveDate.ZERO)
public class MlKemEkMatrixEntryFrequency implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {
        return ExternalLintUtils.getLintResult("e_ml_kem_ek_matrix_entry_frequency", certificate, LintResult.of(Status.ERROR));
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return PQCUtils.isPublicKeyMLKEM(certificate);
    }

}
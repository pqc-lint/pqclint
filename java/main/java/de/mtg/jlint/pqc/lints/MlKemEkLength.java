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

// Covers also e_ml_kem_ek_seed_length, e_ml_kem_ek_matrix_dimension, e_ml_kem_ek_vector_dimension
// e_ml_kem_ek_matrix_entries, e_ml_kem_ek_vector_entries
@Lint(
        name = "e_ml_kem_ek_length",
        description = "An encoded ML-KEM encapsulation key must be of the correct length.",
        citation = "https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.ipd.pdf",
        source = Source.PQC,
        effectiveDate = EffectiveDate.ZERO)
public class MlKemEkLength implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {
        return ExternalLintUtils.getLintResult("e_ml_kem_ek_length", certificate, LintResult.of(Status.ERROR));
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return PQCUtils.isPublicKeyMLKEM(certificate);
    }

}

package de.mtg.jlint.pqc.lints;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.util.encoders.Base64;

import de.mtg.jlint.pqc.util.KnownPublicKeys;
import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.ASN1CertificateUtils;

@Lint(
        name = "e_known_encoded_key",
        description = "A public key whose corresponding private key is known to be compromised, is weak, or is leaked must not be placed in a certificate. Checks if the public key in the certificate corresponds to a known private key. The encoded form of the public key is used.",
        citation = "RFC 9500",
        source = Source.PQC,
        effectiveDate = EffectiveDate.ZERO)
public class KnownEncodedKey implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {
        KnownPublicKeys knownPublicKeys;
        try {
            knownPublicKeys = KnownPublicKeys.getInstance();
            String encodedKey = Base64.toBase64String(ASN1CertificateUtils.getPublicKey(certificate).getEncoded());
            if (knownPublicKeys.contains(encodedKey)) {
                return LintResult.of(Status.ERROR);
            }
            return LintResult.of(Status.PASS);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException |
                 CertificateEncodingException | IOException ex) {
            return LintResult.of(Status.FATAL);
        }
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return true;
    }

}

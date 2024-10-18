package de.mtg.jlint.pqc.lints;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.util.encoders.Hex;

import de.mtg.jlint.pqc.util.PQCUtils;
import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.ASN1CertificateUtils;

@Lint(
        name = "e_ml_kem_public_key_aid_encoding",
        description = "The algorithm identifier in the public key of a certificate with an ML-DSA public key must have the correct encoding.",
        citation = "Section 4, Internet X.509 Public Key Infrastructure - Algorithm Identifiers for Kyber, https://www.ietf.org/archive/id/draft-ietf-lamps-kyber-certificates-03.txt",
        source = Source.PQC,
        effectiveDate = EffectiveDate.ZERO)
public class MlKemPublicKeyAidEncoding implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        final List<String> acceptedMLKEMPublicKeyAlgIDEncodings = Arrays.asList(
                "300d060b2b0601040181b01a050601", //ID_ALG_KYBER_512
                "300d060b2b0601040181b01a050602", //ID_ALG_KYBER_768
                "300d060b2b0601040181b01a050603" //ID_ALG_KYBER_1024
        );

        try {
            ASN1Sequence publicKeyAlgorithmIdentifier = ASN1CertificateUtils.getPublicKeyAlgorithmIdentifier(certificate);
            String hexEncoded = new String(Hex.encode(publicKeyAlgorithmIdentifier.getEncoded(ASN1Encoding.DER)));
            if (acceptedMLKEMPublicKeyAlgIDEncodings.contains(hexEncoded)) {
                return LintResult.of(Status.PASS);
            }
            return LintResult.of(Status.ERROR, String.format("Wrong encoding of ML-KEM public key. Got the unsupported %s", hexEncoded));
        } catch (CertificateEncodingException | IOException ex) {
            return LintResult.of(Status.FATAL);
        }
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return PQCUtils.isPublicKeyMLKEM(certificate);
    }

}
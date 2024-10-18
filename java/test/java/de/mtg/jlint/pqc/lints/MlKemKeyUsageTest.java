package de.mtg.jlint.pqc.lints;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Optional;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import de.mtg.jlint.pqc.util.PQCUtils;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Status;
import de.mtg.jlint.pqc.PQCCAExtension;

class MlKemKeyUsageTest {

    @RegisterExtension
    static PQCCAExtension pqccaExtension = new PQCCAExtension();

    @Test
    void passTest() throws Exception {

        PrivateKey privateKey = pqccaExtension.getMldsaPrivateKey();
        PublicKey publicKey = pqccaExtension.getMlkemPublicKey();

        LocalDateTime notBefore = LocalDateTime.now();
        LocalDateTime notAfter = notBefore.plusDays(100);
        X500Name issuerDN = new X500Name("CN=JZLint CA, C=DE");
        X500Name subjectDN = new X500Name("CN=PQC Certificate, C=DE");
        AlgorithmIdentifier signatureAID = new AlgorithmIdentifier(PQCUtils.ID_ML_DSA_65);

        KeyUsage keyUsage = new KeyUsage(KeyUsage.keyEncipherment);
        Extension ku = new Extension(Extension.keyUsage, true, keyUsage.toASN1Primitive().getEncoded(ASN1Encoding.DER));

        Optional<Extensions> extensions = PQCCAExtension.createExtensions(Arrays.asList(ku));

        V3TBSCertificateGenerator tbsCertificateGenerator = PQCCAExtension.getV3TBSCertificateGenerator(
                publicKey, signatureAID, notBefore, notAfter, BigInteger.ONE, issuerDN, subjectDN, extensions.orElse(null));

        X509Certificate certificate = PQCCAExtension.createCertificate(privateKey,
                PQCUtils.ID_ML_DSA_65.getId(), signatureAID, tbsCertificateGenerator.generateTBSCertificate());

        pqccaExtension.assertLintResult(LintResult.of(Status.PASS), new MlKemKeyUsage(), certificate);
    }

    @Test
    void naTest() throws Exception {
        X509Certificate certificate = PQCCAExtension.createECCertificate();
        pqccaExtension.assertLintResult(LintResult.of(Status.NA), new MlKemKeyUsage(), certificate);
    }

    @Test
    void errorTest() throws Exception {

        PrivateKey privateKey = pqccaExtension.getMldsaPrivateKey();
        PublicKey publicKey = pqccaExtension.getMlkemPublicKey();

        LocalDateTime notBefore = LocalDateTime.now();
        LocalDateTime notAfter = notBefore.plusDays(100);
        X500Name issuerDN = new X500Name("CN=JZLint CA, C=DE");
        X500Name subjectDN = new X500Name("CN=PQC Certificate, C=DE");
        AlgorithmIdentifier signatureAID = new AlgorithmIdentifier(PQCUtils.ID_ML_DSA_65);

        KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature);
        Extension ku = new Extension(Extension.keyUsage, true, keyUsage.toASN1Primitive().getEncoded(ASN1Encoding.DER));

        Optional<Extensions> extensions = PQCCAExtension.createExtensions(Arrays.asList(ku));

        V3TBSCertificateGenerator tbsCertificateGenerator = PQCCAExtension.getV3TBSCertificateGenerator(
                publicKey, signatureAID, notBefore, notAfter, BigInteger.ONE, issuerDN, subjectDN, extensions.orElse(null));

        X509Certificate certificate = PQCCAExtension.createCertificate(privateKey,
                PQCUtils.ID_ML_DSA_65.getId(), signatureAID, tbsCertificateGenerator.generateTBSCertificate());

        pqccaExtension.assertLintResult(LintResult.of(Status.ERROR), new MlKemKeyUsage(), certificate);
    }

}

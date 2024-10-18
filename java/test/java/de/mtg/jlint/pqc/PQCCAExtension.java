package de.mtg.jlint.pqc;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.LintJSONResult;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Runner;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class PQCCAExtension implements BeforeAllCallback {

    private PrivateKey slhdsaPrivateKey;
    private PublicKey slhdsaPublicKey;

    private PrivateKey mldsaPrivateKey;
    private PublicKey mldsaPublicKey;

    private PrivateKey mlkemPrivateKey;
    private PublicKey mlkemPublicKey;

    public static X509Certificate createECCertificate()
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, OperatorCreationException,
            CertificateException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        AlgorithmParameterSpec algParSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        keyPairGenerator.initialize(algParSpec);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        X500Name issuerDN = new X500Name("CN=JZLint CA, C=DE");
        X500Name subjectDN = new X500Name("CN=PQC Certificate, C=DE");
        ZonedDateTime notBefore = ZonedDateTime.of(2023, 9, 1, 0, 0, 0, 0, ZoneId.of("UTC"));
        Date notBeforeDate = Date.from(notBefore.toInstant());
        Date noteAfterDate = Date.from(notBefore.plusYears(1).toInstant());

        X509v3CertificateBuilder certificateBuilder =
                new X509v3CertificateBuilder(issuerDN, BigInteger.ONE, notBeforeDate, noteAfterDate, subjectDN, subjectPublicKeyInfo);

        JcaContentSignerBuilder jcaContentSignerBuilder = new JcaContentSignerBuilder("SHA256WithECDSA");
        ContentSigner contentSigner = jcaContentSignerBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME).build(privateKey);
        X509CertificateHolder x509CertificateHolder = certificateBuilder.build(contentSigner);

        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(x509CertificateHolder);
    }

    public static V3TBSCertificateGenerator getV3TBSCertificateGenerator(PublicKey publicKey, AlgorithmIdentifier signature,
            LocalDateTime notBefore, LocalDateTime notAfter, BigInteger serialNumber, X500Name issuer,
            X500Name subject, Extensions extensions) {

        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        return getV3TBSCertificateGenerator(subjectPublicKeyInfo, signature, notBefore, notAfter, serialNumber, issuer, subject, extensions);
    }

    public static V3TBSCertificateGenerator getV3TBSCertificateGenerator(SubjectPublicKeyInfo subjectPublicKeyInfo, AlgorithmIdentifier signature,
            LocalDateTime notBefore, LocalDateTime notAfter, BigInteger serialNumber, X500Name issuer,
            X500Name subject, Extensions extensions) {

        V3TBSCertificateGenerator certificateGenerator = new V3TBSCertificateGenerator();

        certificateGenerator.setStartDate(new Time(Date.from(notBefore.toInstant(ZoneOffset.UTC))));
        certificateGenerator.setEndDate(new Time(Date.from(notAfter.toInstant(ZoneOffset.UTC))));
        certificateGenerator.setSubjectPublicKeyInfo(subjectPublicKeyInfo);
        certificateGenerator.setSubject(subject);
        certificateGenerator.setIssuer(issuer);
        certificateGenerator.setSerialNumber(new ASN1Integer(serialNumber));
        certificateGenerator.setSignature(signature);
        if (extensions != null) {
            certificateGenerator.setExtensions(extensions);
        }
        return certificateGenerator;
    }

    public static Optional<Extensions> createExtensions(List<Extension> extensions) {

        if (extensions == null || extensions.isEmpty()) {
            return Optional.empty();
        }

        ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
        extensions.forEach(extensionsGenerator::addExtension);
        return Optional.of(extensionsGenerator.generate());
    }

    public static X509Certificate createCertificate(PrivateKey privateKey, String signatureAlgorithm,
            AlgorithmIdentifier signatureAlgorithmIdentifier,
            TBSCertificate tbsCertificate)
            throws CertificateException, NoSuchAlgorithmException, SignatureException, IOException, NoSuchProviderException, InvalidKeyException {

        Signature signature = Signature.getInstance(signatureAlgorithm, BouncyCastleProvider.PROVIDER_NAME);
        signature.initSign(privateKey);
        signature.update(tbsCertificate.getEncoded(ASN1Encoding.DER));
        byte[] rawSignature = signature.sign();

        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(tbsCertificate);
        vector.add(signatureAlgorithmIdentifier);
        vector.add(new DERBitString(rawSignature));

        ASN1Sequence certSeq = new DERSequence(vector);

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
        try (InputStream is = new ByteArrayInputStream(certSeq.getEncoded(ASN1Encoding.DER))) {
            return (X509Certificate) certificateFactory.generateCertificate(is);
        }
    }

    @Override
    public void beforeAll(ExtensionContext extensionContext) throws Exception {

        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());

        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Dilithium", BouncyCastleProvider.PROVIDER_NAME);
            kpg.initialize(DilithiumParameterSpec.dilithium3);
            KeyPair keyPair = kpg.generateKeyPair();

            this.mldsaPrivateKey = keyPair.getPrivate();
            this.mldsaPublicKey = keyPair.getPublic();
        }

        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Sphincsplus", BouncyCastleProvider.PROVIDER_NAME);
            kpg.initialize(SPHINCSPlusParameterSpec.sha2_128s);
            KeyPair keyPair = kpg.generateKeyPair();

            this.slhdsaPrivateKey = keyPair.getPrivate();
            this.slhdsaPublicKey = keyPair.getPublic();
        }

        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("KYBER", BouncyCastlePQCProvider.PROVIDER_NAME);
            kpg.initialize(KyberParameterSpec.kyber768);
            KeyPair keyPair = kpg.generateKeyPair();

            this.mlkemPrivateKey = keyPair.getPrivate();
            this.mlkemPublicKey = keyPair.getPublic();
        }

    }

    public void assertLintResult(LintResult expectedResult, JavaLint lint, X509Certificate certificate) throws Exception {
        Runner runner = new Runner();
        LintJSONResult lintResult = runner.lintForClassName(certificate, lint.getClass().getCanonicalName());
        assertEquals(expectedResult.getStatus().name().toLowerCase(Locale.ROOT), lintResult.getResult());
    }

    public PrivateKey getSlhdsaPrivateKey() {
        return slhdsaPrivateKey;
    }

    public PublicKey getSlhdsaPublicKey() {
        return slhdsaPublicKey;
    }


    public PrivateKey getMldsaPrivateKey() {
        return mldsaPrivateKey;
    }

    public PublicKey getMldsaPublicKey() {
        return mldsaPublicKey;
    }

    public PrivateKey getMlkemPrivateKey() {
        return mlkemPrivateKey;
    }

    public PublicKey getMlkemPublicKey() {
        return mlkemPublicKey;
    }

}

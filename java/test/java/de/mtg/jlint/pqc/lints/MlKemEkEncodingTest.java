package de.mtg.jlint.pqc.lints;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import de.mtg.jlint.pqc.util.PQCUtils;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Status;
import de.mtg.jlint.pqc.PQCCAExtension;

class MlKemEkEncodingTest {

    @RegisterExtension
    static PQCCAExtension pqccaExtension = new PQCCAExtension();

    MlKemEkEncoding lint = new MlKemEkEncoding();

    @Test
    void passTest() throws Exception {

        PrivateKey privateKey = pqccaExtension.getMldsaPrivateKey();

        LocalDateTime notBefore = LocalDateTime.now();
        LocalDateTime notAfter = notBefore.plusDays(100);
        X500Name issuerDN = new X500Name("CN=JZLint CA, C=DE");
        X500Name subjectDN = new X500Name("CN=PQC Certificate, C=DE");
        AlgorithmIdentifier signatureAID = new AlgorithmIdentifier(PQCUtils.ID_ML_DSA_65);

        byte[] decode = Base64.decode(
                "TsiXssiaUYCUiMxb2gG0SzEvycYU27OSKHk1jYEQuypw+NVS2cskIVaiYcmTvSCL+ZddM2FHpyUIBVdi0QJatmXIacSqs9cEGmF6VGDKt6I01jg/mhdo93fMEhgorKldeKhdH2GY5iqRrOyh46AaP7uGpoW434Up0pjJnOZ2ZzknTakfLre1AOYbFjt7NdYy7mnLnTOOZyx1DZbIIeOe2rWxA/XLoGFY9AgWulFaTWousgODzbVZMwDIHJZ5SnY7IEQmWipPSXcsqixVNRSb9WgYLVCFxYcwT/FDlqMewKGqGhQpAjsv12UWprqFHEJgQ+F5R9HH6Yo0nxUqXvVd9JdiBWYooQcgU0a0wCGc8HLH7POai3moqXenHwJYmHgDs0I3DKNpCaI2HqYmwpBMumssW8VjyNcPikRpo9SswBaElOAAqKO8tfvEKhK283psxPS859oq23xFbQd3vFaTInCEWCWoOStMiLlt0hJeNAk85ACUnqQ09jQgmkiDO0g/N4GkswuMsRWq4gRQCjNdxjOJYNNBT3KTfdNWxUSCUdiJdue4WHgkOFsIXql4FjZzeoIvG7a1a4tj/JIvO2BbZGYOVqw+K5OAveWjmxNgADeLj+EkKrWPLJdm/Yp4J1aJpQSFUUwrBEA4auK8jFsIrZlVgLSjYxpbJ9axlONQlYEe8pKQPQoaBHbFyMaVP+BbcZJy/jaYPIAD4xFYNbWgTqkWgkd0ECAgtCaikZhM5ijJwXcpsxZW7benMJSthICRkrc7prmErwRWbPpwFNnJ1ryIUGeeKXC2ILFErxMzeSx4AAcBEmQ4WjQYS9RNJCIyjFKBYPcPcrKfJoCh29WsEThVfcEm0pWroRyk4eu5uXYlNrc515C67jC02YOms3B3BYAJBOYBE5Na9gS+TkvP4+I4fYpV83Qg+YM01LRd6LYTNzidZQaq6ByNr/x2EvukPPlIHkiWb8iqHjCAgfZOU+w1Q9ST31Ze8im8WYxx/IXK0mJiDOu8v6t+20ST11dWTNwnY+ik3UCJf5xn3LB7isyf+Wg16lh9Joa9B/qJJRtIQZircUukfENKQLszP/a1EEFZrvAlPoUE9Ewq8msMLkENtbusUpqRWDGT3CNKn7FwluxH4vqwXWJI2VQtFlhu1+MutTydDzSEDdNeCRKfjmeUriQEdhhLSyhuReuWWfaFDAfEWreJ5mFnVyhiqDCFJ4e+hwSKInVdrVcwoeAGbwGyehig5DiV2EYCrUGfsyrMhmJRh5igNOIBkaSjMruABdRvNoAn4DFWVOAP5ys85hKg48iQpWS1nClKVpUz5rgX4NYghbyL/lQL5paxWWc/WDh9S+xIxsqTl7YKR9gAlCMLDrPApGAgMmcjiuCeSauz0UGmxjG9qhOs/rc1xpNdnIUCYyIaCtaVNUxZyrkytnKccKOrrqKhWotRXvl/HCC+BTfPOVS1HqWEF7Feg7nKC8kh5du7KHAA3Be63uPFDQt2LIU4wngIKVRlBHOGgpSm/yl4IcqQIOdjkJmQ4zDNig64TJi6fUvXZph80nwTGYBIJ0OE22pL9skHhpRYok0=");

        ASN1BitString bitString = new DERBitString(decode);

        SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(new AlgorithmIdentifier(PQCUtils.ID_ALG_KYBER_768), bitString);
        V3TBSCertificateGenerator tbsCertificateGenerator = PQCCAExtension.getV3TBSCertificateGenerator(
                spki, signatureAID, notBefore, notAfter, BigInteger.ONE, issuerDN, subjectDN, null);

        X509Certificate certificate = PQCCAExtension.createCertificate(privateKey,
                PQCUtils.ID_ML_DSA_65.getId(), signatureAID, tbsCertificateGenerator.generateTBSCertificate());

        pqccaExtension.assertLintResult(LintResult.of(Status.PASS), lint, certificate);
    }

    @Test
    void naTest() throws Exception {
        X509Certificate certificate = PQCCAExtension.createECCertificate();
        pqccaExtension.assertLintResult(LintResult.of(Status.NA), lint, certificate);
    }

    @Test
    void errorTest() throws Exception {


        PrivateKey privateKey = pqccaExtension.getMldsaPrivateKey();

        LocalDateTime notBefore = LocalDateTime.now();
        LocalDateTime notAfter = notBefore.plusDays(100);
        X500Name issuerDN = new X500Name("CN=JZLint CA, C=DE");
        X500Name subjectDN = new X500Name("CN=PQC Certificate, C=DE");
        AlgorithmIdentifier signatureAID = new AlgorithmIdentifier(PQCUtils.ID_ML_DSA_65);

        byte[] decode = Base64.decode(
                "QHGaUAJ3lLRkGXQMSuUqlLpRQqUFHBNGAJEg8sh4bhGwlsQ7tqyG3cVGXOtgYCpWKdbLEdCopvYuXeir3LxBB+qoEyu6niMedaAmpJYDYJupqMAIgRS49pgii6wNGmU7q9epM6l0KqOWbNq6JDlIwvydu1XFhBVH2zJc/OShS1d1efgPeJunNkbF91iBgAB74DliZis0Eze9TmnKmoRWQXUILqU+rCdN31ER4siELLp+KpiQEbzLLAZCu1JkOtHMXsTMeIGGsuRiNpGHFGMUsvWtZCEoj9iHQPWJNmUsZWK1vekXQYy105iUsFU4pqJyGeJ3WctVTbw+QoOm+HK0JEFsQcsWV3wf5dKrK2AGQSEVwNDHTBcMnHJfXDQmBZAr9XUpvdxlRAmCMxE7SPizTjUSnHsmtgdeWIioK6idSrxAR6WsBIRAbGQSrijIPnsWlHlSw4MB8BaKy8imrKCRHomxFiIX+GoQT5iJXrkwANJLwHuq6smqNbGt3jCyYqW3I1terzMELKwrR9kO7sWN5HScurKHVqIywXeCslx89VW0YZBjSYBumwslDxWWs7pehcdbbGxyOyp41vxl12s9gQiOPWfCuihIKJhtEYVrUfhcPBAEl1E5+TgLMtmLI5BzRjBPysDEd0kB4zWWLVMlvqFj1KARZeGjtigfMEQohICMgTxcNRJRXUo43QRDiJKs7OEEX9RReZDE0IUELDAXUjUn0JaITwGxzeGXLJWTf2xvypmJpHwNGYM6l5gKF3eqJlhdDoEKjhaMzKcJZsudw1YaIEgBEMB0LiApIlzDWZh6Dbpi4QFvMdUx4gEb9mEFvwssC0Qsk8V8I+t/uPSfjRWbj8rFEumsa8ERYgTBfVQuohg5F2ArNKNi1bm7WPEjq/tDpplm7cUobDxZGGIRH2ce6prLciZ8tmIf4COgS4QzbvmJ3ulUMCa4iRuJIoyYFcp9MkFY1uy31EDCIaRN5tTLnqXMftTNLJOBfspqT2gWNPaBRaI5lqBxgmoqhbSnk5N18oh2z/ppbic4nxCUQkoR/HgesKCLqzfJ/Sl103Mw1fdlx6krmesQyKQaolM8vQalMMUKwnGniyywofNuaXNH8uxpCKOm6TlOC4gjrzC7a4g1a0YjY1py8NF4/Vw7kDk4FCiRtEyia3HHvnB7S+MPjgxKtIpa8QCd+7HNwUtZBhJwHJAQgVqP5XF8gTstIIx7gXAj+oLJ/2SSmhBM6DiK8LfP5uBXjSh95xOmh6wxI4xkhvmKktYPtJaDmCBGGcs8LXUunMSXdtS3wzVzZnaBZkTBEGAm/TaneUQk0wxbs7xg//FvL7E1Sbooa2DJbjIYEIFn8TKbajJ4DLpmRvJVp0B6HKcI4IyF7sichuGup3B3v6RMHyFkzjp5LmFm2vOa2BtbeLE/zhA6nqO9xiVt3lNmkgS4aLWDwMi8FZYZLadxkHaSR/I6JQZNcmPLTCiGv6J7BIIHkVYdgdkgJWOECpsTkNNcsUDG0UIkmmg2MfsDYDQyIsGQoGYB+GFTs1tVbMPwrzRmWdbZveIekzHo+QjADK0o5nu7GMGXJQ==");

        ASN1BitString bitString = new DERBitString(decode);

        SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(new AlgorithmIdentifier(PQCUtils.ID_ALG_KYBER_768), bitString);
        V3TBSCertificateGenerator tbsCertificateGenerator = PQCCAExtension.getV3TBSCertificateGenerator(
                spki, signatureAID, notBefore, notAfter, BigInteger.ONE, issuerDN, subjectDN, null);

        X509Certificate certificate = PQCCAExtension.createCertificate(privateKey,
                PQCUtils.ID_ML_DSA_65.getId(), signatureAID, tbsCertificateGenerator.generateTBSCertificate());

        pqccaExtension.assertLintResult(LintResult.of(Status.ERROR), lint, certificate);
    }

}

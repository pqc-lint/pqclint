package de.mtg.jlint.pqc.lints;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;

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

class KnownEncodedKeyTest {

    @RegisterExtension
    static PQCCAExtension pqccaExtension = new PQCCAExtension();

    @Test
    void passTest() throws Exception {
        X509Certificate certificate = PQCCAExtension.createECCertificate();
        pqccaExtension.assertLintResult(LintResult.of(Status.PASS), new KnownEncodedKey(), certificate);
    }

    @Test
    void errorTest() throws Exception {

        //https://www.ietf.org/archive/id/draft-ietf-lamps-dilithium-certificates-03.txt
        String encodedPublicKey = "MIIHtDANBgsrBgEEAQKCCwcGBQOCB6EAFyP2dnbMELz5lkTFG7YvOdqVF5km835e\n" +
                "   UHXNaynmIrWHeKMla2gHZTCAwgLWIr9RAh1K11KRvFf+HYMs3ykOrd4xQ2vgLsjP\n" +
                "   jU0bup+rgRK5gvm3Z37rm2jAXDzJNxeM5lEDTklz9BQwOdQGm1rI/MXeMGssnOG4\n" +
                "   a9QvNPERdcG7VpTAEEevuTWmOeiKK3+kNCpoMRZr4WkgeInRyVUZXUvbYKkbm1Yj\n" +
                "   2Mn2ZhgqFW4M1IJwq3LPDCAXZU9R0dTQCt9Ns04HQHNylARZya6TdW+F2k+pfZ3U\n" +
                "   BRGbdI0MbVkOxqgRTfdWLlcXCfPn9/qdbz2K18QKdEuBBtPdZxiwTePDS6XvXjEp\n" +
                "   KZg9bukd7Yxqhg+DPGQp+yQLW4H3lkOkq6mCNW2z86OVnja7xHYL8vAU8xDZ9IeL\n" +
                "   oAIJm37X+qLOMIrT7qJE6zx2k+cJBnxBMSErEmOGOHb+dMvZyn8O77EyOSJS5pyn\n" +
                "   70quzO8k+VieM8jc7ZJan3NUeC7F3Os45uAJzEa1ssKwMx+f4Dtz8GkSjjwCIdFA\n" +
                "   fp6MNzek90lPKqJuxL37NGDB9scH6nLQOKpikaYkBYxD/huNtAe/e9MEHFlD1/Uz\n" +
                "   bSWTN2qQ4UmdV7iJKtIvesDrzx7D6v5EUh9QGdt4D3dNI7NvdyOGrQXwMz8M1EOB\n" +
                "   RX7QbAySLAkpGtpjcqkyiW0nOmslMtgI1JPM0bSzx1DuIaWjG/jf6HKpu2Ev2UlN\n" +
                "   pYs8cMoFeHmJpzGUkGlFwE+nGysZOx708p98yDRrQyY/Fw6Qg1xzFle14CTqW86h\n" +
                "   sD4K0scryDnETg3ZXpwhfQncYfxBbnIIyvxn2AnyGjy6h2r0b1SC8xzxWP7tGaSX\n" +
                "   0H4sdGPvv1AIc6id4VhtrKZgau7JK24c4lqun3WgmZH3+/wyDeyf+Zrb8/DPK3N3\n" +
                "   ZI4R+xkZDzSkuFWLh5om8MykaFT6TNmc5Hc1kO039tgz0vqXpsQHir+EiFPbugEp\n" +
                "   JLoxmoCgdxy9RLvDkSjnDwyI4Hg1djp9nRhpTVjvMdoIw6dSyO11ilEwppm+dNIn\n" +
                "   Gxd6iO7yaE2tJ6UjIc+7tuKoZkzmsO6p4hN8VKhzXcVjnRr6xox4sD5u3esqtJly\n" +
                "   9lsMU0qZnqJU4jbBS3SQloj3m8pl4cdf/j6ZHNiAAnfX6hhUGZDetTEv7MICeSW0\n" +
                "   b77XO5i4udTcYQtLvdo7mmyzG/N8NNR1T9pw89GYJ1maJhC2JyYx3Qwedppk0xac\n" +
                "   BwWednYgQMMNEUKmAGoZxytTHtFfPhGQ4s7gZ6zw2CTiqAEGLfGj6lrwuBgXXAn+\n" +
                "   S8B7UwF4b4ReCpwdYO1N5AyWXAax5T67H5a/5VkiX8zT5lX6+/bAqT8waLIImE3Q\n" +
                "   bEK74kOgQvULbzLzVjqJYPiAF8RwPIWRxH8ocOAM+NG0pREiEgDlO0xrcW26PeIo\n" +
                "   pGEsxOfiZRq1CLIRFn2FyczJQ8xFwC7fWio3q91+RGr+hzgBE69HuT8C/Z/pBT/x\n" +
                "   Im+D4lM1l++Xyn1RAoHyfnZy+nQK9i4hZ3eGyvpYfjfNGN5S+cBHY7/pKcr/EFaE\n" +
                "   WgN97C4eTLD/SDxCoS9K25XEVFECHNfgY5NS3sfizlVrQqRIecoSLUhyqswlXYF8\n" +
                "   xgi58ZRh0oCGv6/4oyNROhwBi/aJYL0RRSYd5ZuARcs/aZ+QhdMOkprdzZSh4wDX\n" +
                "   n3Vw1Rm1GAJEDVEojLoFtpWroe4YdsFHDmkJodZl3PHZIOuwHRr8YsqcHwuXM5nW\n" +
                "   iGZRw+PoJP6gri+ev62U0jW5k7t7v35aF4ccBhwg4AVT2odFnj72hwD6df29LMIa\n" +
                "   Zebj4iagOADfdVJhNUis9YseJwJtmlCJqUAB/6BQsCqeleD9LldTMutN/mq67DSe\n" +
                "   z33nzBeLs0PnhtYiX2z3yjw4s+6/c4Q0o+fikm4t23A1Px8sDi72yplLRl67L6L8\n" +
                "   I4zXOW4eA9PFQFndAhDblmceVOoCmRuncXte56/8trdyGepF7+tm+79zKXeDkVkf\n" +
                "   XmyHbcipFPHg00EUDgt2Wovq63obQXHP9f1KWon8YGOmW5MJbBNWiu83RZvwX7YW\n" +
                "   6Z+STzC7aMzmQECmKEuiW1Zx6kcZnXFYDrlEiyit+lCiUyjqVbEJb3GJnOJM7Lmj\n" +
                "   WEhutG6MSdJFuP/LHc0xxjxrQeG776skEujPcIt+kWqYXpdKTthWbfiuqCKbs+Qa\n" +
                "   cGz3tRhyH2urDZC0LuZHF15AyQmSmRP4FcC9aMn6q4alx/+LUZwGvrjb4xJNAtqC\n" +
                "   aapC8vTyNxKBJhawlkSewVoI3c7ra0WKYJ7YGaHct1VeH9u47a7pu/hYC1dAPWd8\n" +
                "   kajqEv2JJyWk0rrCi5OzrIfxE9Bl9C4nFWCPsd61qGLmi7u+1MrdN3k6dk6TG/y5\n" +
                "   Qkn9iw7wFyoaq6p6RFtFFPnAJJDiHEMp/ZFfY9Rxquvb4EK6FjAHAtKejzEMte4x\n" +
                "   zXK4C4pBZTy+RTMvu7j0CGVlKRgSyj05LX2c22NY6YB1ZSoe9r8NFeRSOQ0ojHBf\n" +
                "   afbiN3jcuOA/nB1MHq6ll/VpLR9NIAJyC4Xh+isdDK4JIXesSD9iNA5CIVXMUlE4\n" +
                "   x5AXF2HOm4o=";

        String cleanedKey = encodedPublicKey.replaceAll(" ", "").replaceAll("\\R", "");

        PrivateKey privateKey = pqccaExtension.getMldsaPrivateKey();

        LocalDateTime notBefore = LocalDateTime.now();
        LocalDateTime notAfter = notBefore.plusDays(100);
        X500Name issuerDN = new X500Name("CN=JZLint CA, C=DE");
        X500Name subjectDN = new X500Name("CN=PQC Certificate, C=DE");
        AlgorithmIdentifier signatureAID = new AlgorithmIdentifier(PQCUtils.ID_ML_DSA_65);

        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(Base64.decode(cleanedKey));
        V3TBSCertificateGenerator tbsCertificateGenerator = PQCCAExtension.getV3TBSCertificateGenerator(
                spki, signatureAID, notBefore, notAfter, BigInteger.ONE, issuerDN, subjectDN, null);

        X509Certificate certificate = PQCCAExtension.createCertificate(privateKey,
                PQCUtils.ID_ML_DSA_65.getId(), signatureAID, tbsCertificateGenerator.generateTBSCertificate());

        pqccaExtension.assertLintResult(LintResult.of(Status.ERROR), new KnownEncodedKey(), certificate);
    }

}
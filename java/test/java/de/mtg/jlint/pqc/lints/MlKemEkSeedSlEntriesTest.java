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

class MlKemEkSeedSlEntriesTest {

    @RegisterExtension
    static PQCCAExtension pqccaExtension = new PQCCAExtension();

    MlKemEkSeedSlEntries lint = new MlKemEkSeedSlEntries();

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


        {
            byte[] decode = Base64.decode(
                    "kPlDP/JlfBysdalrBYmOXJCRtmO/88jD2LOO50VPmNhPkRSHMKZiuJOLMmnGkvJzuypJGzlNjUsnntG/RVNcbsS5slVrdpQVcRuNz0s0flLBKgp159Fau3BuDPI1ormJ8ptSq1hylvJ9yQuGHQRrlGTOrrwDPAnCqvE4lBOnmLZz+vOHzNB6HiBx8lu5lPif1dTIXiVbT3tuSNSw7JQlzwxN8PlHDxfDlKesdQKCoMen3fVKTKHNCVZpChG9QbwsAqW6UXU7NENOz8dcLFBcFFpI65aTIQOJKzoNpoMmPFNZdXBI98VT80V8fHFbLCSc35SO4fFRshgEHOFrSgpBIvmMc7aj0Kc6VxnNDkKNLyZUwzITTnkEmlCtoEQ18Uifx7JtzGnGbKI4SnpqFFZUGkdLeCYSpkWGDmQe4zsrVWxDVRwDsaADLkkIXqaMmITDPYi3V1aZ8tKQHrAuvaIP1WMMgyohFFJNEMelD1NZKVSFKEMefFUSx+Y7ihVB3qADsZMo8EIdzBCNyqZpTJyDuZuAwgep9zx2GOkBPuNbVZRMYxpu4LWvbbpdZfc+uHqptYabEAd5myalGAR/JWxjpWQQ5lhXWTowf6gCXRtOzGk8+/xwUXc1+hNybtuodNq9lmpUzdG9M3SIGeto+BKDWVsSO2Ij0vMdq6ON4XEx9RFhQyRnAeZAOYi+zAfN4WaPjnBIXazAQVgaKEwsXnxgeKlQZ2idfBBH1AkW3pW71AJkNFYWrawtxFm+HMKwXvSairYnWbw7wUetVtINurWZDXh8QBEz+byBXOBZwBYAigp2hyosX9Vy8SyMygW3GhlTgAxEfGZrzqpbkZo/hwczoqOd6HCdDNFUWkGYkxMTZbNfkvROPets0yi29/oGqoM9t9OORNJ7o8ZzsZM52kegJME06IkZXhJJUUEz0LU2uaOLxyBFwvkmFDqm2EVnyoFf7EpFXLwhRWNgXCqG86QxjpVbKCgY9Re5dfRHnSd12bGi1siaAbu3HGREnRIsP1TFmfBZUMk7LoJBJVR26Nw1iBtYpQsJ0TSd2vi9oDYfe1anjyNTZvJOnkvHO9ZJOUw7QjGMx2hmWXIwrjGgZJKDpdYULKamBNTHsWzBNdvD20MB+vF4GYUn6BAtxWu3UMuoXvgpMGs8WPMELetKAUejm5AopwRGmREIelwPQuay77fFW0SiYLa3uBlnqvcqdcTA5UNxj7AJlfh8YymICNKaH7XOjjRR7ggteeVxJzWW06Y1jtQM4uwl2oapKNXHR6ZNu7AzYvuHUtxHZzNHslyFTBFoNycMsjCCKKAN9mYZ1zMf1TS+I6Igpja8CDsg4lUNIxfEREm4DJjP3TkwLupN92S6InPIxrywo7KzACWsXcXOq5yn41hLKgizKmQMHsGRZ0Kn0GeM41huIqV09em0JIWkE9KCwgId99uIZ5xOvHwREGAK75syt2maLqgwLASuxok8C4gBajkOoWKR97dXkTy0EtbCH9cWSiJMygprvTaBEbQTBBl6PkzAGtNU/iqGbIGCg4SFhoeIiYqLjI6PkJqbnJ2dnp+goaKjpKWFwww=");
            ASN1BitString bitString = new DERBitString(decode);

            SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(new AlgorithmIdentifier(PQCUtils.ID_ALG_KYBER_768), bitString);
            V3TBSCertificateGenerator tbsCertificateGenerator = PQCCAExtension.getV3TBSCertificateGenerator(
                    spki, signatureAID, notBefore, notAfter, BigInteger.ONE, issuerDN, subjectDN, null);

            X509Certificate certificate = PQCCAExtension.createCertificate(privateKey,
                    PQCUtils.ID_ML_DSA_65.getId(), signatureAID, tbsCertificateGenerator.generateTBSCertificate());

            pqccaExtension.assertLintResult(LintResult.of(Status.ERROR), lint, certificate);
        }

        {
            byte[] decode = Base64.decode(
                    "kPlDP/JlfBysdalrBYmOXJCRtmO/88jD2LOO50VPmNhPkRSHMKZiuJOLMmnGkvJzuypJGzlNjUsnntG/RVNcbsS5slVrdpQVcRuNz0s0flLBKgp159Fau3BuDPI1ormJ8ptSq1hylvJ9yQuGHQRrlGTOrrwDPAnCqvE4lBOnmLZz+vOHzNB6HiBx8lu5lPif1dTIXiVbT3tuSNSw7JQlzwxN8PlHDxfDlKesdQKCoMen3fVKTKHNCVZpChG9QbwsAqW6UXU7NENOz8dcLFBcFFpI65aTIQOJKzoNpoMmPFNZdXBI98VT80V8fHFbLCSc35SO4fFRshgEHOFrSgpBIvmMc7aj0Kc6VxnNDkKNLyZUwzITTnkEmlCtoEQ18Uifx7JtzGnGbKI4SnpqFFZUGkdLeCYSpkWGDmQe4zsrVWxDVRwDsaADLkkIXqaMmITDPYi3V1aZ8tKQHrAuvaIP1WMMgyohFFJNEMelD1NZKVSFKEMefFUSx+Y7ihVB3qADsZMo8EIdzBCNyqZpTJyDuZuAwgep9zx2GOkBPuNbVZRMYxpu4LWvbbpdZfc+uHqptYabEAd5myalGAR/JWxjpWQQ5lhXWTowf6gCXRtOzGk8+/xwUXc1+hNybtuodNq9lmpUzdG9M3SIGeto+BKDWVsSO2Ij0vMdq6ON4XEx9RFhQyRnAeZAOYi+zAfN4WaPjnBIXazAQVgaKEwsXnxgeKlQZ2idfBBH1AkW3pW71AJkNFYWrawtxFm+HMKwXvSairYnWbw7wUetVtINurWZDXh8QBEz+byBXOBZwBYAigp2hyosX9Vy8SyMygW3GhlTgAxEfGZrzqpbkZo/hwczoqOd6HCdDNFUWkGYkxMTZbNfkvROPets0yi29/oGqoM9t9OORNJ7o8ZzsZM52kegJME06IkZXhJJUUEz0LU2uaOLxyBFwvkmFDqm2EVnyoFf7EpFXLwhRWNgXCqG86QxjpVbKCgY9Re5dfRHnSd12bGi1siaAbu3HGREnRIsP1TFmfBZUMk7LoJBJVR26Nw1iBtYpQsJ0TSd2vi9oDYfe1anjyNTZvJOnkvHO9ZJOUw7QjGMx2hmWXIwrjGgZJKDpdYULKamBNTHsWzBNdvD20MB+vF4GYUn6BAtxWu3UMuoXvgpMGs8WPMELetKAUejm5AopwRGmREIelwPQuay77fFW0SiYLa3uBlnqvcqdcTA5UNxj7AJlfh8YymICNKaH7XOjjRR7ggteeVxJzWW06Y1jtQM4uwl2oapKNXHR6ZNu7AzYvuHUtxHZzNHslyFTBFoNycMsjCCKKAN9mYZ1zMf1TS+I6Igpja8CDsg4lUNIxfEREm4DJjP3TkwLupN92S6InPIxrywo7KzACWsXcXOq5yn41hLKgizKmQMHsGRZ0Kn0GeM41huIqV09em0JIWkE9KCwgId99uIZ5xOvHwREGAK75syt2maLqgwLASuxok8C4gBajkOoWKR97dXkTy0EtbCH9cWSiJMygprvTaBEbQTBBl6PkzAGtNU/iqGbAABAgMEBQYHCAkQERITFBUWFxgZICEiIyQlJieFwww=");
            ASN1BitString bitString = new DERBitString(decode);

            SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(new AlgorithmIdentifier(PQCUtils.ID_ALG_KYBER_768), bitString);
            V3TBSCertificateGenerator tbsCertificateGenerator = PQCCAExtension.getV3TBSCertificateGenerator(
                    spki, signatureAID, notBefore, notAfter, BigInteger.ONE, issuerDN, subjectDN, null);

            X509Certificate certificate = PQCCAExtension.createCertificate(privateKey,
                    PQCUtils.ID_ML_DSA_65.getId(), signatureAID, tbsCertificateGenerator.generateTBSCertificate());

            pqccaExtension.assertLintResult(LintResult.of(Status.ERROR), lint, certificate);
        }

    }

}

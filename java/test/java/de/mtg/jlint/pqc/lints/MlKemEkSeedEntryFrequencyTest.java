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

import de.mtg.jlint.pqc.PQCCAExtension;
import de.mtg.jlint.pqc.util.PQCUtils;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Status;

class MlKemEkSeedEntryFrequencyTest {

    @RegisterExtension
    static PQCCAExtension pqccaExtension = new PQCCAExtension();

    MlKemEkSeedEntryFrequency lint = new MlKemEkSeedEntryFrequency();

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
                "JrkRkcoGHPoepigdH8V0eCiLzEbBClJV5Jde4SakRdJPiApQmyZCGtCgfwFM6VNnvOtcs0Jv7fqGtEOu7fmyNGixVPRpPMbKhulabGxLLhgICFCLFfUgc4Un/YytZnoD5esKJHbL7meyX7bP3NZQhugkI2hY3HKZ0fEl/7HN+tPL1bJW8saeGYCi91tXXQy/hmTPBRNAJXmE69iRUjBNGAtu0rp3JXq8syZQIZIElwucl5IPDlBDmWEc4mRAPtq42/nMlLQcH8e6hxw0aVkAd+cuPZcwQGCp4DBRFYGRoRBtSdIqSeJVqtIItcRwZcFwgKgZtkgftlg3nkkWnfAFB1VdT6x3kYiDRwGJKJmZoMW1kFiBlUp4IQphuoO4sTh1iokSoKuv91F8OPyt50gkeLZ5SNVmP/FMRWqEUFIwkKFkP/hPbAxgWUWQXecLOZdpLOFmJuOGMgAYV/aR1jpDQil4ePOeSeBWzydkDslFfyocaZKqCWjLP0Q6S5gyLWo8/OYColyyTfYNk+sMGrCJd7QhBHWM2lI8OUPMeznP17uEierHLFIGKMeR6WPPK2OeXDOiZWyqvEdAwZZ6q5gaADXMDIwi4jiknHggmHZpoXWFEyWwjTJdyaNq5yZSY3RCtOTKSyGtZ/Kld4YR0Ba2r8CeWIQ0UsTNtworg8zCGoFLmBM1r6w/CdcPI/xTlyEY+Em0S+VedGkg6TkozMBZHDU6b2polLRyzUHA2faKopaSnSlTMvlUjDhF/eACzOmvBjh5SYgg3MQaZJBixQBxY3PDB4gbO6eji4EGxIJpSrY1A0srldKOsTSX/6YMQDV6B4FCSTUG9IsH2aFs8wVAUCt1GdsPDIKrprnLe7s/WUmhzXp4VDmKhXJHGZNlsQW9kOKNQuqcD8BNAwZmevJDepFf3ey8WkVa2eNgeyBLpgG4j3gqTCSnVJnOXYeUvPklHph/6CZzXpd+GiapsloyhjJq1tAw4lWDLpkbY1c9O2VHeKMpgDxaoomR44eLecw9JAw6l9xd13YxYjQi2VKPbUU8Ukc8J5W/w3JRWEdXNjRcpaxSqEmoFtoucTmVYcnKUlAv1edJhknCXZgS/lOqiyFIv8nCGiYbbTZAbmBiNkS09embtoE32fARSwKol9SM1uHJFnpwPoYgpeuOv5bH+eNpYhepR7ESWqZl8px9v3gsghdA20KD9fihKUSdzscmGeRhZRlZnzxlxziz14Zq1sTK4ECqt8BIgTXLpyGFfVV8AVy0h1K7zwKD28dI2DDPEXBWfHYm8TMTuQwE28UsWuhJzumPwWwK7iTH1giwjvJ8HyQFvCWpftyhZofABEVwbHSuf7kzbLRabDmfnHiScUStAnKLT0Uf39GAbXK6q2GkbGCnqTw7BYqILrOYsbWaYSW9WvGy5HOdcxy+kTp5d5nFv+ONnipa/wJvc5C32wAHU/k5YaVjqAGqLfa/ppmhd/petbeC8HcNtURpN3AoAeYbDhRPzucv0NNsJjEZInMPuSCx3rdVqCSL86KRSetQADMAhAC1AHcAQACSAJYAFAAsAF0AXQC8cdZpKp+Qr8Y=");

        ASN1BitString bitString = new DERBitString(decode);

        SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(new AlgorithmIdentifier(PQCUtils.ID_ALG_KYBER_768), bitString);
        V3TBSCertificateGenerator tbsCertificateGenerator = PQCCAExtension.getV3TBSCertificateGenerator(
                spki, signatureAID, notBefore, notAfter, BigInteger.ONE, issuerDN, subjectDN, null);

        X509Certificate certificate = PQCCAExtension.createCertificate(privateKey,
                PQCUtils.ID_ML_DSA_65.getId(), signatureAID, tbsCertificateGenerator.generateTBSCertificate());

        pqccaExtension.assertLintResult(LintResult.of(Status.ERROR), lint, certificate);
    }

}

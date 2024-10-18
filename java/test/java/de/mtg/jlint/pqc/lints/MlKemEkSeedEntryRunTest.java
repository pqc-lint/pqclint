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

class MlKemEkSeedEntryRunTest {

    @RegisterExtension
    static PQCCAExtension pqccaExtension = new PQCCAExtension();

    MlKemEkSeedEntryRun lint = new MlKemEkSeedEntryRun();

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
                "RzEu/rdptldb9Ny/wQHCXFhtduIUNRmqweI+WusnfLS9AwmeY0cHoUAaGvQU7TtQx1qTIdSlrgfLILgQEuyx2IBDhjV6v7GJBIOSLZGLGPzK0RZk31SMJoBiBIkq99Z0hrRieFma7QQ8htZV3HQKSIUCybPNs6E341QfoMk/twMZSKLGvGivZaZe9peeK1Z0IJvNG2pvzbiO4XlOR0yNXeRBhJChM4yV93wc52Kqx6bPZjzKmRRgEgK5HijNNTeH3xdH/lhlfPmB6cSeSfsrvgBqAok4Axm43xvFaxW2YdexzNk4ASOiqpWGaIrC/KZofYoCAwBz6QAW63OrhdFxQ+u8FlsR69EAueiuLywZwSuNUFuGyUdezrfCE/NTLzcQ3xKl+deQwEICdMm5Fno34kFbo1Rfq+q+0oVN74BXKtybnLaADgMZJZiC84YpopFhFLN0LJsT6FMm9TSC95AsD4xB2Cg9UCuPvgCr+8R1SSN/6wkZ/lFNRdg8QeI4llk/OtKAjIuFbmC+d6qK1AiNmVQBzWdQrSu6y6ybLAd7VPSMfDhOZpim9XG5/7TK7UM7RaBqEIwX1fFx1ZOLfppnbTVR0KptztZ8erkGD2qQI/kjESGwYaWNt7k81bQ2yix1+mU2pIFBUdZ7RyUeiEhzFos4RggbK+QqtKjN0vJurynHpSsn40MVl0SS7pSpH4MB6DRykJu/4gFNExAvvms9AzPDHtlquoxxO9Qn9osGF4swmAXQYoBfwsYXHpnK+6StcQRETVu77ci9tPsZ1SAhh2JctGsW0swms6cs/LKf/sQJ27UvI3pUZCihIogpydNB/xG5nJtCFhqxfbyfwihWWhJ/H7o6gSZBqbRd0DEb6tqHcls1SUmVHIy91rbPnbgonlWrOgw7o2VBF+VvlLEGmPFrOtdW3xFlifxsBkss1jp/urBl8JOORSpnaoYSBKCkKmui3ctDzFQ0vmQvhrjLlUKZLKw7iWK1SkSwuIYkh8upMdCJWABQA3Ir5NSWUVR/eOXEf3AQ86h56JIWK9ZtiRF4FGa34UmFaFG6j+xRkBDKInclrvdb+PNX7cG1H6XHBuhDaVKeSAWoZ+mAunuoqUkWBeJj0AITuxWUwBUmj0ZbhBPFBiMSePXIPKUGfEZfoWiL4aXEBiu9s5kragCiDdMHxPaXcezF9MnNmRYNykRgMIoXXRAf7oCnVfyyRzIj0btZLiVTfTsRK7lxgtYIKuYidXNubXlglclNisNc2FqtBFt1ebOX27RcY7qy7KEFjkILy+B//6i76twMFCGs0VeIGVamjGGdc3NXTBMH6xgyrBC2a+N34FayExSQKoty4UR9ljY6LFgnE+Cfv1MxWom5LStRntRbxeFdQAC7zjfAchoUTfDHy1uKUnWdd+BpwYohO0gm91c18NrF7CnDjgmmKXUZ3otGfSMJigEXpbANemXIGte3ucrPnedBeKEC67BW/0xRl4mL0AKiDOETYjDLWtgwqJJbGKW5c1Wsr3sybFPHwKlBQLSEHMWqmcx5oFqptLS0LAvASHj3PwGT0jt6BIsbDPJKWlHj8UHZk2o=");

        ASN1BitString bitString = new DERBitString(decode);

        SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(new AlgorithmIdentifier(PQCUtils.ID_ALG_KYBER_768), bitString);
        V3TBSCertificateGenerator tbsCertificateGenerator = PQCCAExtension.getV3TBSCertificateGenerator(
                spki, signatureAID, notBefore, notAfter, BigInteger.ONE, issuerDN, subjectDN, null);

        X509Certificate certificate = PQCCAExtension.createCertificate(privateKey,
                PQCUtils.ID_ML_DSA_65.getId(), signatureAID, tbsCertificateGenerator.generateTBSCertificate());

        pqccaExtension.assertLintResult(LintResult.of(Status.ERROR), lint, certificate);
    }

}

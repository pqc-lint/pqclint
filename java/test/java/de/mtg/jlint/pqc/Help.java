package de.mtg.jlint.pqc;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.encoders.Hex;

import de.mtg.jlint.pqc.util.PQCUtils;

/**
 * This class will help us to update the code when OIDs are finalised.
 */
public class Help {

    public static void main(String[] args) throws IOException {
        printSLHDSAAIDs("acceptedSLHDSAPublicKeyAlgIDEncodings");
        System.out.println();
        System.out.println();
        printSLHDSAAIDs("acceptedSLHDSASignatureAlgIDEncodings");
        printMLDSAAIDs("acceptedMLDSAPublicKeyAlgIDEncodings");
        printMLDSAAIDs("acceptedMLDSASignatureAlgIDEncodings");
        printMLKEMAIDs("acceptedMLKEMPublicKeyAlgIDEncodings");
    }

    private static void printMLKEMAIDs(String variableName) throws IOException {
        System.out.printf("final List<String> %s = Arrays.asList(%n", variableName);

        {
            // parameters are absent
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCUtils.ID_ALG_KYBER_512);

            System.out.printf("\"%s\", //ID_ALG_KYBER_512%n", new String(Hex.encode(algorithmIdentifier.getEncoded(ASN1Encoding.DER))));

        }

        {
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCUtils.ID_ALG_KYBER_768);
            System.out.printf("\"%s\", //ID_ALG_KYBER_768%n", new String(Hex.encode(algorithmIdentifier.getEncoded(ASN1Encoding.DER))));
        }

        {
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCUtils.ID_ALG_KYBER_1024);
            System.out.printf("\"%s\" //ID_ALG_KYBER_1024%n", new String(Hex.encode(algorithmIdentifier.getEncoded(ASN1Encoding.DER))));
        }

        System.out.println(");");
    }

    private static void printMLDSAAIDs(String variableName) throws IOException {
        System.out.printf("final List<String> %s = Arrays.asList(%n", variableName);

        {
            // parameters are absent
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCUtils.ID_ML_DSA_44);

            System.out.printf("\"%s\", //ID_ML_DSA_44%n", new String(Hex.encode(algorithmIdentifier.getEncoded(ASN1Encoding.DER))));

        }

        {
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCUtils.ID_ML_DSA_65);
            System.out.printf("\"%s\", //ID_ML_DSA_65%n", new String(Hex.encode(algorithmIdentifier.getEncoded(ASN1Encoding.DER))));
        }

        {
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCUtils.ID_ML_DSA_87);
            System.out.printf("\"%s\" //ID_ML_DSA_87%n", new String(Hex.encode(algorithmIdentifier.getEncoded(ASN1Encoding.DER))));
        }

        System.out.println(");");
    }

    private static void printSLHDSAAIDs(String variableName) throws IOException {

        System.out.printf("final List<String> %s = Arrays.asList(%n", variableName);

        {
            // parameters are absent
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCUtils.ID_ALG_SLH_DSA_128S_SHAKE);

            System.out.printf("\"%s\", //SLH_DSA_128S_SHAKE%n", new String(Hex.encode(algorithmIdentifier.getEncoded(ASN1Encoding.DER))));

        }

        {
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCUtils.ID_ALG_SLH_DSA_128F_SHAKE);
            System.out.printf("\"%s\", //SLH_DSA_128F_SHAKE%n", new String(Hex.encode(algorithmIdentifier.getEncoded(ASN1Encoding.DER))));
        }

        {
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCUtils.ID_ALG_SLH_DSA_128S_SHA2);
            System.out.printf("\"%s\", //SLH_DSA_128S_SHA2%n", new String(Hex.encode(algorithmIdentifier.getEncoded(ASN1Encoding.DER))));
        }

        {
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCUtils.ID_ALG_SLH_DSA_128F_SHA2);
            System.out.printf("\"%s\", //SLH_DSA_128F_SHA2%n", new String(Hex.encode(algorithmIdentifier.getEncoded(ASN1Encoding.DER))));
        }

        {

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCUtils.ID_ALG_SLH_DSA_192S_SHAKE);
            System.out.printf("\"%s\", //SLH_DSA_192S_SHAKE%n", new String(Hex.encode(algorithmIdentifier.getEncoded(ASN1Encoding.DER))));
        }

        {

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCUtils.ID_ALG_SLH_DSA_192F_SHAKE);
            System.out.printf("\"%s\", //SLH_DSA_192F_SHAKE%n", new String(Hex.encode(algorithmIdentifier.getEncoded(ASN1Encoding.DER))));
        }

        {

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCUtils.ID_ALG_SLH_DSA_256S_SHAKE);
            System.out.printf("\"%s\", //SLH_DSA_256S_SHAKE%n", new String(Hex.encode(algorithmIdentifier.getEncoded(ASN1Encoding.DER))));
        }

        {

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCUtils.ID_ALG_SLH_DSA_256F_SHAKE);
            System.out.printf("\"%s\"  //SLH_DSA_256F_SHAKE%n", new String(Hex.encode(algorithmIdentifier.getEncoded(ASN1Encoding.DER))));
        }

        System.out.println(");");
    }
}

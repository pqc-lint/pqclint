package de.mtg.jlint.pqc.util;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Properties;

import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.ASN1CertificateUtils;

public class ExternalLintUtils {

    private static final String JZLINT_PROPERTIES = "jzlint.properties";

    private static final String PROPERTY_NAME_TMP_DIR = "tmp.dir";
    private static final String PROPERTY_NAME_EXECUTABLE_PATH = "executable.path";
    private static final String PROPERTY_NAME_DELETE_FILES = "delete.files";
    private static final String PASS = "Pass";
    private static final String TRUE = "true";

    public static LintResult getLintResult(String lintName, X509Certificate certificate, LintResult notPassResult) {

        String encodedPublicKey;
        try {
            encodedPublicKey = ASN1CertificateUtils.getPublicKeySubjectPublicKeyBase64Encoded(certificate);
        } catch (CertificateEncodingException ex) {
            return LintResult.of(Status.FATAL);
        }
        String id = PQCUtils.toHexDigest(encodedPublicKey);

        ExternalLintRequest externalLintRequest = new ExternalLintRequest(lintName, id, encodedPublicKey);

        Properties properties = new Properties();


        try (FileInputStream fis = new FileInputStream(JZLINT_PROPERTIES)) {
            properties.load(fis);
        } catch (IOException ioException) {
            return LintResult.of(Status.FATAL);
        }

        String tmpDirectory = properties.getProperty(PROPERTY_NAME_TMP_DIR);
        String executablePath = properties.getProperty(PROPERTY_NAME_EXECUTABLE_PATH);

        Path tmpReq = Paths.get(tmpDirectory, "%s_%s.req.json".formatted(lintName, id));
        Path tmpResp = Paths.get(tmpDirectory, "%s_%s.resp.json".formatted(lintName, id));

        try {

            Files.writeString(tmpReq, externalLintRequest.getOutput());

            ProcessBuilder processBuilder = new ProcessBuilder(executablePath, "lint", "-f", tmpReq.toString(), "-r", tmpResp.toString());
            Process process = processBuilder.start();

            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
            StringBuilder builder = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                builder.append(line);
                builder.append(System.lineSeparator());
            }

            ExternalLintResponse response = new ExternalLintResponse(Files.readString(tmpResp));

            if (PASS.equalsIgnoreCase(response.getResult())) {
                return LintResult.of(Status.PASS);
            }

            return notPassResult;
        } catch (IOException ioException) {
            return LintResult.of(Status.FATAL);
        } finally {
            String deleteFiles = properties.getProperty(PROPERTY_NAME_DELETE_FILES);
            if (TRUE.equalsIgnoreCase(deleteFiles)) {
                try {
                    Files.delete(tmpReq);
                    Files.delete(tmpResp);
                } catch (IOException e) {
                    // silently ignore
                }
            }
        }
    }

}

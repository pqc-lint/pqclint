package de.mtg.jlint.pqc.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

public class KnownPublicKeys {

    private static KnownPublicKeys knownPublicKeys;

    private final List<String> bas64EncodedPublicKeys;

    private KnownPublicKeys(List<String> bas64EncodedPublicKeys) {
        this.bas64EncodedPublicKeys = bas64EncodedPublicKeys;
    }

    public static synchronized KnownPublicKeys getInstance() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {

        if (knownPublicKeys == null) {
            List<String> bas64EncodedPublicKeys = new ArrayList<>();
            String content = getContent();
            String[] keys = content.split("-----END");

            for (int i = 0; i < keys.length - 1; i++) {
                String base64EncodedPublicKey = getBase64EncodedPublicKey(keys[i]);
                bas64EncodedPublicKeys.add(base64EncodedPublicKey);
            }
            knownPublicKeys = new KnownPublicKeys(bas64EncodedPublicKeys);
        }

        return knownPublicKeys;
    }

    private static String getContent() {
        byte[] buffer = new byte[1024];
        byte[] file;
        int length;
        ClassLoader classLoader = KnownPublicKeys.class.getClassLoader();
        try (InputStream inputStream = classLoader.getResourceAsStream("knownPublicKeys.dat");
                ByteArrayOutputStream baos = new ByteArrayOutputStream()) {

            while ((length = inputStream.read(buffer)) != -1) {
                baos.write(buffer, 0, length);
            }

            file = baos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        String content = new String(file, StandardCharsets.UTF_8);
        return content;
    }

    private static String getBase64EncodedPublicKey(String content)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {

        StringBuilder contentBuilder = new StringBuilder();
        String[] lines = content.split("\\R");
        boolean startAppending = false;
        boolean isDirectlyEncoded = false;
        boolean isRSAPrivate = false;
        for (String line : lines) {

            if (reachedEnd(line)) {
                startAppending = false;
            }

            if (startAppending) {
                contentBuilder.append(line.trim());
            }

            if (line.trim().startsWith("-----BEGIN PUBLIC KEY-----")) {
                // is directly encoded
                startAppending = true;
                isDirectlyEncoded = true;
            }

            if (line.trim().startsWith("-----BEGIN RSA PRIVATE KEY-----")) {
                // is directly encoded
                startAppending = true;
                isRSAPrivate = true;
            }
        }

        if (isDirectlyEncoded) {
            return contentBuilder.toString();
        }

        if (isRSAPrivate) {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.decode(contentBuilder.toString()));
            RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) keyFactory.generatePrivate(keySpec);
            PublicKey publicKey = keyFactory.generatePublic(new RSAPublicKeySpec(privateKey.getModulus(), privateKey.getPublicExponent()));
            byte[] encodedPublicKey = publicKey.getEncoded();
            return Base64.toBase64String(encodedPublicKey);
        }

        return null;
    }

    private static boolean reachedEnd(String line) {
        return line.trim().startsWith("-----END PUBLIC KEY-----") ||
                line.trim().startsWith("-----END RSA PRIVATE KEY-----");
    }

    public List<String> getEncodedPublicKeys() {
        return this.bas64EncodedPublicKeys;
    }

    public boolean contains(String publicKey) {
        return this.bas64EncodedPublicKeys.contains(publicKey);
    }

    public boolean contains(byte[] publicKey) {
        return this.bas64EncodedPublicKeys.contains(Base64.toBase64String(publicKey));
    }

}

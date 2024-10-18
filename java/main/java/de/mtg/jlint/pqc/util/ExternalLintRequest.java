/*
 * Copyright (c) MTG AG
 */
package de.mtg.jlint.pqc.util;

public class ExternalLintRequest {

    private String output;

    public ExternalLintRequest(String lintName, String id, String publicKey) {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("{\"lintName\":\"");
        stringBuilder.append(lintName);
        stringBuilder.append("\",\"id\":\"");
        stringBuilder.append(id);
        stringBuilder.append("\",\"publicKey\":\"");
        stringBuilder.append(publicKey);
        stringBuilder.append("\"}");
        this.output = stringBuilder.toString();
    }

    public String getOutput() {
        return output;
    }

}

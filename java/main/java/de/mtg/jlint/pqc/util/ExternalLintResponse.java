package de.mtg.jlint.pqc.util;

public class ExternalLintResponse {
    private String lintName;
    private String id;

    private String result;


    public ExternalLintResponse(String externalResponse) {
        this.lintName = getValue(externalResponse, "\"lintName\"");
        this.id = getValue(externalResponse, "\"id\"");
        this.result = getValue(externalResponse, "\"result\"");
    }


    public String getLintName() {
        return lintName;
    }

    public String getId() {
        return id;
    }

    public String getResult() {
        return result;
    }

    private static String getValue(String externalResponse, String name) {
        int firstStart = externalResponse.indexOf(name);
        int secondStart = firstStart + name.length();
        int effectiveStart = externalResponse.indexOf("\"", secondStart);
        int end = externalResponse.indexOf("\"", effectiveStart + 1);
        return externalResponse.substring(effectiveStart + 1, end);
    }

}

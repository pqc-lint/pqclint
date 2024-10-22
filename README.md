The tool runs under Windows.

First download and install Java 17 for Windows: https://adoptium.net/de/temurin/releases/?version=17

Open a cmd window and change to the directory where you donwloaded the files.

Run: java -jar lintTool.jar mlkem.crt -includeSources PQC -p

This lints the certificate mlkem.crt which contains a valid ML-KEM key.

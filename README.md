# IoT Device Digital Forensics and Incident Analysis Toolkit

A small Java 17 command-line mini-project that hashes a text evidence file, scans it with explainable rules, and writes a plain-text incident report. It uses only the Java standard library at runtime; Maven is used only to build the project.

## Project structure

```text
iot-forensics-toolkit/
├── pom.xml
├── sample-iot.log
├── README.md
└── src/main/java/edu/college/iotforensics/
    ├── AnalysisResult.java
    ├── EvidenceManager.java
    ├── LogParser.java
    ├── Main.java
    ├── ReportGenerator.java
    └── SecurityAlert.java
```

## What each module does

- `EvidenceManager`: streams the evidence file through SHA-256 so large files do not need to be loaded into memory.
- `LogParser`: scans UTF-8 text line by line; alerts on three failed logins from the same source, connection requests from addresses outside the allowlist, errors, and reboot/restart events. Alert timestamps and line numbers are retained.
- `ReportGenerator`: writes the file path, digest, before/after integrity result, line count, and findings to a readable text report.
- `Main`: accepts command-line arguments or prompts for the evidence path, runs the analysis, and writes the report.

The parser is a teaching/demo rules engine, not a full SIEM or a guarantee that all attacks will be identified. Without an explicit allowlist, loopback and RFC1918 private IPv4 addresses are treated as trusted; other IPv4 addresses in connection events are flagged. Supplying an allowlist makes it authoritative, so every source address not listed is flagged.

## Compile and run with Java commands

From the project root with JDK 17+. On Windows PowerShell:

```powershell
New-Item -ItemType Directory -Force out | Out-Null
$sources = Get-ChildItem -Recurse src/main/java -Filter *.java | ForEach-Object FullName
javac -d out $sources
java -cp out edu.college.iotforensics.Main sample-iot.log analysis-report.txt
```

On macOS/Linux:

```sh
mkdir -p out
javac -d out src/main/java/edu/college/iotforensics/*.java
java -cp out edu.college.iotforensics.Main sample-iot.log analysis-report.txt
```

To pass a custom allowlist, give a comma-separated third argument:

```sh
java -cp out edu.college.iotforensics.Main sample-iot.log analysis-report.txt 192.168.1.10,192.168.1.20
```

To be prompted for a path, run without arguments:

```sh
java -cp out edu.college.iotforensics.Main
```

## Compile and run with Maven

From the project root, with Maven and JDK 17+ installed:

```sh
mvn package
java -jar target/iot-forensics-toolkit-1.0.0.jar sample-iot.log analysis-report.txt
```

Optional allowlist:

```sh
java -jar target/iot-forensics-toolkit-1.0.0.jar sample-iot.log analysis-report.txt 192.168.1.10
```

## Sample log

`sample-iot.log` is included at the project root. It has normal activity plus failed logins, an external connection, a device error, and a reboot so the rules have findings to report.

## Evidence integrity note

The report records the SHA-256 digest computed before parsing and compares it with a second digest afterward. A changed file is reported as an integrity failure and the CLI exits with status 3. Keep the original evidence read-only and preserve the generated report and digest in a real chain-of-custody process.

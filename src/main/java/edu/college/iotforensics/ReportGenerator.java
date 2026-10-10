package edu.college.iotforensics;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;

/** Writes a human-readable, plain-text analysis report. */
public final class ReportGenerator {
    private ReportGenerator() { }

    public static void write(Path reportPath, Path evidencePath, String sha256,
                             boolean integrityVerified, AnalysisResult result) throws IOException {
        StringBuilder report = new StringBuilder();
        report.append("IoT Device Forensics - Analysis Report\n")
                .append("=======================================\n")
                .append("Generated: ").append(Instant.now()).append('\n')
                .append("File analyzed: ").append(evidencePath.toAbsolutePath().normalize()).append('\n')
                .append("SHA-256: ").append(sha256).append('\n')
                .append("Integrity check (before/after analysis): ")
                .append(integrityVerified ? "PASS - file unchanged during analysis" : "FAIL - file changed during analysis").append('\n')
                .append("Total lines scanned: ").append(result.totalLines()).append('\n')
                .append("Alerts found: ").append(result.alerts().size()).append("\n\n");

        if (result.alerts().isEmpty()) {
            report.append("No suspicious indicators were detected by the configured rules.\n");
        } else {
            report.append("Security alerts\n---------------\n");
            for (SecurityAlert alert : result.alerts()) {
                report.append('[').append(alert.severity()).append("] ").append(alert.category())
                        .append(" | timestamp=").append(alert.timestamp())
                        .append(" | line=").append(alert.lineNumber())
                        .append(" | ").append(alert.message()).append('\n');
            }
        }
        Files.writeString(reportPath, report.toString(), StandardCharsets.UTF_8);
    }
}

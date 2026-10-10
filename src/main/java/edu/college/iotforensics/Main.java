package edu.college.iotforensics;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Set;
import java.util.Scanner;
import java.util.stream.Collectors;

/** Command-line entry point. Usage: Main [log-file] [report-file] [allowed-ip,allowed-ip,...] */
public final class Main {
    private Main() { }

    public static void main(String[] args) {
        try (Scanner scanner = new Scanner(System.in)) {
            Path evidence = args.length > 0 ? Path.of(args[0]) : promptForFile(scanner);
            if (!Files.isRegularFile(evidence) || !Files.isReadable(evidence)) {
                System.err.println("Error: evidence file does not exist or is not readable: " + evidence);
                System.exit(2);
            }
            Path report = args.length > 1 ? Path.of(args[1]) : Path.of("analysis-report.txt");
            Set<String> allowlist = args.length > 2
                    ? Arrays.stream(args[2].split(",")).map(String::trim).filter(s -> !s.isEmpty()).collect(Collectors.toSet())
                    : Set.of();

            String hashBefore = EvidenceManager.sha256(evidence);
            AnalysisResult findings = new LogParser(allowlist, 3).parse(evidence);
            String hashAfter = EvidenceManager.sha256(evidence);
            boolean unchanged = hashBefore.equals(hashAfter);
            ReportGenerator.write(report, evidence, hashBefore, unchanged, findings);

            System.out.println("Analysis complete. Lines scanned: " + findings.totalLines()
                    + ", alerts: " + findings.alerts().size());
            System.out.println("SHA-256: " + hashBefore);
            System.out.println("Integrity check: " + (unchanged ? "PASS" : "FAIL (evidence changed during analysis)"));
            System.out.println("Report written to: " + report.toAbsolutePath().normalize());
            if (!unchanged) System.exit(3);
        } catch (IOException ex) {
            System.err.println("Analysis failed: " + ex.getMessage());
            System.exit(1);
        }
    }

    private static Path promptForFile(Scanner scanner) {
        System.out.print("Enter path to IoT log file: ");
        return Path.of(scanner.nextLine().trim());
    }
}

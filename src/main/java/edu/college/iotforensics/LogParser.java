package edu.college.iotforensics;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Line-oriented parser for the sample IoT log format and similar plain-text logs. */
public final class LogParser {
    private static final Pattern TIMESTAMP = Pattern.compile("^\\[?([^\\] ]+T[^\\] ]+|\\d{4}-\\d{2}-\\d{2}[ T]\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?(?:Z|[+-]\\d{2}:?\\d{2})?)\\]?");
    private static final Pattern SOURCE_IP = Pattern.compile("(?i)(?:src(?:_ip)?|remote(?:_ip)?|client(?:_ip)?|from|ip)\\s*[=: ]\\s*['\"]?((?:\\d{1,3}\\.){3}\\d{1,3})");
    private static final Pattern FAILED_LOGIN = Pattern.compile("(?i)(failed\\s+(?:login|log\\s*in|auth(?:entication)?)|(?:login|log\\s*in|auth(?:entication)?)\\s+(?:failure|failed)|invalid\\s+password)");
    private static final Pattern CONNECTION = Pattern.compile("(?i)\\b(connect(?:ion)?|session)\\b");
    private static final Pattern ERROR = Pattern.compile("(?i)\\b(error|exception|fault|critical)\\b");
    private static final Pattern REBOOT = Pattern.compile("(?i)\\b(reboot(?:ed|ing)?|restart(?:ed|ing)?|power.?cycle)\\b");

    private final Set<String> allowedIps;
    private final int failedLoginThreshold;

    /** With no supplied allowlist, loopback and RFC1918 IPv4 addresses are treated as trusted. */
    public LogParser() {
        this(Set.of(), 3);
    }

    public LogParser(Set<String> allowedIps, int failedLoginThreshold) {
        if (failedLoginThreshold < 1) throw new IllegalArgumentException("Threshold must be at least 1");
        this.allowedIps = new HashSet<>();
        allowedIps.forEach(ip -> this.allowedIps.add(ip.trim()));
        this.failedLoginThreshold = failedLoginThreshold;
    }

    public AnalysisResult parse(Path file) throws IOException {
        List<SecurityAlert> alerts = new ArrayList<>();
        Map<String, Integer> failedByIp = new HashMap<>();
        Set<String> bruteForceReported = new HashSet<>();
        long lines = 0;

        try (BufferedReader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            String line;
            while ((line = reader.readLine()) != null) {
                lines++;
                String timestamp = extractTimestamp(line);
                Matcher sourceMatch = SOURCE_IP.matcher(line);
                String sourceIp = sourceMatch.find() ? sourceMatch.group(1) : null;

                if (FAILED_LOGIN.matcher(line).find()) {
                    String key = sourceIp == null ? "unknown" : sourceIp;
                    int count = failedByIp.merge(key, 1, Integer::sum);
                    if (count >= failedLoginThreshold && bruteForceReported.add(key)) {
                        alerts.add(new SecurityAlert("HIGH", "Brute-force", timestamp, (int) lines,
                                count + " or more failed login attempts from " + key));
                    }
                }

                if (CONNECTION.matcher(line).find() && sourceIp != null && !isAllowed(sourceIp)) {
                    alerts.add(new SecurityAlert("MEDIUM", "Unauthorized connection", timestamp, (int) lines,
                            "Connection request from non-allowlisted IP " + sourceIp));
                }
                if (ERROR.matcher(line).find()) {
                    alerts.add(new SecurityAlert("MEDIUM", "Device error", timestamp, (int) lines,
                            "Device error or fault recorded"));
                }
                if (REBOOT.matcher(line).find()) {
                    alerts.add(new SecurityAlert("MEDIUM", "Unexpected reboot", timestamp, (int) lines,
                            "Device reboot or restart recorded"));
                }
            }
        }
        return new AnalysisResult(lines, alerts);
    }

    private boolean isAllowed(String ip) {
        if (allowedIps.contains(ip)) return true;
        if (!allowedIps.isEmpty()) return false;
        // Conservative demo default: accept loopback and RFC1918 private IPv4 only.
        String[] octets = ip.split("\\.");
        try {
            int a = Integer.parseInt(octets[0]);
            int b = Integer.parseInt(octets[1]);
            int c = Integer.parseInt(octets[2]);
            int d = Integer.parseInt(octets[3]);
            if (a > 255 || b > 255 || c > 255 || d > 255) return false;
            return a == 10 || a == 127 || (a == 172 && b >= 16 && b <= 31)
                    || (a == 192 && b == 168);
        } catch (NumberFormatException ex) {
            return false;
        }
    }

    private static String extractTimestamp(String line) {
        Matcher matcher = TIMESTAMP.matcher(line);
        return matcher.find() ? matcher.group(1) : "unknown";
    }
}

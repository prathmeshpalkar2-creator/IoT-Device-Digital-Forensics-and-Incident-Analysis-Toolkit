package edu.college.iotforensics;

import java.util.List;

/** Immutable parser output for a single log file. */
public record AnalysisResult(long totalLines, List<SecurityAlert> alerts) {
    public AnalysisResult {
        alerts = List.copyOf(alerts);
    }
}

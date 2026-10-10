package edu.college.iotforensics;

/** One finding produced while analyzing a log. */
public record SecurityAlert(String severity, String category, String timestamp,
                            int lineNumber, String message) { }

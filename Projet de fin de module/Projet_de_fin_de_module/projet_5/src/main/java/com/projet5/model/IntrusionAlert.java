package com.projet5.model;

public class IntrusionAlert {
    private String type;
    private String description;
    private String severity;
    private String timestamp;

    public IntrusionAlert(String type, String description, String severity, String timestamp) {
        this.type = type;
        this.description = description;
        this.severity = severity;
        this.timestamp = timestamp;
    }

    public String getType() { return type; }
    public String getDescription() { return description; }
    public String getSeverity() { return severity; }
    public String getTimestamp() { return timestamp; }
}

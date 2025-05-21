package com.projet5.model;

public class PacketInfo {
    private String srcIP;
    private String dstIP;
    private String protocol;
    private int length;
    private String timestamp;

    public PacketInfo(String srcIP, String dstIP, String protocol, int length, String timestamp) {
        this.srcIP = srcIP;
        this.dstIP = dstIP;
        this.protocol = protocol;
        this.length = length;
        this.timestamp = timestamp;
    }

    public String getSrcIP() { return srcIP; }
    public String getDstIP() { return dstIP; }
    public String getProtocol() { return protocol; }
    public int getLength() { return length; }
    public String getTimestamp() { return timestamp; }
}

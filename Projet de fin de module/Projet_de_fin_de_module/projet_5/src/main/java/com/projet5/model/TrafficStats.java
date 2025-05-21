package com.projet5.model;

import java.util.concurrent.atomic.AtomicLong;

public class TrafficStats {

    private final AtomicLong totalPackets = new AtomicLong(0);
    private final AtomicLong totalBytes = new AtomicLong(0);

    private final AtomicLong tcpPackets = new AtomicLong(0);
    private final AtomicLong udpPackets = new AtomicLong(0);
    private final AtomicLong otherPackets = new AtomicLong(0);

    public void incrementPacketCount(int packetSize, String protocol) {
        totalPackets.incrementAndGet();
        totalBytes.addAndGet(packetSize);

        switch (protocol.toUpperCase()) {
            case "TCP":
                tcpPackets.incrementAndGet();
                break;
            case "UDP":
                udpPackets.incrementAndGet();
                break;
            default:
                otherPackets.incrementAndGet();
                break;
        }
    }

    public long getTotalPackets() {
        return totalPackets.get();
    }

    public long getTotalBytes() {
        return totalBytes.get();
    }

    public long getTcpPackets() {
        return tcpPackets.get();
    }

    public long getUdpPackets() {
        return udpPackets.get();
    }

    public long getOtherPackets() {
        return otherPackets.get();
    }

    public void reset() {
        totalPackets.set(0);
        totalBytes.set(0);
        tcpPackets.set(0);
        udpPackets.set(0);
        otherPackets.set(0);
    }
    public double getAveragePacketSize() {
        long packets = totalPackets.get();
        return packets > 0 ? (double) totalBytes.get() / packets : 0.0;
    }
}

package com.projet5.detection;

import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IcmpV4CommonPacket;
import com.projet5.model.IntrusionAlert;
import java.net.InetAddress;
import java.net.UnknownHostException;


import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;

public class IntrusionDetector {

    private PcapHandle handle;
    private ExecutorService executor;
    private Consumer<IntrusionAlert> alertCallback;

    private static final int SYN_FLOOD_THRESHOLD = 100;
    private static final int PORT_SCAN_THRESHOLD = 15;
    private static final int PING_FLOOD_THRESHOLD = 50;
    private static final int LARGE_PACKET_SIZE = 4000;
    private static final long TIME_WINDOW = 1000;

    private final Map<String, Integer> synCounter = new ConcurrentHashMap<>();
    private final Map<String, Map<Integer, Long>> portScanTracker = new ConcurrentHashMap<>();
    private final Map<String, Integer> icmpCounter = new ConcurrentHashMap<>();
    private final Map<String, Long> lastCleanupTime = new ConcurrentHashMap<>();

    public IntrusionDetector(Consumer<IntrusionAlert> alertCallback) {
        this.alertCallback = alertCallback;
        this.executor = Executors.newSingleThreadExecutor();
    }

    public void startCapture() {
        try {
            List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();
            if (interfaces == null || interfaces.isEmpty()) {
                System.out.println("Aucune interface réseau trouvée.");
                return;
            }

            // Choisir l'interface qui correspond à l’IP locale
            String localIp = InetAddress.getLocalHost().getHostAddress();
            PcapNetworkInterface nif = interfaces.stream()
                    .filter(i -> i.getAddresses().stream()
                            .anyMatch(a -> a.getAddress() != null && a.getAddress().getHostAddress().equals(localIp)))
                    .findFirst().orElse(interfaces.get(0));

            System.out.println("Interface utilisée : " + nif.getName());

            handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);

            executor.submit(() -> {
                try {
                    handle.loop(-1, (PacketListener) packet -> {
                        System.out.println("Paquet capturé...");
                        IntrusionAlert alert = analyzePacket(packet);
                        if (alert != null) {
                            System.out.println("Alerte générée : " + alert.getType());
                            alertCallback.accept(alert);
                        }
                    });
                } catch (Exception e) {
                    System.err.println("Erreur pendant la capture : " + e.getMessage());
                }
            });

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void stopCapture() {
        if (handle != null && handle.isOpen()) {
            try {
                handle.breakLoop();
                handle.close();
            } catch (NotOpenException e) {
                e.printStackTrace();
            }
        }
        if (executor != null && !executor.isShutdown()) {
            executor.shutdownNow();
        }
    }

    public IntrusionAlert analyzePacket(Packet packet) {
        cleanup();
        if (packet == null) return null;

        IntrusionAlert alert;
        alert = detectSynFlood(packet);
        if (alert != null) return alert;

        alert = detectPortScan(packet);
        if (alert != null) return alert;

        alert = detectPingFlood(packet);
        if (alert != null) return alert;

        alert = detectLargePacket(packet);
        return alert;
    }

    private IntrusionAlert detectSynFlood(Packet packet) {
        TcpPacket tcp = packet.get(TcpPacket.class);
        IpV4Packet ip = packet.get(IpV4Packet.class);
        if (tcp != null && ip != null && tcp.getHeader().getSyn() && !tcp.getHeader().getAck()) {
            String src = ip.getHeader().getSrcAddr().getHostAddress();
            int count = synCounter.getOrDefault(src, 0) + 1;
            synCounter.put(src, count);
            lastCleanupTime.put(src, System.currentTimeMillis());

            if (count > SYN_FLOOD_THRESHOLD) {
                return new IntrusionAlert("SYN Flood", "Attaque SYN flood depuis IP : " + src, "Élevé", getCurrentTimestamp());
            }
        }
        return null;
    }

    private IntrusionAlert detectPortScan(Packet packet) {
        TcpPacket tcp = packet.get(TcpPacket.class);
        IpV4Packet ip = packet.get(IpV4Packet.class);
        if (tcp != null && ip != null) {
            String src = ip.getHeader().getSrcAddr().getHostAddress();
            int port = tcp.getHeader().getDstPort().valueAsInt();

            portScanTracker.putIfAbsent(src, new ConcurrentHashMap<>());
            Map<Integer, Long> ports = portScanTracker.get(src);
            ports.put(port, System.currentTimeMillis());
            lastCleanupTime.put(src, System.currentTimeMillis());

            if (ports.size() > PORT_SCAN_THRESHOLD) {
                portScanTracker.remove(src);
                return new IntrusionAlert("Scan de ports", "Scan détecté depuis IP : " + src, "Moyen", getCurrentTimestamp());
            }
        }
        return null;
    }

    private IntrusionAlert detectPingFlood(Packet packet) {
        IcmpV4CommonPacket icmp = packet.get(IcmpV4CommonPacket.class);
        IpV4Packet ip = packet.get(IpV4Packet.class);
        if (icmp != null && ip != null) {
            String src = ip.getHeader().getSrcAddr().getHostAddress();
            int count = icmpCounter.getOrDefault(src, 0) + 1;
            icmpCounter.put(src, count);
            lastCleanupTime.put(src, System.currentTimeMillis());

            if (count > PING_FLOOD_THRESHOLD) {
                return new IntrusionAlert("ICMP Flood", "Ping flood détecté depuis IP : " + src, "Moyen", getCurrentTimestamp());
            }
        }
        return null;
    }

    private IntrusionAlert detectLargePacket(Packet packet) {
        if (packet.length() > LARGE_PACKET_SIZE) {
            IpV4Packet ip = packet.get(IpV4Packet.class);
            String src = (ip != null) ? ip.getHeader().getSrcAddr().getHostAddress() : "Inconnu";
            return new IntrusionAlert("Paquet volumineux", "Paquet suspect > " + LARGE_PACKET_SIZE + " octets depuis : " + src, "Faible", getCurrentTimestamp());
        }
        return null;
    }

    private void cleanup() {
        long now = System.currentTimeMillis();
        for (String ip : new HashSet<>(lastCleanupTime.keySet())) {
            if (now - lastCleanupTime.get(ip) > TIME_WINDOW) {
                synCounter.remove(ip);
                icmpCounter.remove(ip);
                portScanTracker.computeIfPresent(ip, (k, v) -> {
                    v.entrySet().removeIf(e -> now - e.getValue() > TIME_WINDOW);
                    return v.isEmpty() ? null : v;
                });
                lastCleanupTime.remove(ip);
            }
        }
    }

    private String getCurrentTimestamp() {
        return new java.text.SimpleDateFormat("HH:mm:ss").format(new java.util.Date());
    }
}

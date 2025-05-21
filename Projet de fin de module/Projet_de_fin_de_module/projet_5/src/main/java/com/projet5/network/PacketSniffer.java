package com.projet5.network;

import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;

import java.util.List;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;

public class PacketSniffer {

    private PcapHandle handle;
    private volatile boolean running = false;
    private Consumer<Packet> packetConsumer;
    private Thread sniffingThread;

    public PacketSniffer(Consumer<Packet> consumer, String ifaceName) throws PcapNativeException {
        this.packetConsumer = consumer;

        // Trouver l'interface réseau correspondant au nom ifaceName
        List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();
        if (interfaces.isEmpty()) {
            throw new PcapNativeException("Aucune interface réseau détectée.");
        }

        PcapNetworkInterface selectedInterface = null;
        for (PcapNetworkInterface nif : interfaces) {
            if (nif.getName().equals(ifaceName)) {
                selectedInterface = nif;
                break;
            }
        }

        if (selectedInterface == null) {
            throw new PcapNativeException("Interface réseau '" + ifaceName + "' introuvable.");
        }

        // Ouvrir l'interface en mode promiscuité, timeout 10 ms
        handle = selectedInterface.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
    }

    public void startSniffing() {
        running = true;

        sniffingThread = new Thread(() -> {
            while (running) {
                try {
                    Packet packet = handle.getNextPacketEx();
                    if (packet != null) {
                        packetConsumer.accept(packet);
                    }
                } catch (TimeoutException e) {
                    // Timeout ignoré, continue la boucle
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });

        sniffingThread.setDaemon(true);
        sniffingThread.start();
    }

    public void stopSniffing() {
        running = false;
        if (handle != null && handle.isOpen()) {
            try {
                handle.breakLoop();
            } catch (NotOpenException ignored) {
            }
            handle.close();
        }
        if (sniffingThread != null) {
            sniffingThread.interrupt();
        }
    }
}

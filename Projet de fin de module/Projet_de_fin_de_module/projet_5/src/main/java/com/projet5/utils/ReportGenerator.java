package com.projet5.utils;

import com.projet5.model.TrafficStats;
import com.projet5.model.IntrusionAlert;
import com.projet5.model.PacketInfo;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;

public class ReportGenerator {

    public static void generateReport(String filePath,
                                      TrafficStats stats,
                                      List<IntrusionAlert> alerts,
                                      List<PacketInfo> packets) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath))) {
            writer.write("==== RAPPORT DE SURVEILLANCE ====\n\n");

            writer.write(">> Statistiques Réseau:\n");
            writer.write("Nombre de paquets : " + stats.getTotalPackets() + "\n");
            writer.write("Volume total : " + stats.getTotalBytes() + " octets\n");
            writer.write("Débit moyen : " + String.format("%.2f", stats.getAveragePacketSize()) + " octets/paquet\n");
            writer.write("\n");

            writer.write(">> Alertes d'intrusion:\n");
            if (alerts.isEmpty()) {
                writer.write("Aucune alerte détectée.\n");
            } else {
                for (IntrusionAlert alert : alerts) {
                    writer.write("- [" + alert.getTimestamp() + "] " + alert.getDescription() + "\n");
                }
            }
            writer.write("\n");

            writer.write(">> Détails des paquets capturés:\n");
            for (PacketInfo packet : packets) {
                writer.write("- [" + packet.getTimestamp() + "] " +
                             packet.getSrcIP() + " -> " + packet.getDstIP() +
                             " (" + packet.getProtocol() + ", " + packet.getLength() + " octets)\n");
            }

            writer.flush();
            System.out.println("✅ Rapport généré avec succès : " + filePath);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

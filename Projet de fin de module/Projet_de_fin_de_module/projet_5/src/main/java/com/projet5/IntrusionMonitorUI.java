package com.projet5;

import com.projet5.detection.IntrusionDetector;
import com.projet5.model.IntrusionAlert;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.Vector;

public class IntrusionMonitorUI extends JFrame {

    private JTable alertTable;
    private DefaultTableModel tableModel;
    private IntrusionDetector detector;

    public IntrusionMonitorUI() {
        setTitle("Alertes de Sécurité");
        setSize(800, 400);
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE); // ← pour ne pas fermer toute l'app
        setLocationRelativeTo(null);
        initUI();

        // Lancer la détection
        detector = new IntrusionDetector(packet -> {
            SwingUtilities.invokeLater(() -> addAlertToTable(packet));
        });
        detector.startCapture();
    }

    private void initUI() {
        String[] columns = {"Heure", "Gravité", "Description"};
        tableModel = new DefaultTableModel(columns, 0);
        alertTable = new JTable(tableModel);
        alertTable.setEnabled(false);

        JScrollPane scrollPane = new JScrollPane(alertTable);
        add(scrollPane, BorderLayout.CENTER);
    }

    private void addAlertToTable(IntrusionAlert alert) {
        Vector<String> row = new Vector<>();
        row.add(alert.getTimestamp());
        //row.add(alert.getType());
        row.add(alert.getSeverity());
        row.add(alert.getDescription());
        tableModel.addRow(row);
    }

    /**
     * Méthode statique pour afficher l'interface depuis JavaFX ou autre.
     */
    public static void showUI() {
        SwingUtilities.invokeLater(() -> {
            IntrusionMonitorUI ui = new IntrusionMonitorUI();
            ui.setVisible(true);
        });
    }

    // main utilisé uniquement pour tests indépendants
    public static void main(String[] args) {
        showUI();
    }
}

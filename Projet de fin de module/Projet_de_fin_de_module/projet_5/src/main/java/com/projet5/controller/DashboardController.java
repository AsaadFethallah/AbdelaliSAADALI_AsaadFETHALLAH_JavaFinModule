package com.projet5.controller;

import com.projet5.IntrusionMonitorUI;
import com.projet5.model.IntrusionAlert;
import com.projet5.model.PacketInfo;
import com.projet5.model.TrafficStats;
import com.projet5.network.PacketSniffer;
import com.projet5.detection.IntrusionDetector;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.FilteredList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.Node;
import javafx.scene.chart.LineChart;
import javafx.scene.chart.NumberAxis;
import javafx.scene.chart.PieChart;
import javafx.scene.chart.XYChart;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.packet.*;

import java.io.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Predicate;

public class DashboardController {

    @FXML private TableView<PacketInfo> packetTable;
    @FXML private TableColumn<PacketInfo, String> colSrcIP;
    @FXML private TableColumn<PacketInfo, String> colDstIP;
    @FXML private TableColumn<PacketInfo, String> colProtocol;
    @FXML private TableColumn<PacketInfo, Integer> colLength;
    @FXML private TableColumn<PacketInfo, String> colTimestamp;
    @FXML private ComboBox<String> interfaceComboBox;
    @FXML private LineChart<Number, Number> packetRateChart;
    @FXML private NumberAxis xAxis;
    @FXML private NumberAxis yAxis;
    @FXML private Button startButton;
    @FXML private Button stopButton;
    @FXML private PieChart protocolChart;
    @FXML private TextField filterField;
    @FXML private ToggleButton darkModeToggle;
    @FXML private Label totalPacketsLabel;
    @FXML private Label totalBytesLabel;
    @FXML private Label averageRateLabel;
    @FXML private Label tcpStatsLabel;
    @FXML private Label udpStatsLabel;
    @FXML private Label otherStatsLabel;
    @FXML private VBox mainView;
    @FXML private VBox statsView;
    @FXML private ToggleButton mainViewButton;
    @FXML private ToggleButton statsViewButton;

    private ObservableList<PacketInfo> packetData = FXCollections.observableArrayList();
    private PacketSniffer sniffer;
    private TrafficStats trafficStats = new TrafficStats();
    private AlertController alertController;

    private XYChart.Series<Number, Number> packetRateSeries;
    private AtomicInteger packetsInLastSecond = new AtomicInteger(0);
    private ScheduledExecutorService scheduler;
    private int timeSeconds = 0;
    private static final int MAX_DATA_POINTS = 60; // Show last 60 seconds

    private FilteredList<PacketInfo> filteredPacketData;
    private Map<String, Integer> protocolDistribution = new HashMap<>();
    private AtomicLong totalBytes = new AtomicLong(0);
    private long startTime;
    private ScheduledExecutorService statsUpdater;

    private IntrusionDetector intrusionDetector;

    @FXML
    public void initialize() {
        // Create necessary directories
        createRequiredDirectories();

        // Initialize intrusion detector
        intrusionDetector = new IntrusionDetector(packet -> {
            IntrusionAlert alert = intrusionDetector.analyzePacket((Packet) packet);
            if (alert != null && alertController != null) {
                alertController.addAlert(alert);
            }
        });

        colSrcIP.setCellValueFactory(new PropertyValueFactory<>("srcIP"));
        colDstIP.setCellValueFactory(new PropertyValueFactory<>("dstIP"));
        colProtocol.setCellValueFactory(new PropertyValueFactory<>("protocol"));
        colLength.setCellValueFactory(new PropertyValueFactory<>("length"));
        colTimestamp.setCellValueFactory(new PropertyValueFactory<>("timestamp"));

        packetTable.setItems(packetData);

        // Initialize chart
        initializeChart();

        // Initialize buttons
        stopButton.setDisable(true);

        // Récupérer dynamiquement les interfaces réseau disponibles
        try {
            List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();
            if (interfaces.isEmpty()) {
                showAlert(Alert.AlertType.ERROR, "Erreur", "Aucune interface réseau détectée.");
                return;
            }

            ObservableList<String> interfaceNames = FXCollections.observableArrayList();
            for (PcapNetworkInterface nif : interfaces) {
                interfaceNames.add(nif.getName() + " - " + (nif.getDescription() != null ? nif.getDescription() : ""));
            }
            interfaceComboBox.setItems(interfaceNames);

            // Sélectionner la première interface par défaut
            interfaceComboBox.getSelectionModel().selectFirst();
        } catch (PcapNativeException e) {
            e.printStackTrace();
            showAlert(Alert.AlertType.ERROR, "Erreur", "Impossible de récupérer les interfaces réseau.");
        }

        // Initialize filtered list
        filteredPacketData = new FilteredList<>(packetData);
        packetTable.setItems(filteredPacketData);

        // Initialize filter field listener
        filterField.textProperty().addListener((observable, oldValue, newValue) -> {
            updateFilter(newValue);
        });

        // Initialize protocol chart
        protocolChart.setTitle("Distribution des protocoles");
        protocolChart.setLabelsVisible(true);

        // Initialize stats updater
        startStatsUpdater();

        // Initialize view toggle buttons
        ToggleGroup viewToggleGroup = new ToggleGroup();
        mainViewButton.setToggleGroup(viewToggleGroup);
        statsViewButton.setToggleGroup(viewToggleGroup);

        // Add listener for view switching
        viewToggleGroup.selectedToggleProperty().addListener((observable, oldValue, newValue) -> {
            if (newValue == null) {
                // If no button is selected, reselect the old value
                viewToggleGroup.selectToggle(oldValue);
                return;
            }

            if (newValue == mainViewButton) {
                mainView.setVisible(true);
                mainView.setManaged(true);
                statsView.setVisible(false);
                statsView.setManaged(false);
            } else {
                mainView.setVisible(false);
                mainView.setManaged(false);
                statsView.setVisible(true);
                statsView.setManaged(true);
            }
        });

        // Select main view by default
        mainViewButton.setSelected(true);
    }

    private void createRequiredDirectories() {
        // Create directories for reports and CSV files
        File reportsDir = new File("repports");
        File csvDir = new File("csv");

        if (!reportsDir.exists()) {
            reportsDir.mkdirs();
        }
        if (!csvDir.exists()) {
            csvDir.mkdirs();
        }
    }

    private void initializeChart() {
        // Configure chart
        packetRateSeries = new XYChart.Series<>();
        packetRateSeries.setName("Taux de paquets");

        // Disable animations
        packetRateChart.setAnimated(false);

        // Configure chart appearance
        packetRateChart.setCreateSymbols(false);
        packetRateChart.setLegendVisible(true);

        // Add series
        packetRateChart.getData().add(packetRateSeries);

        // Configure axes
        xAxis.setForceZeroInRange(false);
        xAxis.setAnimated(false);
        yAxis.setForceZeroInRange(true);
        yAxis.setAnimated(false);

        // Start packet rate monitoring
        startPacketRateMonitoring();
    }

    private void startPacketRateMonitoring() {
        if (scheduler != null && !scheduler.isShutdown()) {
            scheduler.shutdown();
            try {
                scheduler.awaitTermination(1, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        scheduler = Executors.newSingleThreadScheduledExecutor();
        scheduler.scheduleAtFixedRate(() -> {
            final int currentRate = packetsInLastSecond.getAndSet(0);
            javafx.application.Platform.runLater(() -> {
                timeSeconds++;

                // Add new data point
                packetRateSeries.getData().add(new XYChart.Data<>(timeSeconds, currentRate));

                // Remove old data points if we have more than MAX_DATA_POINTS
                if (packetRateSeries.getData().size() > MAX_DATA_POINTS) {
                    packetRateSeries.getData().remove(0);
                    // Adjust x-axis
                    xAxis.setLowerBound(timeSeconds - MAX_DATA_POINTS);
                    xAxis.setUpperBound(timeSeconds);
                }

                // Adjust y-axis if needed
                if (currentRate > yAxis.getUpperBound()) {
                    yAxis.setUpperBound(currentRate * 1.2); // Add 20% margin
                }
            });
        }, 0, 1, TimeUnit.SECONDS);
    }

    private String extractInterfaceName(String fullName) {
        if (fullName == null) return "";
        int index = fullName.indexOf(" - ");
        if (index == -1) return fullName;
        return fullName.substring(0, index);
    }

    private void startSniffer(String iface) {
        if (sniffer != null) {
            sniffer.stopSniffing();
        }

        try {
            sniffer = new PacketSniffer(packet -> {
                handlePacket(packet);
                IntrusionAlert alert = createAlertFromPacket(packet);
                if (alertController != null) {
                    alertController.addAlert(alert);
                }
            }, iface);

            sniffer.startSniffing();

        } catch (PcapNativeException e) {
            e.printStackTrace();
            showAlert(Alert.AlertType.ERROR, "Erreur", "Impossible d'ouvrir l'interface réseau: " + iface);
        }
    }

    @FXML
    public void handleStartSniffing(ActionEvent event) {
        String selectedFullName = interfaceComboBox.getSelectionModel().getSelectedItem();
        if (selectedFullName == null) {
            showAlert(Alert.AlertType.WARNING, "Attention", "Veuillez sélectionner une interface réseau.");
            return;
        }

        String selectedInterface = extractInterfaceName(selectedFullName);
        System.out.println("Démarrage de la capture sur l'interface : " + selectedInterface);

        // Reset data
        packetData.clear();
        timeSeconds = 0;
        packetRateSeries.getData().clear();
        packetsInLastSecond.set(0);

        // Reset chart
        xAxis.setLowerBound(0);
        xAxis.setUpperBound(60);
        yAxis.setLowerBound(0);
        yAxis.setUpperBound(10);

        // Restart packet rate monitoring
        startPacketRateMonitoring();

        // Start sniffing
        startSniffer(selectedInterface);

        // Update UI
        startButton.setDisable(true);
        stopButton.setDisable(false);
        interfaceComboBox.setDisable(true);

        startTime = System.currentTimeMillis();
        protocolDistribution.clear();
        totalBytes.set(0);
        updateProtocolChart();

        // Start stats updater if needed
        if (statsUpdater == null || statsUpdater.isShutdown()) {
            startStatsUpdater();
        }
    }

    @FXML
    public void handleStopSniffing(ActionEvent event) {
        if (sniffer != null) {
            sniffer.stopSniffing();
            sniffer = null;
        }

        // Stop the chart updates
        if (scheduler != null) {
            scheduler.shutdown();
            scheduler = null;
        }

        // Stop stats updates
        if (statsUpdater != null) {
            statsUpdater.shutdown();
            statsUpdater = null;
        }

        // Update UI
        startButton.setDisable(false);
        stopButton.setDisable(true);
        interfaceComboBox.setDisable(false);
    }

    @FXML
    public void handleInterfaceSelection(ActionEvent event) {
        // Do nothing - sniffing will start only when Start button is clicked
    }

    private void handlePacket(Packet packet) {
        String srcIp = "Unknown";
        String dstIp = "Unknown";
        String protocol = "Unknown";

        IpV4Packet ipV4 = packet.get(IpV4Packet.class);
        IpV6Packet ipV6 = packet.get(IpV6Packet.class);
        ArpPacket arp = packet.get(ArpPacket.class);

        if (ipV4 != null) {
            srcIp = ipV4.getHeader().getSrcAddr().getHostAddress();
            dstIp = ipV4.getHeader().getDstAddr().getHostAddress();

            if (packet.contains(TcpPacket.class)) protocol = "TCP";
            else if (packet.contains(UdpPacket.class)) protocol = "UDP";
            else if (packet.contains(IcmpV4CommonPacket.class)) protocol = "ICMP";
            else protocol = ipV4.getHeader().getProtocol().name();

        } else if (ipV6 != null) {
            srcIp = ipV6.getHeader().getSrcAddr().getHostAddress();
            dstIp = ipV6.getHeader().getDstAddr().getHostAddress();

            if (packet.contains(TcpPacket.class)) protocol = "TCP";
            else if (packet.contains(UdpPacket.class)) protocol = "UDP";
            else if (packet.contains(IcmpV6CommonPacket.class)) protocol = "ICMPv6";
            else protocol = ipV6.getHeader().getNextHeader().name();

        } else if (arp != null) {
            srcIp = arp.getHeader().getSrcProtocolAddr().getHostAddress();
            dstIp = arp.getHeader().getDstProtocolAddr().getHostAddress();
            protocol = "ARP";
        }

        String timestamp = new SimpleDateFormat("HH:mm:ss").format(new Date());

        PacketInfo pkt = new PacketInfo(srcIp, dstIp, protocol, packet.length(), timestamp);

        // Increment packet counter for the current second
        packetsInLastSecond.incrementAndGet();

        // Ajout dans la liste JavaFX sur le thread UI
        javafx.application.Platform.runLater(() -> packetData.add(pkt));

        trafficStats.incrementPacketCount(packet.length(), protocol);

        // Update protocol distribution
        protocolDistribution.merge(protocol, 1, Integer::sum);
        totalBytes.addAndGet(packet.length());
    }

    private IntrusionAlert createAlertFromPacket(Packet packet) {
        return intrusionDetector.analyzePacket(packet);
    }

    @FXML
    public void handleShowAlerts(ActionEvent event) {
//        try {
//            FXMLLoader loader = new FXMLLoader(getClass().getResource("/com/projet5/alert.fxml"));
//            Scene alertScene = new Scene(loader.load());
//
//            alertController = loader.getController();
//
//            Stage stage = new Stage();
//            stage.setTitle("Alertes détectées");
//            stage.setScene(alertScene);
//            stage.show();
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
        IntrusionMonitorUI.showUI();
    }

    @FXML
    public void handleGenerateReport(ActionEvent event) {
        try {
            FileWriter fw = new FileWriter("repports/traffic_report.txt");
            PrintWriter pw = new PrintWriter(fw);

            String now = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
            pw.println("===== Rapport de Surveillance Réseau =====");
            pw.println("Date : " + now);
            pw.println();

            long total = trafficStats.getTotalPackets();
            long totalBytes = trafficStats.getTotalBytes();
            long tcp = trafficStats.getTcpPackets();
            long udp = trafficStats.getUdpPackets();
            long other = trafficStats.getOtherPackets();

            double avgSize = total > 0 ? (double) totalBytes / total : 0;
            pw.printf("Paquets : %d\nTaille totale : %d octets\n", total, totalBytes);
            pw.printf("Taille moyenne : %.2f octets\n\n", avgSize);

            pw.printf("TCP : %d (%.2f%%)\n", tcp, tcp * 100.0 / total);
            pw.printf("UDP : %d (%.2f%%)\n", udp, udp * 100.0 / total);
            pw.printf("Autres : %d (%.2f%%)\n\n", other, other * 100.0 / total);

            pw.println("Derniers paquets capturés :");
            int limit = Math.min(10, packetData.size());
            for (int i = packetData.size() - limit; i < packetData.size(); i++) {
                PacketInfo p = packetData.get(i);
                pw.printf("[%s] %s → %s | %s | %d octets\n",
                        p.getTimestamp(), p.getSrcIP(), p.getDstIP(), p.getProtocol(), p.getLength());
            }

            pw.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void showAlert(Alert.AlertType type, String title, String message) {
        javafx.application.Platform.runLater(() -> {
            Alert alert = new Alert(type);
            alert.setTitle(title);
            alert.setHeaderText(null);
            alert.setContentText(message);
            alert.showAndWait();
        });
    }

    private void startStatsUpdater() {
        if (statsUpdater != null) {
            statsUpdater.shutdown();
        }

        statsUpdater = Executors.newSingleThreadScheduledExecutor();
        statsUpdater.scheduleAtFixedRate(this::updateStats, 0, 1, TimeUnit.SECONDS);
    }

    private void updateStats() {
        javafx.application.Platform.runLater(() -> {
            long totalPkts = trafficStats.getTotalPackets();
            long totalBts = trafficStats.getTotalBytes();
            long elapsedSeconds = (System.currentTimeMillis() - startTime) / 1000;
            double avgRate = elapsedSeconds > 0 ? totalPkts / (double) elapsedSeconds : 0;

            totalPacketsLabel.setText(String.format("%,d", totalPkts));
            totalBytesLabel.setText(String.format("%,d bytes", totalBts));
            averageRateLabel.setText(String.format("%.2f pkt/s", avgRate));

            long tcp = trafficStats.getTcpPackets();
            long udp = trafficStats.getUdpPackets();
            long other = trafficStats.getOtherPackets();

            tcpStatsLabel.setText(String.format("TCP: %d (%.1f%%)", tcp, totalPkts > 0 ? (tcp * 100.0 / totalPkts) : 0));
            udpStatsLabel.setText(String.format("UDP: %d (%.1f%%)", udp, totalPkts > 0 ? (udp * 100.0 / totalPkts) : 0));
            otherStatsLabel.setText(String.format("Autres: %d (%.1f%%)", other, totalPkts > 0 ? (other * 100.0 / totalPkts) : 0));

            updateProtocolChart();
        });
    }

    private void updateProtocolChart() {
        ObservableList<PieChart.Data> pieChartData = FXCollections.observableArrayList();
        protocolDistribution.forEach((protocol, count) -> {
            PieChart.Data data = new PieChart.Data(protocol, count);
            pieChartData.add(data);
        });
        protocolChart.setData(pieChartData);

        // Set chart properties
        protocolChart.setTitle("Distribution des protocoles");
        protocolChart.setLabelsVisible(true);
        protocolChart.setLegendVisible(true);
        protocolChart.setAnimated(false);

        // Apply colors after a short delay to ensure nodes are created
        Platform.runLater(() -> {
            int index = 0;
            for (PieChart.Data data : pieChartData) {
                String color = switch (data.getName().toUpperCase()) {
                    case "TCP" -> "#e74c3c";  // Red
                    case "UDP" -> "#f1c40f";  // Yellow
                    case "ICMP", "ICMPV6" -> "#2ecc71";  // Green
                    case "ARP" -> "#9b59b6";  // Purple
                    default -> "#95a5a6";  // Gray
                };

                // Apply color to the pie slice
                Node slice = data.getNode();
                if (slice != null) {
                    slice.setStyle("-fx-pie-color: " + color + ";");
                }

                // Apply color to the legend item
                Set<Node> items = protocolChart.lookupAll(".chart-legend-item");
                if (items.size() > index) {
                    Node item = items.toArray(new Node[0])[index];
                    if (item instanceof Label) {
                        Node symbol = ((Label) item).getGraphic();
                        if (symbol != null) {
                            symbol.setStyle("-fx-background-color: " + color + ";");
                        }
                    }
                }
                index++;
            }
        });
    }

    private void updateFilter(String filterText) {
        if (filterText == null || filterText.isEmpty()) {
            filteredPacketData.setPredicate(null);
            return;
        }

        Predicate<PacketInfo> filter = packet -> {
            String lowerCaseFilter = filterText.toLowerCase();

            // Check for protocol filter
            if (lowerCaseFilter.equals("tcp") || lowerCaseFilter.equals("udp") ||
                lowerCaseFilter.equals("icmp") || lowerCaseFilter.equals("arp")) {
                return packet.getProtocol().toLowerCase().equals(lowerCaseFilter);
            }

            // Check for IP filter
            if (lowerCaseFilter.startsWith("ip=")) {
                String ip = lowerCaseFilter.substring(3);
                return packet.getSrcIP().equals(ip) || packet.getDstIP().equals(ip);
            }

            // Default search in all fields
            return packet.getSrcIP().contains(lowerCaseFilter) ||
                   packet.getDstIP().contains(lowerCaseFilter) ||
                   packet.getProtocol().toLowerCase().contains(lowerCaseFilter);
        };

        filteredPacketData.setPredicate(filter);
    }

    @FXML
    public void handleDarkMode(ActionEvent event) {
        BorderPane root = (BorderPane) darkModeToggle.getScene().getRoot();
        if (darkModeToggle.isSelected()) {
            root.getStyleClass().add("dark-mode");
        } else {
            root.getStyleClass().remove("dark-mode");
        }
    }

    @FXML
    public void handleExportCsv(ActionEvent event) {
        // Create csv directory if it doesn't exist
        File csvDir = new File("csv");
        if (!csvDir.exists()) {
            csvDir.mkdirs();
        }

        // Create default filename with timestamp
        String timestamp = new SimpleDateFormat("yyyy-MM-dd_HH-mm-ss").format(new Date());
        String defaultFilename = "network_capture_" + timestamp + ".csv";

        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Enregistrer le fichier CSV");
        fileChooser.getExtensionFilters().add(
            new FileChooser.ExtensionFilter("CSV Files", "*.csv")
        );
        fileChooser.setInitialDirectory(csvDir);
        fileChooser.setInitialFileName(defaultFilename);

        File file = fileChooser.showSaveDialog(packetTable.getScene().getWindow());
        if (file != null) {
            try (PrintWriter writer = new PrintWriter(new FileWriter(file))) {
                // Write header
                writer.println("Timestamp,Source IP,Destination IP,Protocol,Length");

                // Write data
                for (PacketInfo packet : filteredPacketData) {
                    writer.printf("%s,%s,%s,%s,%d%n",
                        packet.getTimestamp(),
                        packet.getSrcIP(),
                        packet.getDstIP(),
                        packet.getProtocol(),
                        packet.getLength()
                    );
                }

                showAlert(Alert.AlertType.INFORMATION, "Export réussi",
                         "Les données ont été exportées avec succès vers " + file.getName());
            } catch (IOException e) {
                showAlert(Alert.AlertType.ERROR, "Erreur",
                         "Erreur lors de l'exportation: " + e.getMessage());
            }
        }
    }
}

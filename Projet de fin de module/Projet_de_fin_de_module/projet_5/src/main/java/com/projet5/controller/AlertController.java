package com.projet5.controller;

import com.projet5.model.IntrusionAlert;
import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.cell.PropertyValueFactory;

import java.util.List;

public class AlertController {

    @FXML
    private TableView<IntrusionAlert> alertTable;
    @FXML
    private TableColumn<IntrusionAlert, String> colType;
    @FXML
    private TableColumn<IntrusionAlert, String> colDescription;
    @FXML
    private TableColumn<IntrusionAlert, String> colSeverity;
    @FXML
    private TableColumn<IntrusionAlert, String> colTimestamp;

    // Initialize the TableView
    @FXML
    public void initialize() {
        colType.setCellValueFactory(new PropertyValueFactory<>("type"));
        colDescription.setCellValueFactory(new PropertyValueFactory<>("description"));
        colSeverity.setCellValueFactory(new PropertyValueFactory<>("severity"));
        colTimestamp.setCellValueFactory(new PropertyValueFactory<>("timestamp"));
    }

    // Method to add an alert to the TableView (runs on JavaFX Application Thread)
    public void addAlert(IntrusionAlert alert) {
        // Ensure the UI update is done on the JavaFX Application Thread
        Platform.runLater(() -> alertTable.getItems().add(alert));
    }

    // Method to add multiple alerts (in case you want batch addition)
    public void addAlerts(List<IntrusionAlert> alerts) {
        Platform.runLater(() -> alertTable.getItems().addAll(alerts));
    }
}

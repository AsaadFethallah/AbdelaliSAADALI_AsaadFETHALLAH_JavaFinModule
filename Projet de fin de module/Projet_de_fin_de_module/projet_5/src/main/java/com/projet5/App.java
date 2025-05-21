    package com.projet5;

    import com.projet5.controller.DashboardController;

    import javafx.application.Application;
    import javafx.fxml.FXMLLoader;
    import javafx.scene.Scene;
    import javafx.stage.Stage;

    public class App extends Application {
        @Override
        public void start(Stage stage) throws Exception {
            FXMLLoader loader = new FXMLLoader(getClass().getResource("/com/projet5/dashboard.fxml"));
            Scene scene = new Scene(loader.load());
            scene.getStylesheets().add(getClass().getResource("/com/projet5/style.css").toExternalForm());

            stage.setTitle("Surveillance Réseau");
            stage.setScene(scene);
            stage.show();
        }


        public static void main(String[] args) {
            launch(args);
        }
    }

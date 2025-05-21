package com.projet5;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.net.URL;

class AppTest {
    @Test
    void testResourcesExist() {
        App app = new App();
        
        URL dashboardFxml = app.getClass().getResource("/com/projet5/dashboard.fxml");
        assertNotNull(dashboardFxml, "dashboard.fxml should exist");
        
        URL styleSheet = app.getClass().getResource("/com/projet5/style.css");
        assertNotNull(styleSheet, "style.css should exist");
    }
    
    @Test
    void testAppClassStructure() {
        assertTrue(javafx.application.Application.class.isAssignableFrom(App.class),
            "App should extend javafx.application.Application");
    }
} 
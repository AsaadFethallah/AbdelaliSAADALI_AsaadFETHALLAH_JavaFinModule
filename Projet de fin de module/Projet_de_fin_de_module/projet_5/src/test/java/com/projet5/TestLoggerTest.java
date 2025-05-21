package com.projet5;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import java.lang.reflect.Field;
import static org.junit.jupiter.api.Assertions.*;

class TestLoggerTest {
    @Test
    void testLoggerInitialization() throws Exception {
        Field loggerField = TestLogger.class.getDeclaredField("logger");
        loggerField.setAccessible(true);
        Logger logger = (Logger) loggerField.get(null);
        
        assertNotNull(logger, "Logger should not be null");
        assertEquals("com.projet5.TestLogger", logger.getName(), "Logger should have correct name");
    }
} 
package com.projet5;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TestLogger {
    private static final Logger logger = LoggerFactory.getLogger(TestLogger.class);

    public static void main(String[] args) {
        logger.info("Ceci est un log INFO");
        logger.warn("Ceci est un log WARN");
        logger.error("Ceci est un log ERROR");
    }
}


package com.frauddetection.util;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class DBConnection {

    private static final String LOCAL_URL =
            "jdbc:mysql://localhost:3306/fraud_detection";

    private static final String LOCAL_USER =
            "fraud_app";

    private static final String LOCAL_PASSWORD =
            "FraudApp@12345";

    public static Connection getConnection() throws SQLException {

        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
        } catch (ClassNotFoundException e) {
            throw new SQLException("MySQL JDBC Driver not found", e);
        }

        // TiDB Cloud connection for Render deployment
        String dbUrl = System.getenv("DB_URL");
        String dbUsername = System.getenv("DB_USERNAME");
        String dbPassword = System.getenv("DB_PASSWORD");

        if (dbUrl != null && !dbUrl.isBlank()
                && dbUsername != null && !dbUsername.isBlank()
                && dbPassword != null && !dbPassword.isBlank()) {

            System.out.println("========== RADAR DATABASE DEBUG ==========");
            System.out.println("Using TiDB Cloud database connection.");
            System.out.println("Database URL: " + dbUrl.replaceAll(
                    "(?i)(password=)[^&]*", "$1****"
            ));
            System.out.println("Database username: " + dbUsername);
            System.out.println("==========================================");

            return DriverManager.getConnection(
                    dbUrl,
                    dbUsername,
                    dbPassword
            );
        }

        // Never fall back to localhost on Render
        if (System.getenv("RENDER") != null
                || System.getenv("RENDER_SERVICE_ID") != null) {

            throw new SQLException(
                    "TiDB configuration missing. Check DB_URL, "
                    + "DB_USERNAME and DB_PASSWORD in Render."
            );
        }

        // Local development fallback
        System.out.println(
                "RADAR DATABASE DEBUG: Using LOCAL database connection."
        );

        return DriverManager.getConnection(
                LOCAL_URL,
                LOCAL_USER,
                LOCAL_PASSWORD
        );
    }
}

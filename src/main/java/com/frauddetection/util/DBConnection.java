package com.frauddetection.util;

import java.net.URI;
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
            throw new SQLException(
                    "MySQL JDBC Driver not found",
                    e
            );
        }

        /*
         * Railway connection using MYSQL_URL.
         */
        String mysqlUrl = System.getenv("MYSQL_URL");

        if (mysqlUrl != null && !mysqlUrl.isBlank()) {

            System.out.println("========== RADAR DATABASE DEBUG ==========");
            System.out.println("MYSQL_URL is present: YES");

            String jdbcUrl = mysqlUrl;

            if (jdbcUrl.startsWith("mysql://")) {
                jdbcUrl = "jdbc:" + jdbcUrl;
            }

            /*
             * Print safe connection information only.
             * Password is never printed.
             */
            try {
                URI uri = URI.create(mysqlUrl);

                String host = uri.getHost();
                int port = uri.getPort();

                String database = uri.getPath();

                if (database != null && database.startsWith("/")) {
                    database = database.substring(1);
                }

                System.out.println("Database host: " + host);
                System.out.println("Database port: " + port);
                System.out.println("Database name: " + database);

            } catch (Exception e) {
                System.out.println(
                        "Could not parse MYSQL_URL for diagnostics."
                );
            }

            System.out.println("Attempting Railway MySQL connection...");
            System.out.println("==========================================");

            if (jdbcUrl.contains("?")) {
                jdbcUrl +=
                        "&useSSL=false" +
                        "&allowPublicKeyRetrieval=true" +
                        "&serverTimezone=UTC" +
                        "&connectTimeout=10000";
            } else {
                jdbcUrl +=
                        "?useSSL=false" +
                        "&allowPublicKeyRetrieval=true" +
                        "&serverTimezone=UTC" +
                        "&connectTimeout=10000";
            }

            return DriverManager.getConnection(jdbcUrl);
        }

        /*
         * Fallback to Railway individual variables.
         */
        String host = System.getenv("MYSQLHOST");
        String port = System.getenv("MYSQLPORT");
        String database = System.getenv("MYSQLDATABASE");
        String user = System.getenv("MYSQLUSER");
        String password = System.getenv("MYSQLPASSWORD");

        if (host != null && !host.isBlank()
                && port != null && !port.isBlank()
                && database != null && !database.isBlank()
                && user != null && !user.isBlank()
                && password != null && !password.isBlank()) {

            System.out.println("========== RADAR DATABASE DEBUG ==========");
            System.out.println("MYSQL_URL is present: NO");
            System.out.println("Using individual Railway MySQL variables.");
            System.out.println("Database host: " + host);
            System.out.println("Database port: " + port);
            System.out.println("Database name: " + database);
            System.out.println("Database user: " + user);
            System.out.println("==========================================");

            String url =
                    "jdbc:mysql://" +
                    host +
                    ":" +
                    port +
                    "/" +
                    database +
                    "?useSSL=false" +
                    "&allowPublicKeyRetrieval=true" +
                    "&serverTimezone=UTC" +
                    "&connectTimeout=10000";

            return DriverManager.getConnection(
                    url,
                    user,
                    password
            );
        }

        /*
         * Local development fallback.
         */
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
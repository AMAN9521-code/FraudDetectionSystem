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
            throw new SQLException(
                    "MySQL JDBC Driver not found",
                    e
            );
        }

        /*
         * ==========================================
         * RAILWAY CLOUD DATABASE
         * ==========================================
         *
         * Railway provides MYSQL_URL for the
         * connected MySQL service.
         */
        String mysqlUrl =
                System.getenv("MYSQL_URL");

        if (mysqlUrl != null
                && !mysqlUrl.isBlank()) {

            /*
             * Railway normally provides the URL
             * beginning with mysql://
             *
             * JDBC requires jdbc:mysql://
             */
            if (mysqlUrl.startsWith("mysql://")) {
                mysqlUrl =
                        "jdbc:"
                                + mysqlUrl;
            }

            /*
             * Add JDBC connection options.
             */
            if (mysqlUrl.contains("?")) {
                mysqlUrl +=
                        "&useSSL=false"
                        + "&allowPublicKeyRetrieval=true"
                        + "&serverTimezone=UTC";
            } else {
                mysqlUrl +=
                        "?useSSL=false"
                        + "&allowPublicKeyRetrieval=true"
                        + "&serverTimezone=UTC";
            }

            return DriverManager.getConnection(
                    mysqlUrl
            );
        }

        /*
         * ==========================================
         * LOCAL DEVELOPMENT
         * ==========================================
         *
         * When MYSQL_URL does not exist,
         * RADAR continues using local MySQL.
         */
        return DriverManager.getConnection(
                LOCAL_URL,
                LOCAL_USER,
                LOCAL_PASSWORD
        );
    }
}
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
         * Railway connection using MYSQL_URL.
         */
        String mysqlUrl = System.getenv("MYSQL_URL");

        if (mysqlUrl != null && !mysqlUrl.isBlank()) {

            if (mysqlUrl.startsWith("mysql://")) {
                mysqlUrl = "jdbc:" + mysqlUrl;
            }

            if (mysqlUrl.contains("?")) {
                mysqlUrl +=
                        "&useSSL=false" +
                        "&allowPublicKeyRetrieval=true" +
                        "&serverTimezone=UTC" +
                        "&connectTimeout=10000";
            } else {
                mysqlUrl +=
                        "?useSSL=false" +
                        "&allowPublicKeyRetrieval=true" +
                        "&serverTimezone=UTC" +
                        "&connectTimeout=10000";
            }

            return DriverManager.getConnection(mysqlUrl);
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
        return DriverManager.getConnection(
                LOCAL_URL,
                LOCAL_USER,
                LOCAL_PASSWORD
        );
    }
}
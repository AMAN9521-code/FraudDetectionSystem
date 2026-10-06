package com.frauddetection.service;

import com.frauddetection.util.DBConnection;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;


public class FraudDetectionService {

    private static final double DEFAULT_AMOUNT_WEIGHT = 0.30;
    private static final double DEFAULT_VELOCITY_WEIGHT = 0.25;
    private static final double DEFAULT_LOCATION_WEIGHT = 0.20;
    private static final double DEFAULT_ZSCORE_WEIGHT = 0.25;
    // Random Forest contribution to final RADAR risk
private static final double ML_WEIGHT = 0.60;
private static final double RULE_WEIGHT = 0.40;

    public static double analyzeTransaction(
            int userId,
            double amount,
            String merchant,
            String location,
            int transactionId)
            throws Exception {

        return analyzeTransaction(
                userId,
                amount,
                merchant,
                location,
                transactionId,
                new Timestamp(System.currentTimeMillis())
        );
    }

    public static double analyzeTransaction(
            int userId,
            double amount,
            String merchant,
            String location,
            int transactionId,
            Timestamp transactionTime)
            throws Exception {

        /*
         * ==========================================
         * DEFAULT DETECTION CONFIGURATION
         * ==========================================
         */

        double amountThreshold = 50000.0;
        int velocityLimit = 5;
        int velocityWindowMinutes = 10;
        double zscoreThreshold = 3.0;

        /*
         * ==========================================
         * DEFAULT ALGORITHM WEIGHTS
         * ==========================================
         */

        double amountWeight = DEFAULT_AMOUNT_WEIGHT;
        double velocityWeight = DEFAULT_VELOCITY_WEIGHT;
        double locationWeight = DEFAULT_LOCATION_WEIGHT;
        double zscoreWeight = DEFAULT_ZSCORE_WEIGHT;

        /*
         * ==========================================
         * 1. LOAD DETECTION CONFIGURATION
         * ==========================================
         */

        String configSql = """
                SELECT
                    amount_threshold,
                    velocity_limit,
                    velocity_window_minutes,
                    zscore_threshold
                FROM detection_config
                ORDER BY config_id DESC
                LIMIT 1
                """;

        try (Connection connection =
                     DBConnection.getConnection();
             PreparedStatement statement =
                     connection.prepareStatement(configSql);
             ResultSet resultSet =
                     statement.executeQuery()) {

            if (resultSet.next()) {

                amountThreshold =
                        resultSet.getDouble(
                                "amount_threshold");

                velocityLimit =
                        resultSet.getInt(
                                "velocity_limit");

                velocityWindowMinutes =
                        resultSet.getInt(
                                "velocity_window_minutes");

                zscoreThreshold =
                        resultSet.getDouble(
                                "zscore_threshold");
            }
        }

        /*
         * Defensive validation of configuration.
         */

        if (!Double.isFinite(amountThreshold)
                || amountThreshold <= 0) {

            amountThreshold = 50000.0;
        }

        if (velocityLimit <= 0) {
            velocityLimit = 5;
        }

        if (velocityWindowMinutes <= 0) {
            velocityWindowMinutes = 10;
        }

        if (!Double.isFinite(zscoreThreshold)
                || zscoreThreshold <= 0) {

            zscoreThreshold = 3.0;
        }

        /*
         * ==========================================
         * 2. LOAD ALGORITHM WEIGHTS
         * ==========================================
         */

        String weightSql = """
                SELECT
                    param_name,
                    param_value
                FROM algorithm_params
                """;

        try (Connection connection =
                     DBConnection.getConnection();
             PreparedStatement statement =
                     connection.prepareStatement(weightSql);
             ResultSet resultSet =
                     statement.executeQuery()) {

            while (resultSet.next()) {

                String name =
                        resultSet.getString("param_name");

                double value =
                        resultSet.getDouble("param_value");

                if (!Double.isFinite(value)) {
                    continue;
                }

                value =
                        Math.max(
                                0.0,
                                Math.min(1.0, value)
                        );

                switch (name) {

                    case "AMOUNT_RULE_WEIGHT":
                        amountWeight = value;
                        break;

                    case "VELOCITY_RULE_WEIGHT":
                        velocityWeight = value;
                        break;

                    case "LOCATION_RULE_WEIGHT":
                        locationWeight = value;
                        break;

                    case "ZSCORE_RULE_WEIGHT":
                        zscoreWeight = value;
                        break;

                    default:
                        break;
                }
            }
        }

        /*
         * Make sure weights are valid and sum to 1.
         */

        double weightTotal =
                amountWeight
                        + velocityWeight
                        + locationWeight
                        + zscoreWeight;

        if (!Double.isFinite(weightTotal)
                || weightTotal <= 0) {

            amountWeight = DEFAULT_AMOUNT_WEIGHT;
            velocityWeight = DEFAULT_VELOCITY_WEIGHT;
            locationWeight = DEFAULT_LOCATION_WEIGHT;
            zscoreWeight = DEFAULT_ZSCORE_WEIGHT;

        } else {

            amountWeight =
                    amountWeight / weightTotal;

            velocityWeight =
                    velocityWeight / weightTotal;

            locationWeight =
                    locationWeight / weightTotal;

            zscoreWeight =
                    zscoreWeight / weightTotal;
        }

        /*
         * ==========================================
         * 3. AMOUNT SCORE
         * ==========================================
         */

        double amountScore;

        double amountRatio =
                amount / amountThreshold;

        if (amountRatio >= 2.0) {

            amountScore = 1.0;

        } else if (amountRatio >= 1.0) {

            amountScore =
                    0.5
                            + ((amountRatio - 1.0) * 0.5);

        } else {

            amountScore =
                    amountRatio * 0.5;
        }

        amountScore =
                clamp(amountScore);

        double amountContribution =
                amountScore * amountWeight;

        /*
         * ==========================================
         * 4. VELOCITY SCORE
         * ==========================================
         */

        int previousTransactionCount = 0;

        String velocitySql = """
                SELECT COUNT(*)
                FROM transactions
                WHERE user_id = ?
                  AND transaction_id <> ?
                  AND txn_timestamp >=
                      DATE_SUB(
                          ?,
                          INTERVAL ? MINUTE
                      )
                """;

        try (Connection connection =
                     DBConnection.getConnection();
             PreparedStatement statement =
                     connection.prepareStatement(
                             velocitySql)) {

            statement.setInt(1, userId);
            statement.setInt(2, transactionId);
            statement.setTimestamp(3, transactionTime);
            statement.setInt(4, velocityWindowMinutes);

            try (ResultSet resultSet =
                         statement.executeQuery()) {

                if (resultSet.next()) {

                    previousTransactionCount =
                            resultSet.getInt(1);
                }
            }
        }

        double velocityScore =
                (double) previousTransactionCount
                        / velocityLimit;

        velocityScore =
                clamp(velocityScore);

        double velocityContribution =
                velocityScore * velocityWeight;

        /*
         * ==========================================
         * 5. LOCATION SCORE
         * ==========================================
         */

        boolean newLocation = true;

        String locationSql = """
                SELECT COUNT(*)
                FROM transactions
                WHERE user_id = ?
                  AND transaction_id <> ?
                  AND LOWER(location) = LOWER(?)
                """;

        try (Connection connection =
                     DBConnection.getConnection();
             PreparedStatement statement =
                     connection.prepareStatement(
                             locationSql)) {

            statement.setInt(1, userId);
            statement.setInt(2, transactionId);
            statement.setString(3, location);

            try (ResultSet resultSet =
                         statement.executeQuery()) {

                if (resultSet.next()) {

                    int count =
                            resultSet.getInt(1);

                    newLocation = count == 0;
                }
            }
        }

        double locationScore =
                newLocation ? 0.75 : 0.0;

        double locationContribution =
                locationScore * locationWeight;

        /*
         * ==========================================
         * 6. Z-SCORE
         * ==========================================
         */

        double averageAmount = 0.0;
        double standardDeviation = 0.0;
        int historicalCount = 0;

        String statisticsSql = """
                SELECT
                    COUNT(*) AS transaction_count,
                    AVG(amount) AS average_amount,
                    STDDEV_POP(amount) AS standard_deviation
                FROM transactions
                WHERE user_id = ?
                  AND transaction_id <> ?
                """;

        try (Connection connection =
                     DBConnection.getConnection();
             PreparedStatement statement =
                     connection.prepareStatement(
                             statisticsSql)) {

            statement.setInt(1, userId);
            statement.setInt(2, transactionId);

            try (ResultSet resultSet =
                         statement.executeQuery()) {

                if (resultSet.next()) {

                    historicalCount =
                            resultSet.getInt(
                                    "transaction_count");

                    averageAmount =
                            resultSet.getDouble(
                                    "average_amount");

                    standardDeviation =
                            resultSet.getDouble(
                                    "standard_deviation");
                }
            }
        }

        double zscore = 0.0;

        if (historicalCount >= 2
                && Double.isFinite(averageAmount)
                && Double.isFinite(standardDeviation)
                && standardDeviation > 0) {

            zscore =
                    Math.abs(
                            (amount - averageAmount)
                                    / standardDeviation
                    );
        }

        double zscoreScore =
                zscore / zscoreThreshold;

        zscoreScore =
                clamp(zscoreScore);

        double zscoreContribution =
                zscoreScore * zscoreWeight;

        double ruleRiskScore =
        amountContribution
                + velocityContribution
                + locationContribution
                + zscoreContribution;

ruleRiskScore =
        clamp(ruleRiskScore);

double ruleRiskPercentage =
        ruleRiskScore * 100.0;

/*
 * ==========================================
 * RANDOM FOREST ML PREDICTION
 * ==========================================
 *
 * The Python ML service returns a fraud
 * probability from 0 to 100.
 *
 * If the ML service is unavailable,
 * RADAR safely falls back to the
 * existing rule-based risk.
 */

double mlRiskPercentage = ruleRiskPercentage;

try {

    mlRiskPercentage =
            MLFraudService.predictFraudProbability(
                    amount,
                    merchant,
                    location
            );

    mlRiskPercentage =
            Math.max(
                    0.0,
                    Math.min(100.0, mlRiskPercentage)
            );

} catch (Exception mlException) {

    System.out.println(
            "RADAR ML service unavailable. "
                    + "Using rule-based risk only."
                    + mlException
    );
}

/*
 * ==========================================
 * COMBINED RADAR RISK
 * ==========================================
 */

double finalRiskPercentage =
        (ruleRiskPercentage * RULE_WEIGHT)
                + (mlRiskPercentage * ML_WEIGHT);

double finalRiskScore =
        finalRiskPercentage / 100.0;

finalRiskScore =
        clamp(finalRiskScore);

double riskPercentage =
        finalRiskScore * 100.0;
        /*
         * ==========================================
         * 8. CREATE FRAUD ALERT
         * ==========================================
         */

        if (riskPercentage >= 50.0) {

            String reason =
                    "Amount="
                            + format(amountScore * 100)
                            + "% ("
                            + format(
                                    amountContribution * 100)
                            + "%); "

                            + "Velocity="
                            + format(
                                    velocityScore * 100)
                            + "% ("
                            + format(
                                    velocityContribution * 100)
                            + "%); "

                            + "Location="
                            + format(
                                    locationScore * 100)
                            + "% ("
                            + format(
                                    locationContribution * 100)
                            + "%); "

                            + "ZScore="
                            + format(
                                    zscoreScore * 100)
                            + "% ("
                            + format(
                                    zscoreContribution * 100)
                            + "%); "

                            + "Final="
                            + format(riskPercentage)
                            + "%";
                        createFraudAlert(
        transactionId,
        reason
                + "; ML Risk="
                + format(mlRiskPercentage)
                + "%",
        riskPercentage,
        amountScore,
        velocityScore,
        locationScore,
        zscoreScore,
        mlRiskPercentage
);
        }

        return riskPercentage;
    }

    /*
     * ==========================================
     * CREATE FRAUD ALERT
     * ==========================================
     */

    private static void createFraudAlert(
            int transactionId,
            String reason,
            double riskPercentage,
            double amountScore,
            double velocityScore,
            double locationScore,
            double zscoreScore,
            double mlScore)
            throws Exception {

        /*
         * Application-level duplicate check.
         */

        String checkSql = """
                SELECT alert_id
                FROM fraud_alerts
                WHERE transaction_id = ?
                LIMIT 1
                """;

        try (Connection connection =
                     DBConnection.getConnection();
             PreparedStatement checkStatement =
                     connection.prepareStatement(
                             checkSql)) {

            checkStatement.setInt(
                    1,
                    transactionId
            );

            try (ResultSet resultSet =
                         checkStatement.executeQuery()) {

                if (resultSet.next()) {
                    return;
                }
            }
        }

        /*
         * Database-level UNIQUE constraint on
         * fraud_alerts.transaction_id provides
         * the final duplicate protection.
         */

        String alertSql = """
                INSERT INTO fraud_alerts
                (
                    transaction_id,
                    reason,
                    risk_score,
                    amount_score,
                    velocity_score,
                    location_score,
                    zscore_score,
                    ml_score,
                    review_status
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'OPEN')
                """;

        try (Connection connection =
                     DBConnection.getConnection();
             PreparedStatement statement =
                     connection.prepareStatement(
                             alertSql)) {

            statement.setInt(
                    1,
                    transactionId
            );

            statement.setString(
                    2,
                    reason
            );

            statement.setDouble(
                    3,
                    riskPercentage
            );

            statement.setDouble(
                    4,
                    amountScore
            );

            statement.setDouble(
                    5,
                    velocityScore
            );

            statement.setDouble(
                    6,
                    locationScore
            );

            statement.setDouble(
                    7,
                    zscoreScore
            );
            statement.setDouble(
                    8,
                    mlScore
            );

            statement.executeUpdate();

        } catch (SQLException e) {

            /*
             * SQLSTATE 23000 represents an integrity
             * constraint violation. If another request
             * inserted the alert at the same time,
             * the UNIQUE constraint safely prevents
             * a duplicate alert.
             */

            if ("23000".equals(e.getSQLState())) {
                return;
            }

            throw e;
        }
    }

    /*
     * ==========================================
     * CLAMP VALUE BETWEEN 0 AND 1
     * ==========================================
     */

    private static double clamp(double value) {

        if (!Double.isFinite(value)) {
            return 0.0;
        }

        return Math.max(
                0.0,
                Math.min(1.0, value)
        );
    }

    /*
     * ==========================================
     * FORMAT NUMBER
     * ==========================================
     */

    private static String format(double value) {

        return String.format(
                "%.2f",
                value
        );
    }
}
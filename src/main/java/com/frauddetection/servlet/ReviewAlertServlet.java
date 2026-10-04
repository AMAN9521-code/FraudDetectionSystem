package com.frauddetection.servlet;

import com.frauddetection.util.DBConnection;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.HashMap;
import java.util.Map;

@WebServlet("/review-alert")
public class ReviewAlertServlet extends HttpServlet {

    /*
     * Controls how quickly the algorithm learns.
     *
     * 0.05 = small adjustment per reviewed transaction.
     * This prevents one review from drastically changing
     * the entire fraud detection system.
     */
    private static final double LEARNING_RATE = 0.05;

    @Override
    protected void doPost(
            HttpServletRequest request,
            HttpServletResponse response)
            throws ServletException, IOException {

        HttpSession session = request.getSession(false);

        // ==========================================
        // 1. ADMIN ACCESS CHECK
        // ==========================================

        if (session == null
                || session.getAttribute("userId") == null
                || !"ADMIN".equals(session.getAttribute("userRole"))) {

            response.sendRedirect("login.html");
            return;
        }

        String alertIdText = request.getParameter("alertId");
        String decision = request.getParameter("decision");

        if (alertIdText == null
                || decision == null
                || (!"CONFIRMED_FRAUD".equals(decision)
                && !"FALSE_POSITIVE".equals(decision))) {

            response.sendRedirect("alerts");
            return;
        }

        int alertId;
        int adminUserId;

        try {

            alertId = Integer.parseInt(alertIdText);

            adminUserId =
                    (Integer) session.getAttribute("userId");

        } catch (Exception e) {

            response.sendRedirect("alerts");
            return;
        }

        try (Connection connection =
                     DBConnection.getConnection()) {

            // ==========================================
            // 2. READ RULE SCORES FROM THE ALERT
            // ==========================================

            double riskScore;
            double amountScore;
            double velocityScore;
            double locationScore;
            double zscoreScore;

            String alertSql = """
                    SELECT
                        risk_score,
                        amount_score,
                        velocity_score,
                        location_score,
                        zscore_score,
                        review_status
                    FROM fraud_alerts
                    WHERE alert_id = ?
                    """;

            try (PreparedStatement statement =
                         connection.prepareStatement(alertSql)) {

                statement.setInt(1, alertId);

                try (ResultSet resultSet =
                             statement.executeQuery()) {

                    if (!resultSet.next()) {

                        response.sendRedirect("alerts");
                        return;
                    }

                    String currentStatus =
                            resultSet.getString("review_status");

                    /*
                     * Do not allow an already-reviewed alert
                     * to be reviewed again.
                     */
                    if (!"OPEN".equals(currentStatus)) {

                        response.sendRedirect("alerts");
                        return;
                    }

                    riskScore =
                            resultSet.getDouble("risk_score");

                    amountScore =
                            resultSet.getDouble("amount_score");

                    velocityScore =
                            resultSet.getDouble("velocity_score");

                    locationScore =
                            resultSet.getDouble("location_score");

                    zscoreScore =
                            resultSet.getDouble("zscore_score");
                }
            }

            // ==========================================
            // 3. UPDATE ALERT REVIEW
            // ==========================================

            String updateAlertSql = """
                    UPDATE fraud_alerts
                    SET review_status = ?,
                        reviewed_by = ?,
                        reviewed_at = CURRENT_TIMESTAMP
                    WHERE alert_id = ?
                      AND review_status = 'OPEN'
                    """;

            try (PreparedStatement statement =
                         connection.prepareStatement(updateAlertSql)) {

                statement.setString(1, decision);
                statement.setInt(2, adminUserId);
                statement.setInt(3, alertId);

                statement.executeUpdate();
            }

            // ==========================================
            // 4. LOAD CURRENT ALGORITHM WEIGHTS
            // ==========================================

            Map<String, Double> weights =
                    new HashMap<>();

            String weightSql = """
                    SELECT
                        param_name,
                        param_value
                    FROM algorithm_params
                    WHERE param_name IN (
                        'AMOUNT_RULE_WEIGHT',
                        'VELOCITY_RULE_WEIGHT',
                        'LOCATION_RULE_WEIGHT',
                        'ZSCORE_RULE_WEIGHT'
                    )
                    """;

            try (PreparedStatement statement =
                         connection.prepareStatement(weightSql);
                 ResultSet resultSet =
                         statement.executeQuery()) {

                while (resultSet.next()) {

                    weights.put(
                            resultSet.getString("param_name"),
                            resultSet.getDouble("param_value")
                    );
                }
            }

            if (weights.size() != 4) {

                throw new ServletException(
                        "Algorithm parameters are incomplete."
                );
            }

            // ==========================================
            // 5. CALCULATE RULE-SPECIFIC LEARNING
            // ==========================================

            /*
             * Confirmed fraud:
             *
             * Strongly active rules receive a larger
             * positive adjustment.
             *
             * False positive:
             *
             * Strongly active rules receive a larger
             * negative adjustment.
             */

            double feedbackDirection;

            if ("CONFIRMED_FRAUD".equals(decision)) {

                feedbackDirection = 1.0;

            } else {

                feedbackDirection = -1.0;
            }

            double amountWeight =
                    weights.get("AMOUNT_RULE_WEIGHT");

            double velocityWeight =
                    weights.get("VELOCITY_RULE_WEIGHT");

            double locationWeight =
                    weights.get("LOCATION_RULE_WEIGHT");

            double zscoreWeight =
                    weights.get("ZSCORE_RULE_WEIGHT");

            /*
             * Each rule learns according to its own score.
             *
             * Example:
             *
             * Amount = 100%
             * Velocity = 100%
             * Location = 0%
             * ZScore = 55%
             *
             * Amount and Velocity therefore receive
             * stronger learning than Location.
             */

            amountWeight =
                    amountWeight
                            + (LEARNING_RATE
                            * feedbackDirection
                            * amountScore);

            velocityWeight =
                    velocityWeight
                            + (LEARNING_RATE
                            * feedbackDirection
                            * velocityScore);

            locationWeight =
                    locationWeight
                            + (LEARNING_RATE
                            * feedbackDirection
                            * locationScore);

            zscoreWeight =
                    zscoreWeight
                            + (LEARNING_RATE
                            * feedbackDirection
                            * zscoreScore);

            // ==========================================
            // 6. KEEP WEIGHTS BETWEEN 0 AND 1
            // ==========================================

            amountWeight =
                    clamp(amountWeight);

            velocityWeight =
                    clamp(velocityWeight);

            locationWeight =
                    clamp(locationWeight);

            zscoreWeight =
                    clamp(zscoreWeight);

            // ==========================================
            // 7. NORMALIZE TOTAL TO 1.00
            // ==========================================

            double total =
                    amountWeight
                            + velocityWeight
                            + locationWeight
                            + zscoreWeight;

            if (total <= 0) {

                throw new ServletException(
                        "Invalid algorithm weights."
                );
            }

            amountWeight =
                    amountWeight / total;

            velocityWeight =
                    velocityWeight / total;

            locationWeight =
                    locationWeight / total;

            zscoreWeight =
                    zscoreWeight / total;

            // ==========================================
            // 8. SAVE LEARNED WEIGHTS
            // ==========================================

            updateWeight(
                    connection,
                    "AMOUNT_RULE_WEIGHT",
                    amountWeight,
                    feedbackDirection * amountScore
            );

            updateWeight(
                    connection,
                    "VELOCITY_RULE_WEIGHT",
                    velocityWeight,
                    feedbackDirection * velocityScore
            );

            updateWeight(
                    connection,
                    "LOCATION_RULE_WEIGHT",
                    locationWeight,
                    feedbackDirection * locationScore
            );

            updateWeight(
                    connection,
                    "ZSCORE_RULE_WEIGHT",
                    zscoreWeight,
                    feedbackDirection * zscoreScore
            );

            // ==========================================
            // 9. AUDIT LOG
            // ==========================================

            String auditSql = """
                    INSERT INTO audit_log
                    (
                        user_id,
                        action
                    )
                    VALUES (?, ?)
                    """;

            String auditAction =
                    "Reviewed fraud alert ID "
                            + alertId
                            + " as "
                            + decision
                            + ". Risk Score="
                            + String.format(
                                    "%.2f",
                                    riskScore
                            )
                            + "%. Rule Scores: "
                            + "Amount="
                            + String.format(
                                    "%.2f",
                                    amountScore * 100
                            )
                            + "%, Velocity="
                            + String.format(
                                    "%.2f",
                                    velocityScore * 100
                            )
                            + "%, Location="
                            + String.format(
                                    "%.2f",
                                    locationScore * 100
                            )
                            + "%, ZScore="
                            + String.format(
                                    "%.2f",
                                    zscoreScore * 100
                            )
                            + "%. New Weights: "
                            + "Amount="
                            + String.format(
                                    "%.4f",
                                    amountWeight
                            )
                            + ", Velocity="
                            + String.format(
                                    "%.4f",
                                    velocityWeight
                            )
                            + ", Location="
                            + String.format(
                                    "%.4f",
                                    locationWeight
                            )
                            + ", ZScore="
                            + String.format(
                                    "%.4f",
                                    zscoreWeight
                            );

            try (PreparedStatement statement =
                         connection.prepareStatement(auditSql)) {

                statement.setInt(1, adminUserId);
                statement.setString(2, auditAction);

                statement.executeUpdate();
            }

            // ==========================================
            // 10. CONSOLE OUTPUT
            // ==========================================

            System.out.println(
                    "===== FRAUD LEARNING ====="
            );

            System.out.println(
                    "Alert ID: " + alertId
            );

            System.out.println(
                    "Decision: " + decision
            );

            System.out.println(
                    "Risk Score: "
                            + String.format(
                                    "%.2f",
                                    riskScore
                            )
                            + "%"
            );

            System.out.println(
                    "New Amount Weight: "
                            + String.format(
                                    "%.4f",
                                    amountWeight
                            )
            );

            System.out.println(
                    "New Velocity Weight: "
                            + String.format(
                                    "%.4f",
                                    velocityWeight
                            )
            );

            System.out.println(
                    "New Location Weight: "
                            + String.format(
                                    "%.4f",
                                    locationWeight
                            )
            );

            System.out.println(
                    "New ZScore Weight: "
                            + String.format(
                                    "%.4f",
                                    zscoreWeight
                            )
            );

        } catch (Exception e) {

            throw new ServletException(
                    "Unable to review fraud alert",
                    e
            );
        }

        response.sendRedirect("alerts");
    }

    // ==========================================
    // UPDATE ONE ALGORITHM WEIGHT
    // ==========================================

    private static void updateWeight(
            Connection connection,
            String paramName,
            double value,
            double feedbackScore)
            throws Exception {

        String sql = """
                UPDATE algorithm_params
                SET param_value = ?,
                    last_feedback_score = ?
                WHERE param_name = ?
                """;

        try (PreparedStatement statement =
                     connection.prepareStatement(sql)) {

            statement.setString(
                    1,
                    String.format("%.4f", value)
            );

            statement.setDouble(
                    2,
                    feedbackScore
            );

            statement.setString(
                    3,
                    paramName
            );

            statement.executeUpdate();
        }
    }

    // ==========================================
    // KEEP VALUE BETWEEN 0 AND 1
    // ==========================================

    private static double clamp(double value) {

        if (value < 0.0) {
            return 0.0;
        }

        if (value > 1.0) {
            return 1.0;
        }

        return value;
    }
}
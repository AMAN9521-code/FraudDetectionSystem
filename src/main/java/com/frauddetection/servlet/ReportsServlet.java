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

@WebServlet("/reports")
public class ReportsServlet extends HttpServlet {

    @Override
    protected void doGet(
            HttpServletRequest request,
            HttpServletResponse response)
            throws ServletException, IOException {

        HttpSession session = request.getSession(false);

        if (session == null ||
                session.getAttribute("userId") == null) {

            response.sendRedirect("login.html");
            return;
        }

        int userId =
                (Integer) session.getAttribute("userId");

        String role =
                (String) session.getAttribute("userRole");

        boolean isAdmin =
                "ADMIN".equalsIgnoreCase(role);

        response.setContentType("text/html;charset=UTF-8");

        try (Connection connection =
                     DBConnection.getConnection()) {

            int totalTransactions = 0;
            int flaggedTransactions = 0;
            int totalAlerts = 0;
            int openAlerts = 0;
            int confirmedFraud = 0;
            int falsePositives = 0;

            double totalAmount = 0.0;
            double fraudAmount = 0.0;
            double averageRiskScore = 0.0;
            double confirmedAverageRisk = 0.0;

            double averageAmountScore = 0.0;
            double averageVelocityScore = 0.0;
            double averageLocationScore = 0.0;
            double averageZscoreScore = 0.0;
            double averageMLScore = 0.0;

            String transactionFilter;

            if (isAdmin) {
                transactionFilter = "";
            } else {
                transactionFilter =
                        " WHERE t.user_id = ?";
            }

            // ==========================================
            // 1. TOTAL TRANSACTIONS
            // ==========================================

            String sqlTotal =
                    "SELECT COUNT(*) " +
                    "FROM transactions t" +
                    transactionFilter;

            try (PreparedStatement statement =
                         connection.prepareStatement(sqlTotal)) {

                if (!isAdmin) {
                    statement.setInt(1, userId);
                }

                try (ResultSet rs =
                             statement.executeQuery()) {

                    if (rs.next()) {
                        totalTransactions =
                                rs.getInt(1);
                    }
                }
            }

            // ==========================================
            // 2. FLAGGED TRANSACTIONS
            // ==========================================

            String sqlFlagged =
                    "SELECT COUNT(*) " +
                    "FROM transactions t " +
                    "WHERE t.status = 'FLAGGED' " +
                    (isAdmin
                            ? ""
                            : "AND t.user_id = ?");

            try (PreparedStatement statement =
                         connection.prepareStatement(sqlFlagged)) {

                if (!isAdmin) {
                    statement.setInt(1, userId);
                }

                try (ResultSet rs =
                             statement.executeQuery()) {

                    if (rs.next()) {
                        flaggedTransactions =
                                rs.getInt(1);
                    }
                }
            }

            // ==========================================
            // 3. TOTAL TRANSACTION AMOUNT
            // ==========================================

            String sqlAmount =
                    "SELECT COALESCE(SUM(t.amount), 0) " +
                    "FROM transactions t" +
                    transactionFilter;

            try (PreparedStatement statement =
                         connection.prepareStatement(sqlAmount)) {

                if (!isAdmin) {
                    statement.setInt(1, userId);
                }

                try (ResultSet rs =
                             statement.executeQuery()) {

                    if (rs.next()) {
                        totalAmount =
                                rs.getDouble(1);
                    }
                }
            }

            // ==========================================
            // 4. AVERAGE RISK SCORE
            // ==========================================

            String sqlRisk =
                    "SELECT COALESCE(AVG(t.risk_score), 0) " +
                    "FROM transactions t" +
                    transactionFilter;

            try (PreparedStatement statement =
                         connection.prepareStatement(sqlRisk)) {

                if (!isAdmin) {
                    statement.setInt(1, userId);
                }

                try (ResultSet rs =
                             statement.executeQuery()) {

                    if (rs.next()) {
                        averageRiskScore =
                                rs.getDouble(1);
                    }
                }
            }

            // ==========================================
            // 5. TOTAL FRAUD ALERTS
            // ==========================================

            String sqlAlerts =
                    "SELECT COUNT(*) " +
                    "FROM fraud_alerts fa " +
                    "JOIN transactions t " +
                    "ON fa.transaction_id = t.transaction_id " +
                    "WHERE 1 = 1 " +
                    (isAdmin
                            ? ""
                            : "AND t.user_id = ?");

            try (PreparedStatement statement =
                         connection.prepareStatement(sqlAlerts)) {

                if (!isAdmin) {
                    statement.setInt(1, userId);
                }

                try (ResultSet rs =
                             statement.executeQuery()) {

                    if (rs.next()) {
                        totalAlerts =
                                rs.getInt(1);
                    }
                }
            }

            // ==========================================
            // 6. OPEN ALERTS
            // ==========================================

            String sqlOpen =
                    "SELECT COUNT(*) " +
                    "FROM fraud_alerts fa " +
                    "JOIN transactions t " +
                    "ON fa.transaction_id = t.transaction_id " +
                    "WHERE fa.review_status = 'OPEN' " +
                    (isAdmin
                            ? ""
                            : "AND t.user_id = ?");

            try (PreparedStatement statement =
                         connection.prepareStatement(sqlOpen)) {

                if (!isAdmin) {
                    statement.setInt(1, userId);
                }

                try (ResultSet rs =
                             statement.executeQuery()) {

                    if (rs.next()) {
                        openAlerts =
                                rs.getInt(1);
                    }
                }
            }

            // ==========================================
            // 7. CONFIRMED FRAUD
            // ==========================================

            String sqlConfirmed =
                    "SELECT COUNT(*) " +
                    "FROM fraud_alerts fa " +
                    "JOIN transactions t " +
                    "ON fa.transaction_id = t.transaction_id " +
                    "WHERE fa.review_status = " +
                    "'CONFIRMED_FRAUD' " +
                    (isAdmin
                            ? ""
                            : "AND t.user_id = ?");

            try (PreparedStatement statement =
                         connection.prepareStatement(sqlConfirmed)) {

                if (!isAdmin) {
                    statement.setInt(1, userId);
                }

                try (ResultSet rs =
                             statement.executeQuery()) {

                    if (rs.next()) {
                        confirmedFraud =
                                rs.getInt(1);
                    }
                }
            }

            // ==========================================
            // 8. FALSE POSITIVES
            // ==========================================

            String sqlFalsePositive =
                    "SELECT COUNT(*) " +
                    "FROM fraud_alerts fa " +
                    "JOIN transactions t " +
                    "ON fa.transaction_id = t.transaction_id " +
                    "WHERE fa.review_status = " +
                    "'FALSE_POSITIVE' " +
                    (isAdmin
                            ? ""
                            : "AND t.user_id = ?");

            try (PreparedStatement statement =
                         connection.prepareStatement(
                                 sqlFalsePositive)) {

                if (!isAdmin) {
                    statement.setInt(1, userId);
                }

                try (ResultSet rs =
                             statement.executeQuery()) {

                    if (rs.next()) {
                        falsePositives =
                                rs.getInt(1);
                    }
                }
            }

            // ==========================================
            // 9. CONFIRMED FRAUD AMOUNT
            // ==========================================

            String sqlFraudAmount =
                    "SELECT COALESCE(SUM(t.amount), 0) " +
                    "FROM fraud_alerts fa " +
                    "JOIN transactions t " +
                    "ON fa.transaction_id = t.transaction_id " +
                    "WHERE fa.review_status = " +
                    "'CONFIRMED_FRAUD' " +
                    (isAdmin
                            ? ""
                            : "AND t.user_id = ?");

            try (PreparedStatement statement =
                         connection.prepareStatement(
                                 sqlFraudAmount)) {

                if (!isAdmin) {
                    statement.setInt(1, userId);
                }

                try (ResultSet rs =
                             statement.executeQuery()) {

                    if (rs.next()) {
                        fraudAmount =
                                rs.getDouble(1);
                    }
                }
            }

            // ==========================================
            // 10. CONFIRMED FRAUD AVERAGE RISK
            // ==========================================

            String sqlConfirmedRisk =
                    "SELECT COALESCE(AVG(fa.risk_score), 0) " +
                    "FROM fraud_alerts fa " +
                    "JOIN transactions t " +
                    "ON fa.transaction_id = t.transaction_id " +
                    "WHERE fa.review_status = " +
                    "'CONFIRMED_FRAUD' " +
                    (isAdmin
                            ? ""
                            : "AND t.user_id = ?");

            try (PreparedStatement statement =
                         connection.prepareStatement(
                                 sqlConfirmedRisk)) {

                if (!isAdmin) {
                    statement.setInt(1, userId);
                }

                try (ResultSet rs =
                             statement.executeQuery()) {

                    if (rs.next()) {
                        confirmedAverageRisk =
                                rs.getDouble(1);
                    }
                }
            }

            // ==========================================
            // 11. AVERAGE RULE SCORES
            // ==========================================

           String sqlRuleScores =
        "SELECT " +
        "COALESCE(AVG(fa.amount_score), 0), " +
        "COALESCE(AVG(fa.velocity_score), 0), " +
        "COALESCE(AVG(fa.location_score), 0), " +
        "COALESCE(AVG(fa.zscore_score), 0), " +
        "COALESCE(AVG(NULLIF(fa.ml_score, 0)), 0) " +
        "FROM fraud_alerts fa " +
        "JOIN transactions t " +
        "ON fa.transaction_id = t.transaction_id " +
        "WHERE 1 = 1 " +
        (isAdmin
                ? ""
                : "AND t.user_id = ?");

            try (PreparedStatement statement =
                         connection.prepareStatement(
                                 sqlRuleScores)) {

                if (!isAdmin) {
                    statement.setInt(1, userId);
                }

                try (ResultSet rs =
                             statement.executeQuery()) {

                    if (rs.next()) {

                        averageAmountScore =
                                rs.getDouble(1);

                        averageVelocityScore =
                                rs.getDouble(2);

                        averageLocationScore =
                                rs.getDouble(3);

                        averageZscoreScore =
                                rs.getDouble(4);
                        averageMLScore =
                                rs.getDouble(5);        
                    }
                }
            }

            // ==========================================
            // 12. CALCULATED RATES
            // ==========================================

            double detectionRate = 0.0;

            if (totalTransactions > 0) {

                detectionRate =
                        ((double) flaggedTransactions
                                / totalTransactions)
                                * 100.0;
            }

            double confirmationRate = 0.0;

            if (totalAlerts > 0) {

                confirmationRate =
                        ((double) confirmedFraud
                                / totalAlerts)
                                * 100.0;
            }

            // ==========================================
            // 13. RADAR / DUNE HTML REPORT
            // ==========================================

            StringBuilder html =
                    new StringBuilder();

            html.append("""
                    <!DOCTYPE html>
                    <html lang="en">

                    <head>

                        <meta charset="UTF-8">

                        <meta name="viewport"
                              content="width=device-width, initial-scale=1.0">

                        <title>
                            RADAR - Reports & Analytics
                        </title>

                        <link rel="stylesheet"
                              href="style.css">

                    </head>

                    <body class="radar-servlet-page">

                        <div class="radar-glow"></div>

                        <header class="radar-servlet-header">

                            <div>

                                <h1 class="radar-title">
                                    RADAR
                                </h1>

                                <div class="radar-subtitle">
                                    Risk Analysis and Detection of Anonymous Response
                                </div>

                            </div>

                        </header>


                        <main class="radar-servlet-content">

                            <section class="radar-servlet-panel">

                                <div class="radar-welcome">

                                    <h2>
                                        Reports & Analytics
                                    </h2>

                                    <p>
                                        AI-Powered Fraud Detection Intelligence
                                    </p>

                                    <p>
                                        Transaction statistics, risk analysis
                                        and fraud detection performance.
                                    </p>

                                </div>


                                <div class="radar-report-grid">
                    """);

            appendCard(
                    html,
                    "Total Transactions",
                    String.valueOf(totalTransactions)
            );

            appendCard(
                    html,
                    "Flagged Transactions",
                    String.valueOf(flaggedTransactions)
            );

            appendCard(
                    html,
                    "Fraud Alerts",
                    String.valueOf(totalAlerts)
            );

            appendCard(
                    html,
                    "Open Alerts",
                    String.valueOf(openAlerts)
            );

            appendCard(
                    html,
                    "Confirmed Fraud",
                    String.valueOf(confirmedFraud)
            );

            appendCard(
                    html,
                    "False Positives",
                    String.valueOf(falsePositives)
            );

            appendCard(
                    html,
                    "Total Transaction Amount",
                    "₹" + String.format(
                            "%.2f",
                            totalAmount
                    )
            );

            appendCard(
                    html,
                    "Confirmed Fraud Amount",
                    "₹" + String.format(
                            "%.2f",
                            fraudAmount
                    )
            );

            appendCard(
                    html,
                    "Average Risk Score",
                    String.format(
                            "%.2f%%",
                            averageRiskScore
                    )
            );

            appendCard(
                    html,
                    "Confirmed Fraud Avg Risk",
                    String.format(
                            "%.2f%%",
                            confirmedAverageRisk
                    )
            );

            appendCard(
                    html,
                    "Detection Rate",
                    String.format(
                            "%.2f%%",
                            detectionRate
                    )
            );

            appendCard(
                    html,
                    "Confirmation Rate",
                    String.format(
                            "%.2f%%",
                            confirmationRate
                    )
            );

            html.append("""
                                </div>


                                <div class="radar-report-section">

                                    <h2 class="radar-page-title">
                                        Average Fraud Rule Scores
                                    </h2>

                                    <div class="radar-report-card">
                    """);

            appendRuleBar(
                    html,
                    "Amount Rule",
                    averageAmountScore * 100.0
            );

            appendRuleBar(
                    html,
                    "Velocity Rule",
                    averageVelocityScore * 100.0
            );

            appendRuleBar(
                    html,
                    "Location Rule",
                    averageLocationScore * 100.0
            );

            appendRuleBar(
                    html,
                    "Z-Score Rule",
                    averageZscoreScore * 100.0
            );
            appendRuleBar(
                     html,
                    "Random Forest ML",
                     averageMLScore
            );

            html.append("""
                                    </div>

                                </div>


                                <div class="radar-report-section">

                                    <h2 class="radar-page-title">
                                        Fraud Detection Summary
                                    </h2>

                                    <div class="radar-report-card">

                                        <div class="radar-summary-row">

                                            <span>
                                                Flagged Transactions
                                            </span>

                                            <strong>
                    """);

            html.append(flaggedTransactions);

            html.append("""
                                            </strong>

                                        </div>

                                        <div class="radar-summary-row">

                                            <span>
                                                Confirmed Fraud
                                            </span>

                                            <strong>
                    """);

            html.append(confirmedFraud);

            html.append("""
                                            </strong>

                                        </div>

                                        <div class="radar-summary-row">

                                            <span>
                                                False Positives
                                            </span>

                                            <strong>
                    """);

            html.append(falsePositives);

            html.append("""
                                            </strong>

                                        </div>

                                        <div class="radar-summary-row">

                                            <span>
                                                Open Alerts
                                            </span>

                                            <strong>
                    """);

            html.append(openAlerts);

            html.append("""
                                            </strong>

                                        </div>

                                    </div>

                                </div>


                                <div class="radar-navigation">

                                    <a class="radar-servlet-button"
                                       href="dashboard.html">
                                        Dashboard
                                    </a>

                                    <a class="radar-servlet-button"
                                       href="transaction-history">
                                        Transaction History
                                    </a>

                                    <a class="radar-servlet-button"
                                       href="alerts">
                                        Fraud Alerts
                                    </a>

                                    <a class="radar-servlet-button"
                                       href="admin">
                                        Administration
                                    </a>

                                </div>

                            </section>

                        </main>


                        <footer class="radar-footer">

                            RADAR &nbsp; • &nbsp;
                            RISK ANALYSIS AND DETECTION OF ANONYMOUS RESPONSE

                        </footer>

                    </body>

                    </html>
                    """);

            response.getWriter().println(
                    html.toString()
            );

        } catch (Exception e) {

            e.printStackTrace();

            response.setContentType(
                    "text/html;charset=UTF-8"
            );

            response.getWriter().println("""
                    <!DOCTYPE html>
                    <html lang="en">

                    <head>

                        <meta charset="UTF-8">

                        <meta name="viewport"
                              content="width=device-width, initial-scale=1.0">

                        <title>RADAR - Reports Error</title>

                        <link rel="stylesheet"
                              href="style.css">

                    </head>

                    <body class="radar-servlet-page">

                        <div class="radar-glow"></div>

                        <main class="radar-servlet-content">

                            <section class="radar-servlet-panel">

                                <h1 class="radar-page-title">
                                    Reports Error
                                </h1>

                                <div class="radar-message">
                                    Unable to load reports.
                                    Please try again later.
                                </div>

                                <div class="radar-navigation">

                                    <a class="radar-servlet-button"
                                       href="dashboard.html">
                                        Back to Dashboard
                                    </a>

                                </div>

                            </section>

                        </main>

                    </body>

                    </html>
                    """);
        }
    }

    private void appendCard(
            StringBuilder html,
            String title,
            String value) {

        html.append("""
                <div class="radar-report-card">

                    <h3>
                """);

        html.append(
                escapeHtml(title)
        );

        html.append("""
                    </h3>

                    <div class="radar-report-value">
                """);

        html.append(
                escapeHtml(value)
        );

        html.append("""
                    </div>

                </div>
                """);
    }

    private void appendRuleBar(
        StringBuilder html,
        String name,
        double score) {

    score = Math.max(
            0.0,
            Math.min(100.0, score)
    );

    String formattedScore =
            String.format("%.2f", score);

    html.append("""
            <div class="radar-rule">

                <div class="radar-rule-label">

                    <span>
            """);

    html.append(
            escapeHtml(name)
    );

    html.append("""
                    </span>

                    <strong>
            """);

    html.append(
            formattedScore
    );

    html.append("""
                    %</strong>

                </div>

                <div class="radar-progress">
            """);

    html.append(
            "<div class=\"radar-progress-fill\" style=\"width:"
            + formattedScore
            + "% !important;\"></div>"
    );

    html.append("""
                </div>

            </div>
            """);
}

    private String escapeHtml(String value) {

        if (value == null) {
            return "";
        }

        return value
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }
}

package com.frauddetection.servlet;

import com.frauddetection.util.DBConnection;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

/*
 * =============================================================
 * RADAR - Transaction Analysis Servlet (Explainable AI)
 *
 * URL: /transaction-analysis?id=<transactionId>
 *
 * Shows:
 *  - Transaction details
 *  - Overall fraud risk score
 *  - Individual risk factor breakdown
 *  - Actual fraud detection reason
 *  - Alert review status
 *  - Plain-English AI explanations
 *
 * Uses existing transactions and fraud_alerts tables.
 * No new database columns required.
 * =============================================================
 */

@WebServlet("/transaction-analysis")
public class TransactionAnalysisServlet extends HttpServlet {

    @Override
    protected void doGet(
            HttpServletRequest request,
            HttpServletResponse response)
            throws ServletException, IOException {

        /*
         * =====================================================
         * AUTHENTICATION CHECK
         * =====================================================
         */

        HttpSession session = request.getSession(false);

        if (session == null ||
                session.getAttribute("userId") == null) {

            response.sendRedirect("login.html");
            return;
        }

        int sessionUserId = (Integer) session.getAttribute("userId");

        String role = (String) session.getAttribute("userRole");

        boolean isAdmin = "ADMIN".equalsIgnoreCase(role);

        /*
         * =====================================================
         * PARSE TRANSACTION ID
         * =====================================================
         */

        String idParam = request.getParameter("id");

        if (idParam == null || idParam.trim().isEmpty()) {

            sendError(
                    response,
                    "Missing Parameter",
                    "No transaction ID was provided.");
            return;
        }

        int transactionId;

        try {
            transactionId = Integer.parseInt(idParam.trim());

        } catch (NumberFormatException e) {

            sendError(
                    response,
                    "Invalid Parameter",
                    "Transaction ID must be a number.");
            return;
        }

        response.setContentType("text/html;charset=UTF-8");

        PrintWriter out = response.getWriter();

        /*
         * =====================================================
         * DATABASE QUERY
         * =====================================================
         */

        String sql = """
                SELECT
                    t.transaction_id,
                    t.user_id,
                    t.amount,
                    t.merchant,
                    t.location,
                    t.txn_timestamp,
                    t.status,
                    t.risk_score,
                    fa.alert_id,
                    fa.reason,
                    fa.amount_score,
                    fa.velocity_score,
                    fa.location_score,
                    fa.zscore_score,
                    fa.ml_score,
                    fa.review_status
                FROM transactions t
                LEFT JOIN fraud_alerts fa
                    ON t.transaction_id = fa.transaction_id
                WHERE t.transaction_id = ?
                """;

        try (Connection connection = DBConnection.getConnection();
                PreparedStatement statement = connection.prepareStatement(sql)) {

            statement.setInt(1, transactionId);

            try (ResultSet rs = statement.executeQuery()) {

                if (!rs.next()) {

                    sendError(
                            response,
                            "Not Found",
                            "Transaction #" + transactionId +
                                    " was not found.");
                    return;
                }

                /* ---- SECURITY CHECK ---- */

                int txnUserId = rs.getInt("user_id");

                if (!isAdmin && txnUserId != sessionUserId) {

                    sendError(
                            response,
                            "Access Denied",
                            "You do not have permission to view this transaction.");
                    return;
                }

                /* ---- EXTRACT VALUES ---- */

                double amount = rs.getDouble("amount");

                String merchant = rs.getString("merchant");

                String location = rs.getString("location");

                String timestamp = String.valueOf(rs.getTimestamp("txn_timestamp"));

                String status = rs.getString("status");

                double riskScore = rs.getDouble("risk_score");

                boolean hasAlert = rs.getObject("alert_id") != null;

                double amountScore = hasAlert ? rs.getDouble("amount_score") : 0.0;

                double velocityScore = hasAlert ? rs.getDouble("velocity_score") : 0.0;

                double locationScore = hasAlert ? rs.getDouble("location_score") : 0.0;

                double zscoreScore = hasAlert ? rs.getDouble("zscore_score") : 0.0;

                double mlScore = hasAlert ? rs.getDouble("ml_score") : 0.0;

                String reviewStatus = hasAlert ? rs.getString("review_status") : null;

                String reason = hasAlert ? rs.getString("reason") : null;

                /*
                 * =====================================================
                 * RENDER HTML PAGE
                 * =====================================================
                 */

                out.println("""
                        <!DOCTYPE html>
                        <html lang="en">

                        <head>

                            <meta charset="UTF-8">

                            <meta name="viewport"
                                  content="width=device-width, initial-scale=1.0">

                            <title>RADAR - Transaction Analysis</title>

                            <link rel="stylesheet"
                                  href="style.css">

                        </head>

                        <body class="radar-servlet-page">

                        <div class="radar-glow"></div>

                        <header class="radar-servlet-header">

                            <h1>RADAR</h1>

                            <p>
                                Risk Analysis and Detection of Anonymous Response
                            </p>

                        </header>

                        <main class="radar-servlet-content">

                            <section class="radar-servlet-panel">
                        """);

                /* ---- PAGE TITLE ---- */

                out.println("""
                            <h2 class="radar-page-title">
                                Transaction Analysis
                            </h2>

                            <p style="text-align:center;color:#9f866e;margin-bottom:25px;">
                                Explainable AI — Why was this decision made?
                            </p>
                        """);

                /* ---- NAVIGATION ---- */

                out.println("""
                            <div class="radar-navigation">

                                <a href="dashboard.html">
                                    Dashboard
                                </a>

                                <a href="transaction-history">
                                    Transaction History
                                </a>

                                <a href="alerts">
                                    Fraud Alerts
                                </a>

                            </div>
                        """);

                /*
                 * =====================================================
                 * TRANSACTION SUMMARY
                 * =====================================================
                 */

                String statusClass = getStatusClass(status);

                out.println("<div class=\"radar-analysis-card\">");

                out.println("""
                        <h3 class="radar-analysis-section-title">
                            Transaction Details
                        </h3>
                        """);

                out.println("<div class=\"radar-analysis-grid\">");

                printDetailRow(
                        out,
                        "Transaction ID",
                        String.valueOf(transactionId));

                printDetailRow(
                        out,
                        "Amount",
                        String.format("₹%.2f", amount));

                printDetailRow(
                        out,
                        "Merchant",
                        escapeHtml(merchant));

                printDetailRow(
                        out,
                        "Location",
                        escapeHtml(location));

                printDetailRow(
                        out,
                        "Date / Time",
                        escapeHtml(timestamp));

                out.println("""
                        <div class="radar-detail-row">
                            <span class="radar-detail-label">Status</span>
                        """);

                out.println(
                        "<span class=\"radar-detail-value\">" +
                                "<span class=\"" + statusClass + "\">" +
                                escapeHtml(status) +
                                "</span></span></div>");

                out.println("</div>");
                out.println("</div>");

                /*
                 * =====================================================
                 * OVERALL RISK SCORE
                 * =====================================================
                 */

                String gaugeColor = riskScore >= 75
                        ? "#c0392b"
                        : riskScore >= 50
                                ? "#e67e22"
                                : riskScore >= 25
                                        ? "#f1c40f"
                                        : "#27ae60";

                out.println("<div class=\"radar-analysis-card\">");

                out.println("""
                        <h3 class="radar-analysis-section-title">
                            Overall Risk Score
                        </h3>
                        """);

                out.println("<div class=\"radar-risk-gauge-container\">");

                out.println(
                        "<div class=\"radar-risk-gauge-label\" style=\"color:" +
                                gaugeColor + ";\">" +
                                String.format("%.2f%%", riskScore) +
                                "</div>");

                out.println("<div class=\"radar-progress-track\">");

                out.println(
                        "<div class=\"radar-progress-fill\" style=\"width:" +
                                Math.max(0, Math.min(riskScore, 100)) +
                                "%;background:" + gaugeColor + ";\"></div>");

                out.println("</div>");

                out.println(
                        "<div class=\"radar-risk-verdict " +
                                statusClass + "\">" +
                                escapeHtml(getRiskVerdict(status, riskScore)) +
                                "</div>");

                out.println("</div>");
                out.println("</div>");

                /*
                 * =====================================================
                 * INDIVIDUAL RISK FACTOR BREAKDOWN
                 * =====================================================
                 */

                if (hasAlert) {

                    out.println("<div class=\"radar-analysis-card\">");

                    out.println("""
                            <h3 class="radar-analysis-section-title">
                                Risk Factor Breakdown
                            </h3>
                            """);

                    out.println("""
                            <p style="color:#9f866e;font-size:13px;margin-bottom:18px;">
                                Each factor's score (0–100%) shows how much
                                it contributed to the fraud decision.
                                The rule-based factors are weighted and
                                combined (40%), then blended with the
                                Random Forest ML prediction (60%).
                            </p>
                            """);

                    printFactor(
                            out,
                            "Amount Risk",
                            amountScore * 100,
                            getAmountExplanation(amountScore));

                    printFactor(
                            out,
                            "Velocity Risk",
                            velocityScore * 100,
                            getVelocityExplanation(velocityScore));

                    printFactor(
                            out,
                            "Location Risk",
                            locationScore * 100,
                            getLocationExplanation(locationScore));

                    printFactor(
                            out,
                            "Z-Score (Statistical Anomaly)",
                            zscoreScore * 100,
                            getZscoreExplanation(zscoreScore));

                    printFactor(
                            out,
                            "Random Forest ML Model",
                            mlScore,
                            getMLExplanation(mlScore));

                    out.println("</div>");

                    /*
                     * =====================================================
                     * ACTUAL FRAUD DETECTION REASON
                     * FIX: REASON VARIABLE IS NOW USED
                     * =====================================================
                     */

                    if (reason != null && !reason.trim().isEmpty()) {

                        out.println("<div class=\"radar-analysis-card\">");

                        out.println("""
                                <h3 class="radar-analysis-section-title">
                                    Why Was This Transaction Flagged?
                                </h3>
                                """);

                        out.println(
                                "<p style=\"color:#9f866e;font-size:14px;padding:16px;\">" +
                                        escapeHtml(reason) +
                                        "</p>");

                        out.println("</div>");
                    }

                    /*
                     * =====================================================
                     * ALERT REVIEW STATUS
                     * =====================================================
                     */

                    if (reviewStatus != null) {

                        String reviewClass = getAlertStatusClass(reviewStatus);

                        out.println("<div class=\"radar-analysis-card\">");

                        out.println("""
                                <h3 class="radar-analysis-section-title">
                                    Alert Review Status
                                </h3>
                                """);

                        out.println(
                                "<div style=\"padding:12px;\">" +
                                        "<span class=\"" + reviewClass + "\">" +
                                        escapeHtml(reviewStatus) +
                                        "</span></div>");

                        out.println("</div>");
                    }

                } else {

                    /*
                     * =====================================================
                     * APPROVED TRANSACTION
                     * =====================================================
                     */

                    out.println("<div class=\"radar-analysis-card\">");

                    out.println("""
                            <h3 class="radar-analysis-section-title">
                                Risk Analysis
                            </h3>
                            """);

                    out.println("""
                            <p style="color:#9f866e;font-size:14px;padding:16px;">
                                This transaction was
                                <strong style="color:#27ae60;">approved</strong>.
                            """);

                    out.println(
                            "The combined RADAR risk score of <strong>" +
                                    String.format("%.2f%%", riskScore) +
                                    "</strong> was below the flagging threshold of 50%.");

                    out.println("""
                                No detailed factor breakdown is stored for
                                approved transactions.

                                Individual factor scores are only stored
                                for flagged transactions.
                            </p>
                            """);

                    out.println("</div>");
                }

                /*
                 * =====================================================
                 * BOTTOM NAVIGATION
                 * =====================================================
                 */

                out.println("""
                                <div class="radar-navigation">

                                    <a href="transaction-history">
                                        Transaction History
                                    </a>

                                    <a href="transaction.html">
                                        New Transaction
                                    </a>

                                    <a href="dashboard.html">
                                        Back to Dashboard
                                    </a>

                                </div>

                            </section>

                        </main>

                        <footer class="radar-footer">

                            RADAR
                            &nbsp; • &nbsp;
                            EXPLAINABLE AI
                            &nbsp; • &nbsp;
                            FRAUD INTELLIGENCE

                        </footer>

                        </body>
                        </html>
                        """);
            }

        } catch (Exception e) {

            e.printStackTrace();

            sendError(
                    response,
                    "System Error",
                    "Could not load transaction analysis. Please try again later.");
        }
    }

    /*
     * =========================================================
     * RENDER HELPERS
     * =========================================================
     */

    private void printDetailRow(
            PrintWriter out,
            String label,
            String value) {

        out.println(
                "<div class=\"radar-detail-row\">" +
                        "<span class=\"radar-detail-label\">" +
                        escapeHtml(label) +
                        "</span>" +
                        "<span class=\"radar-detail-value\">" +
                        value +
                        "</span></div>");
    }

    private void printFactor(
            PrintWriter out,
            String label,
            double scorePercent,
            String explanation) {

        double clamped = Double.isFinite(scorePercent)
                ? Math.max(0, Math.min(100, scorePercent))
                : 0;

        String color = clamped >= 75
                ? "#c0392b"
                : clamped >= 50
                        ? "#e67e22"
                        : clamped >= 25
                                ? "#f1c40f"
                                : "#27ae60";

        out.println("<div class=\"radar-factor-row\">");

        out.println("<div class=\"radar-factor-header\">");

        out.println(
                "<span class=\"radar-factor-label\">" +
                        escapeHtml(label) +
                        "</span>");

        out.println(
                "<span class=\"radar-factor-score\" style=\"color:" +
                        color + ";\">" +
                        String.format("%.1f%%", clamped) +
                        "</span>");

        out.println("</div>");

        out.println("<div class=\"radar-progress-track\">");

        out.println(
                "<div class=\"radar-progress-fill\" style=\"width:" +
                        clamped + "%;background:" + color + ";\"></div>");

        out.println("</div>");

        out.println(
                "<p class=\"radar-factor-explanation\">" +
                        escapeHtml(explanation) +
                        "</p>");

        out.println("</div>");
    }

    /*
     * =========================================================
     * EXPLANATION TEXT GENERATORS
     * =========================================================
     */

    private String getAmountExplanation(double score) {

        if (score >= 1.0) {
            return "The transaction amount is extremely high — more than twice the configured high-value threshold. This is a strong fraud indicator.";

        } else if (score >= 0.75) {
            return "The transaction amount significantly exceeds the configured threshold. High-value transactions carry elevated fraud risk.";

        } else if (score >= 0.5) {
            return "The transaction amount is above the configured risk threshold, contributing moderately to the fraud score.";

        } else if (score >= 0.25) {
            return "The transaction amount is elevated but within moderate range relative to the configured threshold.";

        } else {
            return "The transaction amount is within normal range and poses low amount-based risk.";
        }
    }

    private String getVelocityExplanation(double score) {

        if (score >= 1.0) {
            return "Multiple transactions were detected from this user within a very short time window, well above the velocity limit. This is a strong indicator of automated or fraudulent activity.";

        } else if (score >= 0.75) {
            return "Unusually high transaction frequency was detected for this user in the recent time window.";

        } else if (score >= 0.5) {
            return "This user had an above-average number of recent transactions, which raises moderate velocity-based concern.";

        } else if (score >= 0.25) {
            return "Some recent transaction activity was detected but within acceptable limits.";

        } else {
            return "Transaction velocity for this user is normal with no unusual frequency detected.";
        }
    }

    private String getLocationExplanation(double score) {

        if (score >= 0.5) {
            return "This location has not been seen in this user's previous transaction history. A new location is a fraud risk signal — it may indicate account takeover or use from an unfamiliar place.";

        } else {
            return "This location has been seen in this user's previous transaction history. No location-based anomaly was detected.";
        }
    }

    private String getZscoreExplanation(double score) {

        if (score >= 1.0) {
            return "The transaction amount is a severe statistical outlier compared to this user's historical average — more than 3 standard deviations away. This is a strong anomaly signal.";

        } else if (score >= 0.75) {
            return "The amount deviates significantly from this user's historical spending patterns.";

        } else if (score >= 0.5) {
            return "The amount is moderately unusual compared to this user's historical average.";

        } else if (score >= 0.25) {
            return "The amount shows mild deviation from historical patterns.";

        } else {
            return "The transaction amount is consistent with this user's historical spending patterns.";
        }
    }

    private String getMLExplanation(double mlScore) {

        if (mlScore >= 75) {
            return "The Random Forest ML model predicted a very high fraud probability. The model uses transaction amount, merchant category, and location patterns learned from historical data.";

        } else if (mlScore >= 50) {
            return "The Random Forest ML model predicted a moderately high fraud probability based on this transaction's features.";

        } else if (mlScore >= 25) {
            return "The ML model flagged some concern but remained below the high-risk threshold.";

        } else {
            return "The Random Forest ML model assessed low fraud probability for this transaction's features.";
        }
    }

    private String getRiskVerdict(String status, double riskScore) {

        if ("FLAGGED".equalsIgnoreCase(status)) {
            return "⚠ FLAGGED — Risk score exceeds the 50% threshold.";

        } else if ("APPROVED".equalsIgnoreCase(status)) {
            return "✓ APPROVED — Risk score is within safe limits.";

        } else {
            return "⏳ PENDING — Analysis in progress.";
        }
    }

    /*
     * =========================================================
     * CSS CLASS HELPERS
     * =========================================================
     */

    private String getStatusClass(String status) {

        if (status == null)
            return "status";

        switch (status.toUpperCase()) {

            case "FLAGGED":
                return "radar-status-fraud";

            case "APPROVED":
                return "radar-status-false";

            case "PENDING":
                return "radar-status-open";

            default:
                return "status";
        }
    }

    private String getAlertStatusClass(String status) {

        if (status == null)
            return "status";

        switch (status.toUpperCase()) {

            case "OPEN":
                return "radar-status-open";

            case "CONFIRMED_FRAUD":
                return "radar-status-fraud";

            case "FALSE_POSITIVE":
                return "radar-status-false";

            default:
                return "status";
        }
    }

    /*
     * =========================================================
     * ERROR PAGE
     * =========================================================
     */

    private void sendError(
            HttpServletResponse response,
            String title,
            String message)
            throws IOException {

        response.setContentType("text/html;charset=UTF-8");

        response.getWriter().println(
                "<!DOCTYPE html>" +
                        "<html><head><meta charset='UTF-8'>" +
                        "<title>" + escapeHtml(title) + "</title>" +
                        "<link rel='stylesheet' href='style.css'>" +
                        "</head>" +

                        "<body class='radar-servlet-page'>" +

                        "<div class='radar-glow'></div>" +

                        "<main class='radar-servlet-content'>" +

                        "<section class='radar-servlet-panel' " +
                        "style='text-align:center;padding:60px;'>" +

                        "<h2 style='color:#c0392b;'>" +
                        escapeHtml(title) +
                        "</h2>" +

                        "<p style='color:#9f866e;'>" +
                        escapeHtml(message) +
                        "</p>" +

                        "<a href='transaction-history' " +
                        "class='radar-servlet-button'>" +
                        "Transaction History</a>" +

                        "</section></main></body></html>");
    }

    /*
     * =========================================================
     * HTML ESCAPING
     * =========================================================
     */

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

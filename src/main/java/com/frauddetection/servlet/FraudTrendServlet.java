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
import java.util.ArrayList;
import java.util.List;

/*
 * =============================================================
 * RADAR - Fraud Trend & Anomaly Monitoring Dashboard
 *
 * URL: /fraud-trend
 * Access: ADMIN only
 *
 * Shows:
 *  - Summary statistics (total, flagged, approved, flagged%)
 *  - Daily fraud trend chart (last 14 days) via Chart.js
 *  - Weekly fraud trend chart (last 8 weeks) via Chart.js
 *  - Unusual activity detection (days where flagged% > 2x average)
 *
 * No new database schema required. All data is from the
 * existing transactions table.
 * =============================================================
 */
@WebServlet("/fraud-trend")
public class FraudTrendServlet extends HttpServlet {

    @Override
    protected void doGet(
            HttpServletRequest request,
            HttpServletResponse response)
            throws ServletException, IOException {

        /*
         * =====================================================
         * AUTHENTICATION + ADMIN CHECK
         * =====================================================
         */

        HttpSession session = request.getSession(false);

        if (session == null ||
                session.getAttribute("userId") == null) {

            response.sendRedirect("login.html");
            return;
        }

        String role = (String) session.getAttribute("userRole");

        if (!"ADMIN".equalsIgnoreCase(role)) {

            response.sendRedirect("dashboard.html");
            return;
        }

        response.setContentType("text/html;charset=UTF-8");

        PrintWriter out = response.getWriter();

        try (Connection connection = DBConnection.getConnection()) {

            /*
             * =====================================================
             * 1. SUMMARY STATISTICS
             * =====================================================
             */

            int totalTransactions = 0;
            int flaggedCount = 0;
            int approvedCount = 0;

            String sqlSummary = """
                    SELECT
                        COUNT(*) AS total,
                        SUM(CASE WHEN status = 'FLAGGED'  THEN 1 ELSE 0 END) AS flagged,
                        SUM(CASE WHEN status = 'APPROVED' THEN 1 ELSE 0 END) AS approved
                    FROM transactions
                    """;

            try (PreparedStatement ps = connection.prepareStatement(sqlSummary);
                    ResultSet rs = ps.executeQuery()) {

                if (rs.next()) {
                    totalTransactions = rs.getInt("total");
                    flaggedCount = rs.getInt("flagged");
                    approvedCount = rs.getInt("approved");
                }
            }

            double flaggedPercent = totalTransactions > 0
                    ? (flaggedCount * 100.0 / totalTransactions)
                    : 0.0;

            /*
             * =====================================================
             * 2. DAILY TREND — last 14 days
             * =====================================================
             */

            List<String> dailyLabels = new ArrayList<>();
            List<Integer> dailyTotal = new ArrayList<>();
            List<Integer> dailyFlag = new ArrayList<>();

            String sqlDaily = """
                    SELECT
                        DATE(txn_timestamp) AS txn_date,
                        COUNT(*) AS total,
                        SUM(CASE WHEN status = 'FLAGGED' THEN 1 ELSE 0 END) AS flagged
                    FROM transactions
                    WHERE txn_timestamp >= DATE_SUB(CURDATE(), INTERVAL 14 DAY)
                    GROUP BY DATE(txn_timestamp)
                    ORDER BY txn_date ASC
                    """;

            try (PreparedStatement ps = connection.prepareStatement(sqlDaily);
                    ResultSet rs = ps.executeQuery()) {

                while (rs.next()) {
                    dailyLabels.add(rs.getString("txn_date"));
                    dailyTotal.add(rs.getInt("total"));
                    dailyFlag.add(rs.getInt("flagged"));
                }
            }

            /*
             * =====================================================
             * 3. WEEKLY TREND — last 8 weeks
             * =====================================================
             */

            List<String> weeklyLabels = new ArrayList<>();
            List<Integer> weeklyTotal = new ArrayList<>();
            List<Integer> weeklyFlag = new ArrayList<>();

            String sqlWeekly = """
                    SELECT
                        YEARWEEK(txn_timestamp, 1) AS yr_week,
                        MIN(DATE(txn_timestamp))   AS week_start,
                        COUNT(*) AS total,
                        SUM(CASE WHEN status = 'FLAGGED' THEN 1 ELSE 0 END) AS flagged
                    FROM transactions
                    WHERE txn_timestamp >= DATE_SUB(CURDATE(), INTERVAL 8 WEEK)
                    GROUP BY YEARWEEK(txn_timestamp, 1)
                    ORDER BY yr_week ASC
                    """;

            try (PreparedStatement ps = connection.prepareStatement(sqlWeekly);
                    ResultSet rs = ps.executeQuery()) {

                while (rs.next()) {
                    weeklyLabels.add("Week of " + rs.getString("week_start"));
                    weeklyTotal.add(rs.getInt("total"));
                    weeklyFlag.add(rs.getInt("flagged"));
                }
            }

            /*
             * =====================================================
             * 4. UNUSUAL ACTIVITY DETECTION
             * Days where flagged% is more than 2× the overall avg
             * =====================================================
             */

            List<String[]> anomalies = new ArrayList<>();

            if (!dailyLabels.isEmpty() && flaggedPercent > 0) {

                for (int i = 0; i < dailyLabels.size(); i++) {

                    int dayTotal = dailyTotal.get(i);
                    int dayFlagged = dailyFlag.get(i);

                    if (dayTotal > 0) {

                        double dayPct = dayFlagged * 100.0 / dayTotal;

                        if (dayPct > (flaggedPercent * 2.0)) {

                            anomalies.add(new String[] {
                                    dailyLabels.get(i),
                                    String.format("%.1f%%", dayPct),
                                    String.valueOf(dayFlagged),
                                    String.valueOf(dayTotal)
                            });
                        }
                    }
                }
            }

            /*
             * =====================================================
             * 5. BUILD HTML
             * =====================================================
             */

            out.println("""
                    <!DOCTYPE html>
                    <html lang="en">

                    <head>

                        <meta charset="UTF-8">

                        <meta name="viewport"
                              content="width=device-width, initial-scale=1.0">

                        <title>
                            RADAR - Fraud Trend Monitor
                        </title>

                        <link rel="stylesheet"
                              href="style.css">

                        <!-- Chart.js from CDN — no new Maven dependency needed -->
                        <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>

                    </head>

                    <body class="radar-servlet-page">

                    <div class="radar-glow"></div>


                    <header class="radar-servlet-header">

                        <h1>
                            RADAR
                        </h1>

                        <p>
                            Risk Analysis and Detection of Anonymous Response
                        </p>

                    </header>


                    <main class="radar-servlet-content">

                        <section class="radar-servlet-panel">
                    """);

            out.println("""
                                <h2 class="radar-page-title">
                                    Fraud Trend &amp; Anomaly Monitor
                                </h2>

                                <p style="text-align:center;color:#9f866e;margin-bottom:25px;">
                                    Admin-only view — real-time fraud activity intelligence
                                </p>
                    """);

            /* ---- navigation ---- */

            out.println("""
                                <div class="radar-navigation">

                                    <a href="dashboard.html">
                                        Dashboard
                                    </a>

                                    <a href="alerts">
                                        Fraud Alerts
                                    </a>

                                    <a href="reports">
                                        Reports
                                    </a>

                                    <a href="admin">
                                        Administration
                                    </a>

                                </div>
                    """);

            /* ---- summary stats grid ---- */

            out.println("<div class=\"radar-report-grid\">");

            appendStatCard(out, "Total Transactions",
                    String.valueOf(totalTransactions), "#e4b983");

            appendStatCard(out, "Flagged Transactions",
                    String.valueOf(flaggedCount),
                    flaggedCount > 0 ? "#c0392b" : "#27ae60");

            appendStatCard(out, "Approved Transactions",
                    String.valueOf(approvedCount), "#27ae60");

            appendStatCard(out, "Flagged Rate",
                    String.format("%.2f%%", flaggedPercent),
                    flaggedPercent >= 20 ? "#c0392b"
                            : flaggedPercent >= 10 ? "#e67e22"
                                    : "#27ae60");

            out.println("</div>");

            /* ---- daily chart ---- */

            out.println("""
                                <div class="radar-analysis-card">
                                    <h3 class="radar-analysis-section-title">
                                        Daily Fraud Trend — Last 14 Days
                                    </h3>
                                    <div class="radar-chart-container">
                                        <canvas id="dailyChart"></canvas>
                                    </div>
                                </div>
                    """);

            /* ---- weekly chart ---- */

            out.println("""
                                <div class="radar-analysis-card">
                                    <h3 class="radar-analysis-section-title">
                                        Weekly Fraud Trend — Last 8 Weeks
                                    </h3>
                                    <div class="radar-chart-container">
                                        <canvas id="weeklyChart"></canvas>
                                    </div>
                                </div>
                    """);

            /* ---- anomaly table ---- */

            /* ---- anomaly table ---- */

            out.println("""
                    <div class="radar-analysis-card">
                        <h3 class="radar-analysis-section-title">
                            &#9888; Unusual Activity Detected
                        </h3>
                        <p style="color:#9f866e;font-size:13px;margin-bottom:14px;">
                            Days where the flagged percentage is more than
                            twice the overall average
                    """);

            out.println(
                    "(" + String.format("%.2f%%", flaggedPercent) + ").");

            out.println("""
                        </p>
                    """);

            if (anomalies.isEmpty()) {

                out.println("""
                                        <p style="color:#27ae60;padding:12px;">
                                            ✓ No unusual activity detected in the last 14 days.
                                        </p>
                        """);

            } else {

                out.println("""
                                        <div class="radar-servlet-table-wrapper">
                                        <table class="radar-servlet-table">
                                            <thead>
                                                <tr>
                                                    <th>Date</th>
                                                    <th>Flagged %</th>
                                                    <th>Flagged Count</th>
                                                    <th>Total on Day</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                        """);

                for (String[] row : anomalies) {
                    out.println("<tr>");
                    out.println("<td>" + escapeHtml(row[0]) + "</td>");
                    out.println("<td><span class=\"radar-risk-score\">" + escapeHtml(row[1]) + "</span></td>");
                    out.println("<td>" + escapeHtml(row[2]) + "</td>");
                    out.println("<td>" + escapeHtml(row[3]) + "</td>");
                    out.println("</tr>");
                }

                out.println("""
                                            </tbody>
                                        </table>
                                        </div>
                        """);
            }

            out.println("</div>");

            /* ---- bottom navigation ---- */

            out.println("""
                                <div class="radar-navigation">

                                    <a href="reports">
                                        Reports
                                    </a>

                                    <a href="alerts">
                                        Fraud Alerts
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
                            FRAUD INTELLIGENCE
                            &nbsp; • &nbsp;
                            ANOMALY MONITORING

                        </footer>
                    """);

            /* ---- Chart.js inline script ---- */

            out.println("<script>");

            /* Daily chart data */
            out.print("const dailyLabels = [");
            for (int i = 0; i < dailyLabels.size(); i++) {
                if (i > 0)
                    out.print(",");
                out.print("'" + escapeJs(dailyLabels.get(i)) + "'");
            }
            out.println("];");

            out.print("const dailyTotal = [");
            for (int i = 0; i < dailyTotal.size(); i++) {
                if (i > 0)
                    out.print(",");
                out.print(dailyTotal.get(i));
            }
            out.println("];");

            out.print("const dailyFlag = [");
            for (int i = 0; i < dailyFlag.size(); i++) {
                if (i > 0)
                    out.print(",");
                out.print(dailyFlag.get(i));
            }
            out.println("];");

            /* Weekly chart data */
            out.print("const weeklyLabels = [");
            for (int i = 0; i < weeklyLabels.size(); i++) {
                if (i > 0)
                    out.print(",");
                out.print("'" + escapeJs(weeklyLabels.get(i)) + "'");
            }
            out.println("];");

            out.print("const weeklyTotal = [");
            for (int i = 0; i < weeklyTotal.size(); i++) {
                if (i > 0)
                    out.print(",");
                out.print(weeklyTotal.get(i));
            }
            out.println("];");

            out.print("const weeklyFlag = [");
            for (int i = 0; i < weeklyFlag.size(); i++) {
                if (i > 0)
                    out.print(",");
                out.print(weeklyFlag.get(i));
            }
            out.println("];");

            out.println("""
                    const chartDefaults = {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                labels: { color: '#c0a58c', font: { size: 12 } }
                            }
                        },
                        scales: {
                            x: {
                                ticks: { color: '#9f866e', font: { size: 11 } },
                                grid:  { color: 'rgba(184,117,56,0.12)' }
                            },
                            y: {
                                beginAtZero: true,
                                ticks: { color: '#9f866e', font: { size: 11 } },
                                grid:  { color: 'rgba(184,117,56,0.12)' }
                            }
                        }
                    };

                    new Chart(document.getElementById('dailyChart'), {
                        type: 'bar',
                        data: {
                            labels: dailyLabels,
                            datasets: [
                                {
                                    label: 'Total Transactions',
                                    data: dailyTotal,
                                    backgroundColor: 'rgba(184,117,56,0.45)',
                                    borderColor: '#b87538',
                                    borderWidth: 1
                                },
                                {
                                    label: 'Flagged',
                                    data: dailyFlag,
                                    backgroundColor: 'rgba(192,57,43,0.65)',
                                    borderColor: '#c0392b',
                                    borderWidth: 1
                                }
                            ]
                        },
                        options: chartDefaults
                    });

                    new Chart(document.getElementById('weeklyChart'), {
                        type: 'line',
                        data: {
                            labels: weeklyLabels,
                            datasets: [
                                {
                                    label: 'Total Transactions',
                                    data: weeklyTotal,
                                    borderColor: '#b87538',
                                    backgroundColor: 'rgba(184,117,56,0.15)',
                                    tension: 0.3,
                                    fill: true,
                                    pointBackgroundColor: '#e4b983'
                                },
                                {
                                    label: 'Flagged',
                                    data: weeklyFlag,
                                    borderColor: '#c0392b',
                                    backgroundColor: 'rgba(192,57,43,0.12)',
                                    tension: 0.3,
                                    fill: true,
                                    pointBackgroundColor: '#e74c3c'
                                }
                            ]
                        },
                        options: chartDefaults
                    });
                    """);

            out.println("</script>");
            out.println("</body></html>");

        } catch (Exception e) {

            e.printStackTrace();

            out.println("""
                    <!DOCTYPE html>
                    <html><head><meta charset='UTF-8'>
                    <title>Error</title>
                    <link rel='stylesheet' href='style.css'>
                    </head>
                    <body class='radar-servlet-page'>
                    <main class='radar-servlet-content'>
                    <section class='radar-servlet-panel' style='text-align:center;padding:60px;'>
                    <h2 style='color:#c0392b;'>System Error</h2>
                    <p style='color:#9f866e;'>Could not load fraud trend data. Please try again later.</p>
                    <a href='dashboard.html' class='radar-servlet-button'>Dashboard</a>
                    </section></main></body></html>
                    """);
        }
    }

    /*
     * =========================================================
     * HELPER: stat card HTML
     * =========================================================
     */

    private void appendStatCard(
            PrintWriter out,
            String label,
            String value,
            String color) {

        out.println(
                "<div class=\"radar-report-card\" style=\"text-align:center;\">" +
                        "    <div style=\"font-size:11px;letter-spacing:2px;text-transform:uppercase;" +
                        "                color:#9f866e;margin-bottom:12px;\">" +
                        escapeHtml(label) +
                        "    </div>" +
                        "    <div style=\"font-size:34px;font-weight:400;color:" + color + ";\">" +
                        escapeHtml(value) +
                        "    </div>" +
                        "</div>");
    }

    /*
     * =========================================================
     * HTML + JS ESCAPING
     * =========================================================
     */

    private String escapeHtml(String value) {

        if (value == null)
            return "";

        return value
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }

    private String escapeJs(String value) {

        if (value == null)
            return "";

        return value
                .replace("\\", "\\\\")
                .replace("'", "\\'")
                .replace("\n", "\\n")
                .replace("\r", "");
    }
}

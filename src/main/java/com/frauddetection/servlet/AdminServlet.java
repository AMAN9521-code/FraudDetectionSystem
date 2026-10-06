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
import java.util.Locale;

@WebServlet("/admin")
public class AdminServlet extends HttpServlet {

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

        String role =
                (String) session.getAttribute("userRole");

        // ==========================================
        // ACCESS DENIED (non-admin users)
        // ==========================================

        if (!"ADMIN".equalsIgnoreCase(role)) {

            response.setContentType("text/html;charset=UTF-8");

            response.getWriter().println("""
                    <!DOCTYPE html>
                    <html lang="en">
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <title>RADAR - Access Denied</title>
                        <link rel="icon" type="image/svg+xml" href="favicon.svg">
                        <link rel="stylesheet" href="style.css">
                    </head>
                    <body class="radar-servlet-page">
                        <div class="radar-glow"></div>
                        <main class="radar-servlet-content">
                            <section class="radar-servlet-panel">
                                <div class="radar-welcome">
                                    <h2>Access Denied</h2>
                                    <p>Only administrators can access system administration.</p>
                                </div>
                                <div class="radar-navigation">
                                    <a class="radar-servlet-button" href="dashboard.html">Back to Dashboard</a>
                                </div>
                            </section>
                        </main>
                    </body>
                    </html>
                    """);

            return;
        }

        // ==========================================
        // ADMIN PAGE
        // ==========================================

        try (Connection connection =
                     DBConnection.getConnection()) {

            double amountThreshold = 0;
            int velocityLimit = 0;
            int velocityWindow = 0;
            double zscoreThreshold = 0;

            String sql = """
                    SELECT amount_threshold,
                           velocity_limit,
                           velocity_window_minutes,
                           zscore_threshold
                    FROM detection_config
                    ORDER BY config_id DESC
                    LIMIT 1
                    """;

            try (PreparedStatement statement =
                         connection.prepareStatement(sql);
                 ResultSet rs =
                         statement.executeQuery()) {

                if (rs.next()) {

                    amountThreshold =
                            rs.getDouble("amount_threshold");

                    velocityLimit =
                            rs.getInt("velocity_limit");

                    velocityWindow =
                            rs.getInt("velocity_window_minutes");

                    zscoreThreshold =
                            rs.getDouble("zscore_threshold");
                }
            }

            response.setContentType("text/html;charset=UTF-8");

            // The four %s below are filled in, in order:
            // amount threshold, velocity limit, velocity window, z-score threshold.
            // (No other percent signs may appear in this block.)
            String page = """
                    <!DOCTYPE html>
                    <html lang="en">
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <title>RADAR - Administration</title>
                        <link rel="icon" type="image/svg+xml" href="favicon.svg">
                        <link rel="stylesheet" href="style.css">
                    </head>

                    <body class="radar-servlet-page">

                        <div class="radar-glow"></div>

                        <header class="radar-servlet-header">
                            <div>
                                <h1 class="radar-title">RADAR</h1>
                                <div class="radar-subtitle">
                                    Risk Analysis and Detection of Anonymous Response
                                </div>
                            </div>
                        </header>

                        <main class="radar-servlet-content">

                            <section class="radar-servlet-panel">

                                <div class="radar-welcome">
                                    <h2>Administration Command Center</h2>
                                    <p>Configure the fraud detection engine.</p>
                                    <p>
                                        Manage detection thresholds,
                                        algorithm parameters and system auditing.
                                    </p>
                                </div>


                                <!-- DETECTION CONFIGURATION -->

                                <div class="radar-report-section">

                                    <h2 class="radar-page-title">Detection Configuration</h2>

                                    <div class="radar-report-card">

                                        <form class="radar-form" action="update-config" method="post">

                                            <div class="radar-config-row">
                                                <label for="amountThreshold">Amount Threshold</label>
                                                <input id="amountThreshold" type="number"
                                                       name="amountThreshold" step="0.01" min="0"
                                                       value="%s" required>
                                                <small>
                                                    Transactions above this amount receive
                                                    a high amount-risk score.
                                                </small>
                                            </div>

                                            <div class="radar-config-row">
                                                <label for="velocityLimit">Velocity Limit</label>
                                                <input id="velocityLimit" type="number"
                                                       name="velocityLimit" min="1"
                                                       value="%s" required>
                                                <small>
                                                    Maximum number of transactions allowed
                                                    within the velocity window.
                                                </small>
                                            </div>

                                            <div class="radar-config-row">
                                                <label for="velocityWindow">Velocity Window (minutes)</label>
                                                <input id="velocityWindow" type="number"
                                                       name="velocityWindow" min="1"
                                                       value="%s" required>
                                                <small>
                                                    Time period used for transaction velocity analysis.
                                                </small>
                                            </div>

                                            <div class="radar-config-row">
                                                <label for="zscoreThreshold">Z-Score Threshold</label>
                                                <input id="zscoreThreshold" type="number"
                                                       name="zscoreThreshold" step="0.01" min="0"
                                                       value="%s" required>
                                                <small>
                                                    Statistical anomaly threshold used by the Z-Score rule.
                                                </small>
                                            </div>

                                            <button class="radar-servlet-button" type="submit">
                                                Update Configuration
                                            </button>

                                        </form>

                                    </div>

                                </div>


                                <!-- SYSTEM ADMINISTRATION: 5 CARDS -->

                                <div class="radar-report-section">

                                    <h2 class="radar-page-title">System Administration</h2>

                                    <div class="radar-cards"
                                         style="grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));">

                                        <div class="radar-card">
                                            <h2>Algorithm Parameters</h2>
                                            <p>
                                                View and modify the adaptive
                                                fraud detection rule weights.
                                            </p>
                                            <a class="radar-button" href="algorithm-params">
                                                Manage Parameters
                                            </a>
                                        </div>

                                        <div class="radar-card">
                                            <h2>Audit Log</h2>
                                            <p>
                                                Monitor administrative actions,
                                                configuration changes and system activity.
                                            </p>
                                            <a class="radar-button" href="audit-log">
                                                View Audit Log
                                            </a>
                                        </div>

                                        <div class="radar-card">
                                            <h2>Fraud Alerts</h2>
                                            <p>
                                                Review detected threats and
                                                provide fraud feedback.
                                            </p>
                                            <a class="radar-button" href="alerts">
                                                Review Alerts
                                            </a>
                                        </div>

                                        <div class="radar-card">
                                            <h2>Risk Reports</h2>
                                            <p>
                                                Analyze fraud statistics, risk scores
                                                and detection performance.
                                            </p>
                                            <a class="radar-button" href="reports">
                                                View Reports
                                            </a>
                                        </div>

                                        <div class="radar-card">
                                            <h2>Users &amp; Logins</h2>
                                            <p>
                                                View registered users, login activity
                                                and account details.
                                            </p>
                                            <a class="radar-button" href="admin-users">
                                                View Users
                                            </a>
                                        </div>

                                    </div>

                                </div>


                                <!-- NAVIGATION -->

                                <div class="radar-navigation">
                                    <a class="radar-servlet-button" href="dashboard.html">Dashboard</a>
                                    <a class="radar-servlet-button" href="transaction-history">Transaction History</a>
                                    <a class="radar-servlet-button" href="alerts">Fraud Alerts</a>
                                    <a class="radar-servlet-button" href="reports">Reports</a>
                                </div>

                            </section>

                        </main>

                        <footer class="radar-footer">
                            RADAR &nbsp; • &nbsp;
                            RISK ANALYSIS AND DETECTION OF ANONYMOUS RESPONSE
                        </footer>

                    </body>
                    </html>
                    """.formatted(
                            String.format(Locale.US, "%.2f", amountThreshold),
                            velocityLimit,
                            velocityWindow,
                            String.format(Locale.US, "%.2f", zscoreThreshold)
                    );

            response.getWriter().println(page);

        } catch (Exception e) {

            e.printStackTrace();

            response.setContentType("text/html;charset=UTF-8");

            response.getWriter().println("""
                    <!DOCTYPE html>
                    <html lang="en">
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <title>RADAR - Administration Error</title>
                        <link rel="icon" type="image/svg+xml" href="favicon.svg">
                        <link rel="stylesheet" href="style.css">
                    </head>
                    <body class="radar-servlet-page">
                        <div class="radar-glow"></div>
                        <main class="radar-servlet-content">
                            <section class="radar-servlet-panel">
                                <h1 class="radar-page-title">Administration Error</h1>
                                <div class="radar-message">
                                    Unable to load administration configuration.
                                    Please try again later.
                                </div>
                                <div class="radar-navigation">
                                    <a class="radar-servlet-button" href="dashboard.html">Back to Dashboard</a>
                                </div>
                            </section>
                        </main>
                    </body>
                    </html>
                    """);
        }
    }
}
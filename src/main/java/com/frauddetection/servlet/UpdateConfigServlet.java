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

@WebServlet("/update-config")
public class UpdateConfigServlet extends HttpServlet {

    @Override
    protected void doPost(
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

        if (!"ADMIN".equalsIgnoreCase(role)) {

            response.setContentType(
                    "text/html;charset=UTF-8");

            response.getWriter().println("""
                    <!DOCTYPE html>
                    <html lang="en">

                    <head>

                        <meta charset="UTF-8">

                        <meta name="viewport"
                              content="width=device-width, initial-scale=1.0">

                        <title>
                            RADAR - Access Denied
                        </title>

                        <link rel="stylesheet"
                              href="style.css">

                    </head>

                    <body class="radar-servlet-page">

                        <div class="radar-glow"></div>

                        <main class="radar-servlet-content">

                            <section class="radar-servlet-panel">

                                <div class="radar-welcome">

                                    <h2>
                                        Access Denied
                                    </h2>

                                    <p>
                                        Only administrators can update
                                        system configuration.
                                    </p>

                                </div>

                                <div class="radar-navigation">

                                    <a
                                        class="radar-servlet-button"
                                        href="dashboard.html">

                                        Back to Dashboard

                                    </a>

                                </div>

                            </section>

                        </main>

                    </body>

                    </html>
                    """);

            return;
        }

        int adminId =
                (Integer) session.getAttribute("userId");

        try {

            String amountText =
                    request.getParameter("amountThreshold");

            String velocityLimitText =
                    request.getParameter("velocityLimit");

            String velocityWindowText =
                    request.getParameter("velocityWindow");

            String zscoreText =
                    request.getParameter("zscoreThreshold");

            double amountThreshold =
                    Double.parseDouble(amountText);

            int velocityLimit =
                    Integer.parseInt(velocityLimitText);

            int velocityWindow =
                    Integer.parseInt(velocityWindowText);

            double zscoreThreshold =
                    Double.parseDouble(zscoreText);

            // Basic validation
            if (amountThreshold < 0 ||
                    velocityLimit < 1 ||
                    velocityWindow < 1 ||
                    zscoreThreshold < 0) {

                showError(
                        response,
                        "Invalid Configuration",
                        "Configuration values must contain valid positive values.",
                        "admin"
                );

                return;
            }

            String sql = """
                    INSERT INTO detection_config
                    (
                        amount_threshold,
                        velocity_limit,
                        velocity_window_minutes,
                        zscore_threshold,
                        updated_by
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """;

            try (Connection connection =
                         DBConnection.getConnection();
                 PreparedStatement statement =
                         connection.prepareStatement(sql)) {

                statement.setDouble(
                        1, amountThreshold);

                statement.setInt(
                        2, velocityLimit);

                statement.setInt(
                        3, velocityWindow);

                statement.setDouble(
                        4, zscoreThreshold);

                statement.setInt(
                        5, adminId);

                statement.executeUpdate();
            }

            // Record configuration change
            String auditSql = """
                    INSERT INTO audit_log
                    (user_id, action)
                    VALUES (?, ?)
                    """;

            try (Connection connection =
                         DBConnection.getConnection();
                 PreparedStatement statement =
                         connection.prepareStatement(auditSql)) {

                String action =
                        "Updated fraud detection configuration: "
                        + "amount threshold="
                        + amountThreshold
                        + ", velocity limit="
                        + velocityLimit
                        + ", velocity window="
                        + velocityWindow
                        + " minutes, z-score threshold="
                        + zscoreThreshold;

                statement.setInt(1, adminId);
                statement.setString(2, action);

                statement.executeUpdate();
            }

            response.setContentType(
                    "text/html;charset=UTF-8");

            response.getWriter().println("""
                    <!DOCTYPE html>
                    <html lang="en">

                    <head>

                        <meta charset="UTF-8">

                        <meta name="viewport"
                              content="width=device-width, initial-scale=1.0">

                        <title>
                            RADAR - Configuration Updated
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
                                        Configuration Updated
                                    </h2>

                                    <p>
                                        Fraud detection configuration
                                        was updated successfully.
                                    </p>

                                </div>


                                <div class="radar-message">

                                    Detection engine configuration
                                    has been saved successfully.

                                </div>


                                <div class="radar-report-section">

                                    <h2 class="radar-page-title">
                                        Updated Parameters
                                    </h2>

                                    <div class="radar-report-grid">

                                        <div class="radar-report-card">

                                            <div class="radar-report-value">
                    """);

            response.getWriter().println(
                    String.format(
                            "₹%.2f",
                            amountThreshold
                    )
            );

            response.getWriter().println("""
                                            </div>

                                            <div class="radar-rule-label">
                                                Amount Threshold
                                            </div>

                                        </div>


                                        <div class="radar-report-card">

                                            <div class="radar-report-value">
                    """);

            response.getWriter().println(
                    velocityLimit
            );

            response.getWriter().println("""
                                            </div>

                                            <div class="radar-rule-label">
                                                Velocity Limit
                                            </div>

                                        </div>


                                        <div class="radar-report-card">

                                            <div class="radar-report-value">
                    """);

            response.getWriter().println(
                    velocityWindow
            );

            response.getWriter().println("""
                                            </div>

                                            <div class="radar-rule-label">
                                                Velocity Window (Minutes)
                                            </div>

                                        </div>


                                        <div class="radar-report-card">

                                            <div class="radar-report-value">
                    """);

            response.getWriter().println(
                    String.format(
                            "%.2f",
                            zscoreThreshold
                    )
            );

            response.getWriter().println("""
                                            </div>

                                            <div class="radar-rule-label">
                                                Z-Score Threshold
                                            </div>

                                        </div>

                                    </div>

                                </div>


                                <div class="radar-navigation">

                                    <a
                                        class="radar-servlet-button"
                                        href="admin">

                                        Administration

                                    </a>

                                    <a
                                        class="radar-servlet-button"
                                        href="algorithm-params">

                                        Algorithm Parameters

                                    </a>

                                    <a
                                        class="radar-servlet-button"
                                        href="alerts">

                                        Fraud Alerts

                                    </a>

                                    <a
                                        class="radar-servlet-button"
                                        href="reports">

                                        Reports

                                    </a>

                                    <a
                                        class="radar-servlet-button"
                                        href="dashboard.html">

                                        Dashboard

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

        } catch (NumberFormatException e) {

            showError(
                    response,
                    "Invalid Configuration Values",
                    "Please enter valid numeric values.",
                    "admin"
            );

        } catch (Exception e) {

            e.printStackTrace();

            showError(
                    response,
                    "Configuration Update Error",
                    "Unable to update the fraud detection configuration. Please try again later.",
                    "admin"
            );
        }
    }

    private void showError(
            HttpServletResponse response,
            String title,
            String message,
            String backLink)
            throws IOException {

        response.setContentType(
                "text/html;charset=UTF-8");

        String safeTitle =
                escapeHtml(title);

        String safeMessage =
                escapeHtml(message);

        response.getWriter().println("""
                <!DOCTYPE html>
                <html lang="en">

                <head>

                    <meta charset="UTF-8">

                    <meta name="viewport"
                          content="width=device-width, initial-scale=1.0">

                    <title>
                """ + safeTitle + """
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
                """ + safeTitle + """
                                </h2>

                            </div>


                            <div class="radar-message">
                """ + safeMessage + """
                            </div>


                            <div class="radar-navigation">

                                <a
                                    class="radar-servlet-button"
                                    href="
                """ + backLink + """
                                    ">

                                    Back to Administration

                                </a>

                                <a
                                    class="radar-servlet-button"
                                    href="dashboard.html">

                                    Dashboard

                                </a>

                            </div>

                        </section>

                    </main>

                </body>

                </html>
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
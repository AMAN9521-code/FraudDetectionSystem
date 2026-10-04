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

@WebServlet("/update-algorithm-params")
public class UpdateAlgorithmParamsServlet extends HttpServlet {

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
                                        algorithm parameters.
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

            double amountWeight =
                    Double.parseDouble(
                            request.getParameter("amountWeight"));

            double velocityWeight =
                    Double.parseDouble(
                            request.getParameter("velocityWeight"));

            double locationWeight =
                    Double.parseDouble(
                            request.getParameter("locationWeight"));

            double zscoreWeight =
                    Double.parseDouble(
                            request.getParameter("zscoreWeight"));

            // Validate individual values
            if (amountWeight < 0 || amountWeight > 1 ||
                    velocityWeight < 0 || velocityWeight > 1 ||
                    locationWeight < 0 || locationWeight > 1 ||
                    zscoreWeight < 0 || zscoreWeight > 1) {

                showError(
                        response,
                        "Invalid Algorithm Weights",
                        "Each parameter must be between 0 and 1."
                );

                return;
            }

            // The four weights must add up to 1.00
            double total =
                    amountWeight
                    + velocityWeight
                    + locationWeight
                    + zscoreWeight;

            if (Math.abs(total - 1.0) > 0.0001) {

                showError(
                        response,
                        "Invalid Weight Distribution",
                        "The four algorithm weights must add up to 1.00."
                );

                return;
            }

            updateParameter(
                    "AMOUNT_RULE_WEIGHT",
                    amountWeight
            );

            updateParameter(
                    "VELOCITY_RULE_WEIGHT",
                    velocityWeight
            );

            updateParameter(
                    "LOCATION_RULE_WEIGHT",
                    locationWeight
            );

            updateParameter(
                    "ZSCORE_RULE_WEIGHT",
                    zscoreWeight
            );

            // Audit log
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
                        "Updated algorithm parameters: "
                        + "amount weight="
                        + amountWeight
                        + ", velocity weight="
                        + velocityWeight
                        + ", location weight="
                        + locationWeight
                        + ", z-score weight="
                        + zscoreWeight;

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
                            RADAR - Parameters Updated
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
                                        Algorithm Parameters Updated
                                    </h2>

                                    <p>
                                        Fraud detection algorithm parameters
                                        were updated successfully.
                                    </p>

                                </div>


                                <div class="radar-message">

                                    The new configuration has been
                                    recorded in the audit log.

                                </div>


                                <div class="radar-report-section">

                                    <h2 class="radar-page-title">
                                        New Rule Distribution
                                    </h2>

                                    <div class="radar-report-grid">

                                        <div class="radar-report-card">

                                            <div class="radar-report-value">
                    """);

            response.getWriter().println(
                    String.format(
                            "%.2f%%",
                            amountWeight * 100
                    )
            );

            response.getWriter().println("""
                                            </div>

                                            <div class="radar-rule-label">
                                                Amount Rule
                                            </div>

                                        </div>


                                        <div class="radar-report-card">

                                            <div class="radar-report-value">
                    """);

            response.getWriter().println(
                    String.format(
                            "%.2f%%",
                            velocityWeight * 100
                    )
            );

            response.getWriter().println("""
                                            </div>

                                            <div class="radar-rule-label">
                                                Velocity Rule
                                            </div>

                                        </div>


                                        <div class="radar-report-card">

                                            <div class="radar-report-value">
                    """);

            response.getWriter().println(
                    String.format(
                            "%.2f%%",
                            locationWeight * 100
                    )
            );

            response.getWriter().println("""
                                            </div>

                                            <div class="radar-rule-label">
                                                Location Rule
                                            </div>

                                        </div>


                                        <div class="radar-report-card">

                                            <div class="radar-report-value">
                    """);

            response.getWriter().println(
                    String.format(
                            "%.2f%%",
                            zscoreWeight * 100
                    )
            );

            response.getWriter().println("""
                                            </div>

                                            <div class="radar-rule-label">
                                                Z-Score Rule
                                            </div>

                                        </div>

                                    </div>

                                </div>


                                <div class="radar-message">

                                    Total Weight:
                """);

            response.getWriter().println(
                    String.format(
                            "%.2f",
                            total
                    )
            );

            response.getWriter().println("""
                                    &nbsp; • &nbsp;
                                    Normalized Configuration

                                </div>


                                <div class="radar-navigation">

                                    <a
                                        class="radar-servlet-button"
                                        href="algorithm-params">

                                        View Algorithm Parameters

                                    </a>

                                    <a
                                        class="radar-servlet-button"
                                        href="admin">

                                        Administration

                                    </a>

                                    <a
                                        class="radar-servlet-button"
                                        href="audit-log">

                                        Audit Log

                                    </a>

                                    <a
                                        class="radar-servlet-button"
                                        href="alerts">

                                        Fraud Alerts

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
                    "Invalid Parameter Values",
                    "Please enter valid numeric values."
            );

        } catch (Exception e) {

            e.printStackTrace();

            showError(
                    response,
                    "Algorithm Update Error",
                    "Unable to update algorithm parameters. Please try again later."
            );
        }
    }

    private void updateParameter(
            String parameterName,
            double parameterValue)
            throws Exception {

        String sql = """
                UPDATE algorithm_params
                SET param_value = ?
                WHERE param_name = ?
                """;

        try (Connection connection =
                     DBConnection.getConnection();
             PreparedStatement statement =
                     connection.prepareStatement(sql)) {

            statement.setString(
                    1,
                    String.valueOf(parameterValue)
            );

            statement.setString(
                    2,
                    parameterName
            );

            statement.executeUpdate();
        }
    }

    private void showError(
            HttpServletResponse response,
            String title,
            String message)
            throws IOException {

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
                """ + escapeHtml(title) + """
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
                """ + escapeHtml(title) + """
                                </h2>

                            </div>


                            <div class="radar-message">
                """ + escapeHtml(message) + """
                            </div>


                            <div class="radar-navigation">

                                <a
                                    class="radar-servlet-button"
                                    href="algorithm-params">

                                    Back to Algorithm Parameters

                                </a>

                                <a
                                    class="radar-servlet-button"
                                    href="admin">

                                    Administration

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
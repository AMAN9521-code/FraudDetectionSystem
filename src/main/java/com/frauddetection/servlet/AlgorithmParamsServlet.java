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

@WebServlet("/algorithm-params")
public class AlgorithmParamsServlet extends HttpServlet {

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
                                        Only administrators can access
                                        algorithm parameters.
                                    </p>

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

            return;
        }

        String amountWeight = "0.30";
        String velocityWeight = "0.25";
        String locationWeight = "0.20";
        String zscoreWeight = "0.25";

        try (Connection connection =
                     DBConnection.getConnection()) {

            String sql = """
                    SELECT param_name, param_value
                    FROM algorithm_params
                    WHERE param_name IN (
                        'AMOUNT_RULE_WEIGHT',
                        'VELOCITY_RULE_WEIGHT',
                        'LOCATION_RULE_WEIGHT',
                        'ZSCORE_RULE_WEIGHT'
                    )
                    """;

            try (PreparedStatement statement =
                         connection.prepareStatement(sql);
                 ResultSet rs =
                         statement.executeQuery()) {

                while (rs.next()) {

                    String name =
                            rs.getString("param_name");

                    String value =
                            rs.getString("param_value");

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

            response.setContentType(
                    "text/html;charset=UTF-8");

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
                            RADAR - Algorithm Parameters
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
                                        Algorithm Parameters
                                    </h2>

                                    <p>
                                        Fraud Detection Engine Configuration
                                    </p>

                                    <p>
                                        Configure the weighting applied to
                                        each fraud detection rule.
                                    </p>

                                </div>


                                <div class="radar-report-section">

                                    <h2 class="radar-page-title">
                                        Rule Weight Configuration
                                    </h2>

                                    <div class="radar-report-card">

                                        <form
                                            class="radar-form"
                                            action="update-algorithm-params"
                                            method="post">


                                            <div class="radar-config-row">

                                                <label for="amountWeight">
                                                    Amount Rule Weight
                                                </label>

                                                <input
                                                    id="amountWeight"
                                                    type="number"
                                                    name="amountWeight"
                                                    step="0.01"
                                                    min="0"
                                                    max="1"
                    """);

            html.append("value=\"");
            html.append(escapeHtml(amountWeight));
            html.append("""
                                                    "
                                                    required>

                                                <small>
                                                    Controls the influence of
                                                    transaction amount anomalies.
                                                    Allowed range: 0.00 - 1.00.
                                                </small>

                                            </div>


                                            <div class="radar-config-row">

                                                <label for="velocityWeight">
                                                    Velocity Rule Weight
                                                </label>

                                                <input
                                                    id="velocityWeight"
                                                    type="number"
                                                    name="velocityWeight"
                                                    step="0.01"
                                                    min="0"
                                                    max="1"
                    """);

            html.append("value=\"");
            html.append(escapeHtml(velocityWeight));
            html.append("""
                                                    "
                                                    required>

                                                <small>
                                                    Controls the influence of
                                                    rapid transaction activity.
                                                    Allowed range: 0.00 - 1.00.
                                                </small>

                                            </div>


                                            <div class="radar-config-row">

                                                <label for="locationWeight">
                                                    Location Rule Weight
                                                </label>

                                                <input
                                                    id="locationWeight"
                                                    type="number"
                                                    name="locationWeight"
                                                    step="0.01"
                                                    min="0"
                                                    max="1"
                    """);

            html.append("value=\"");
            html.append(escapeHtml(locationWeight));
            html.append("""
                                                    "
                                                    required>

                                                <small>
                                                    Controls the influence of
                                                    unusual transaction locations.
                                                    Allowed range: 0.00 - 1.00.
                                                </small>

                                            </div>


                                            <div class="radar-config-row">

                                                <label for="zscoreWeight">
                                                    Z-Score Rule Weight
                                                </label>

                                                <input
                                                    id="zscoreWeight"
                                                    type="number"
                                                    name="zscoreWeight"
                                                    step="0.01"
                                                    min="0"
                                                    max="1"
                    """);

            html.append("value=\"");
            html.append(escapeHtml(zscoreWeight));
            html.append("""
                                                    "
                                                    required>

                                                <small>
                                                    Controls the influence of
                                                    statistical anomaly detection.
                                                    Allowed range: 0.00 - 1.00.
                                                </small>

                                            </div>


                                            <button
                                                class="radar-servlet-button"
                                                type="submit">

                                                Update Algorithm Parameters

                                            </button>

                                        </form>

                                    </div>

                                </div>


                                <div class="radar-report-section">

                                    <h2 class="radar-page-title">
                                        Current Rule Distribution
                                    </h2>

                                    <div class="radar-report-card">
                    """);

            appendRuleBar(
                    html,
                    "Amount Rule",
                    parseWeight(amountWeight)
            );

            appendRuleBar(
                    html,
                    "Velocity Rule",
                    parseWeight(velocityWeight)
            );

            appendRuleBar(
                    html,
                    "Location Rule",
                    parseWeight(locationWeight)
            );

            appendRuleBar(
                    html,
                    "Z-Score Rule",
                    parseWeight(zscoreWeight)
            );

            html.append("""
                                    </div>

                                </div>


                                <div class="radar-report-section">

                                    <h2 class="radar-page-title">
                                        Adaptive Detection
                                    </h2>

                                    <div class="radar-report-card">

                                        <p class="radar-admin-description">
                                            These weights influence the final
                                            fraud risk score produced by the
                                            detection engine.
                                        </p>

                                        <p class="radar-admin-description">
                                            Administrator feedback from fraud
                                            alert reviews can adapt these
                                            rule weights over time.
                                        </p>

                                        <p class="radar-admin-description">
                                            The four rule weights are normalized
                                            so their combined contribution
                                            remains balanced.
                                        </p>

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

            response.getWriter().println(
                    html.toString()
            );

        } catch (Exception e) {

            e.printStackTrace();

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
                            RADAR - Algorithm Error
                        </title>

                        <link rel="stylesheet"
                              href="style.css">

                    </head>

                    <body class="radar-servlet-page">

                        <div class="radar-glow"></div>

                        <main class="radar-servlet-content">

                            <section class="radar-servlet-panel">

                                <h1 class="radar-page-title">
                                    Algorithm Parameters Error
                                </h1>

                                <div class="radar-message">
                                    Unable to load algorithm parameters.
                                    Please try again later.
                                </div>

                                <div class="radar-navigation">

                                    <a
                                        class="radar-servlet-button"
                                        href="admin">

                                        Back to Administration

                                    </a>

                                </div>

                            </section>

                        </main>

                    </body>

                    </html>
                    """);
        }
    }

    private double parseWeight(String value) {

        try {

            double weight =
                    Double.parseDouble(value);

            return Math.max(
                    0.0,
                    Math.min(
                            1.0,
                            weight
                    )
            ) * 100.0;

        } catch (Exception e) {

            return 0.0;
        }
    }

    private void appendRuleBar(
            StringBuilder html,
            String name,
            double score) {

        score =
                Math.max(
                        0.0,
                        Math.min(100.0, score)
                );

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
                String.format(
                        "%.2f%%",
                        score
                )
        );

        html.append("""
                        </strong>

                    </div>

                    <div class="radar-progress">

                        <div class="radar-progress-fill"
                             style="width:
                """);

        html.append(
                String.format(
                        "%.2f",
                        score
                )
        );

        html.append("""
                        %;">
                        </div>

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
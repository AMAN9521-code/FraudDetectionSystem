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

@WebServlet("/audit-log")
public class AuditLogServlet extends HttpServlet {

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
                                        Only administrators can view
                                        the audit log.
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
                        RADAR - Audit Log
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
                                    Audit Log
                                </h2>

                                <p>
                                    Administrative Activity Monitor
                                </p>

                                <p>
                                    Administrative actions performed
                                    within the fraud detection system.
                                </p>

                            </div>


                            <div class="radar-report-section">

                                <h2 class="radar-page-title">
                                    System Activity
                                </h2>

                                <div class="radar-servlet-table-wrapper">

                                    <table class="radar-servlet-table">

                                        <thead>

                                            <tr>

                                                <th>
                                                    Log ID
                                                </th>

                                                <th>
                                                    User ID
                                                </th>

                                                <th>
                                                    User Name
                                                </th>

                                                <th>
                                                    Action
                                                </th>

                                                <th>
                                                    Date &amp; Time
                                                </th>

                                            </tr>

                                        </thead>

                                        <tbody>
                """);

        String sql = """
                SELECT
                    a.log_id,
                    a.user_id,
                    u.name,
                    a.action,
                    a.log_timestamp
                FROM audit_log a
                LEFT JOIN users u
                    ON a.user_id = u.user_id
                ORDER BY a.log_timestamp DESC
                """;

        try (Connection connection =
                     DBConnection.getConnection();
             PreparedStatement statement =
                     connection.prepareStatement(sql);
             ResultSet resultSet =
                     statement.executeQuery()) {

            boolean found = false;

            while (resultSet.next()) {

                found = true;

                int logId =
                        resultSet.getInt("log_id");

                int userId =
                        resultSet.getInt("user_id");

                String userName =
                        resultSet.getString("name");

                String action =
                        resultSet.getString("action");

                String timestamp =
                        resultSet.getString("log_timestamp");

                html.append("""
                        <tr>

                            <td>
                        """);

                html.append(logId);

                html.append("""
                            </td>

                            <td>
                        """);

                html.append(userId);

                html.append("""
                            </td>

                            <td>
                        """);

                html.append(
                        escapeHtml(userName)
                );

                html.append("""
                            </td>

                            <td>
                                <span class="radar-audit-action">
                        """);

                html.append(
                        escapeHtml(action)
                );

                html.append("""
                                </span>
                            </td>

                            <td>
                        """);

                html.append(
                        escapeHtml(timestamp)
                );

                html.append("""
                            </td>

                        </tr>
                        """);
            }

            if (!found) {

                html.append("""
                        <tr>

                            <td colspan="5"
                                class="radar-empty-state">

                                No audit log entries found.

                            </td>

                        </tr>
                        """);
            }

        } catch (Exception e) {

            e.printStackTrace();

            html.append("""
                    <tr>

                        <td colspan="5"
                            class="radar-empty-state">

                            Unable to load audit log.
                            Please try again later.

                        </td>

                    </tr>
                    """);
        }

        html.append("""
                                    </tbody>

                                </table>

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
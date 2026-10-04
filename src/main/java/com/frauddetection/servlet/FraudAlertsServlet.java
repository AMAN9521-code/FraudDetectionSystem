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

@WebServlet("/alerts")
public class FraudAlertsServlet extends HttpServlet {

    @Override
    protected void doGet(
            HttpServletRequest request,
            HttpServletResponse response)
            throws ServletException, IOException {

        HttpSession session =
                request.getSession(false);

        if (session == null ||
                session.getAttribute("userId") == null) {

            response.sendRedirect("login.html");
            return;
        }

        int userId =
                (Integer) session.getAttribute("userId");

        String role =
                (String) session.getAttribute("userRole");

        response.setContentType(
                "text/html;charset=UTF-8");

        PrintWriter out =
                response.getWriter();


        /* =====================================================
           RADAR PAGE HEADER
           ===================================================== */

        out.println("""
                <!DOCTYPE html>
                <html lang="en">

                <head>

                    <meta charset="UTF-8">

                    <meta name="viewport"
                          content="width=device-width, initial-scale=1.0">

                    <title>
                        RADAR - Fraud Alerts
                    </title>

                    <link rel="stylesheet"
                          href="style.css">

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


                        <h2 class="radar-page-title">
                            Fraud Alerts
                        </h2>


                        <p style="
                            text-align:center;
                            color:#9f866e;
                            margin-bottom:25px;
                        ">
                            Transactions requiring fraud review
                        </p>


                        <div class="radar-navigation">

                            <a href="dashboard.html">
                                Dashboard
                            </a>

                            <a href="transaction.html">
                                New Transaction
                            </a>

                            <a href="transaction-history">
                                Transaction History
                            </a>

                            <a href="reports">
                                Reports
                            </a>

                        </div>


                        <div class="radar-servlet-table-wrapper">

                        <table class="radar-servlet-table">

                            <thead>

                                <tr>

                                    <th>
                                        Alert ID
                                    </th>

                                    <th>
                                        Transaction ID
                                    </th>

                                    <th>
                                        Amount
                                    </th>

                                    <th>
                                        Merchant
                                    </th>

                                    <th>
                                        Location
                                    </th>

                                    <th>
                                        Risk Score
                                    </th>

                                    <th>
                                        Reason
                                    </th>

                                    <th>
                                        Status
                                    </th>

                                    <th>
                                        Reviewed
                                    </th>

                                    <th>
                                        Review Action
                                    </th>

                                </tr>

                            </thead>

                            <tbody>
                """);


        /* =====================================================
           DATABASE QUERY
           ===================================================== */

        String sql = """
                SELECT
                    fa.alert_id,
                    fa.transaction_id,
                    t.amount,
                    t.merchant,
                    t.location,
                    fa.risk_score,
                    fa.reason,
                    fa.review_status,
                    fa.reviewed_at
                FROM fraud_alerts fa
                INNER JOIN transactions t
                    ON fa.transaction_id = t.transaction_id
                WHERE t.user_id = ?
                ORDER BY fa.alert_id DESC
                """;


        if ("ADMIN".equalsIgnoreCase(role)) {

            sql = """
                    SELECT
                        fa.alert_id,
                        fa.transaction_id,
                        t.amount,
                        t.merchant,
                        t.location,
                        fa.risk_score,
                        fa.reason,
                        fa.review_status,
                        fa.reviewed_at
                    FROM fraud_alerts fa
                    INNER JOIN transactions t
                        ON fa.transaction_id = t.transaction_id
                    ORDER BY fa.alert_id DESC
                    """;
        }


        try (
                Connection connection =
                        DBConnection.getConnection();

                PreparedStatement statement =
                        connection.prepareStatement(sql)
        ) {

            if (!"ADMIN".equalsIgnoreCase(role)) {

                statement.setInt(1, userId);
            }


            try (
                    ResultSet resultSet =
                            statement.executeQuery()
            ) {

                boolean found = false;


                while (resultSet.next()) {

                    found = true;


                    int alertId =
                            resultSet.getInt(
                                    "alert_id");

                    int transactionId =
                            resultSet.getInt(
                                    "transaction_id");

                    double amount =
                            resultSet.getDouble(
                                    "amount");

                    String merchant =
                            escapeHtml(
                                    resultSet.getString(
                                            "merchant"));

                    String location =
                            escapeHtml(
                                    resultSet.getString(
                                            "location"));

                    double riskScore =
                            resultSet.getDouble(
                                    "risk_score");

                    String reason =
                            escapeHtml(
                                    resultSet.getString(
                                            "reason"));

                    String reviewStatus =
                            resultSet.getString(
                                    "review_status");

                    String reviewedAt =
                            resultSet.getString(
                                    "reviewed_at");


                    if (reviewedAt == null) {

                        reviewedAt = "-";
                    }


                    String statusClass =
                            getStatusClass(
                                    reviewStatus);


                    out.println("<tr>");


                    /* ALERT ID */

                    out.println(
                            "<td>"
                                    + alertId
                                    + "</td>"
                    );


                    /* TRANSACTION ID */

                    out.println(
                            "<td>"
                                    + transactionId
                                    + "</td>"
                    );


                    /* AMOUNT */

                    out.println(
                            "<td>"
                                    + String.format(
                                            "₹%.2f",
                                            amount)
                                    + "</td>"
                    );


                    /* MERCHANT */

                    out.println(
                            "<td>"
                                    + merchant
                                    + "</td>"
                    );


                    /* LOCATION */

                    out.println(
                            "<td>"
                                    + location
                                    + "</td>"
                    );


                    /* RISK SCORE */

                    out.println(
                            "<td>"
                                    + "<span class=\"radar-risk-score\">"
                                    + String.format(
                                            "%.2f%%",
                                            riskScore)
                                    + "</span>"
                                    + "</td>"
                    );


                    /* REASON */

                    out.println(
                            "<td style=\"min-width:260px;\">"
                                    + reason
                                    + "</td>"
                    );


                    /* STATUS */

                    out.println(
                            "<td>"
                                    + "<span class=\""
                                    + statusClass
                                    + "\">"
                                    + escapeHtml(
                                            reviewStatus)
                                    + "</span>"
                                    + "</td>"
                    );


                    /* REVIEWED DATE */

                    out.println(
                            "<td>"
                                    + escapeHtml(
                                            reviewedAt)
                                    + "</td>"
                    );


                    /* =================================================
                       ADMIN REVIEW ACTIONS
                       ================================================= */

                    if ("ADMIN".equalsIgnoreCase(role)
                            && "OPEN".equalsIgnoreCase(
                                    reviewStatus)) {


                        out.println("""
                                <td>

                                    <form
                                        action="review-alert"
                                        method="post"
                                        style="margin-bottom:8px;">

                                        <input
                                            type="hidden"
                                            name="alertId"
                                """);


                        out.println(
                                "value=\""
                                        + alertId
                                        + "\">"
                        );


                        out.println("""
                                        <input
                                            type="hidden"
                                            name="decision"
                                            value="CONFIRMED_FRAUD">

                                        <button
                                            class="radar-servlet-button"
                                            type="submit">

                                            Confirm Fraud

                                        </button>

                                    </form>
                                """);


                        out.println("""
                                    <form
                                        action="review-alert"
                                        method="post">

                                        <input
                                            type="hidden"
                                            name="alertId"
                                """);


                        out.println(
                                "value=\""
                                        + alertId
                                        + "\">"
                        );


                        out.println("""
                                        <input
                                            type="hidden"
                                            name="decision"
                                            value="FALSE_POSITIVE">

                                        <button
                                            class="radar-servlet-button radar-danger-button"
                                            type="submit">

                                            False Positive

                                        </button>

                                    </form>

                                </td>
                                """);

                    } else {

                        out.println(
                                "<td>"
                                        + "<span style=\"color:#665546;\">"
                                        + "—"
                                        + "</span>"
                                        + "</td>"
                        );
                    }


                    out.println("</tr>");
                }


                /* =====================================================
                   EMPTY RESULT
                   ===================================================== */

                if (!found) {

                    out.println("""
                            <tr>

                                <td colspan="10">

                                    <div class="radar-message">

                                        No fraud alerts found.

                                    </div>

                                </td>

                            </tr>
                            """);
                }
            }


        } catch (Exception e) {

            e.printStackTrace();


            out.println("""
                    <tr>

                        <td colspan="10">

                            <div class="radar-message">

                                Unable to load fraud alerts.
                                Please try again later.

                            </div>

                        </td>

                    </tr>
                    """);
        }


        /* =====================================================
           PAGE FOOTER
           ===================================================== */

        out.println("""
                            </tbody>

                        </table>

                        </div>


                        <div class="radar-navigation">

                            <a href="transaction.html">
                                New Transaction
                            </a>

                            <a href="transaction-history">
                                Transaction History
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
                    THREAT DETECTION
                    &nbsp; • &nbsp;
                    FRAUD INTELLIGENCE

                </footer>


                </body>

                </html>
                """);
    }


    /* =========================================================
       STATUS STYLE
       ========================================================= */

    private String getStatusClass(String status) {

        if (status == null) {
            return "status";
        }

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


    /* =========================================================
       HTML ESCAPING
       ========================================================= */

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
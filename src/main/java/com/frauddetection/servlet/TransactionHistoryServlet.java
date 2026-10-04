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

@WebServlet("/transaction-history")
public class TransactionHistoryServlet extends HttpServlet {

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

        response.setContentType(
                "text/html;charset=UTF-8"
        );

        PrintWriter out =
                response.getWriter();


        /* =====================================================
           PAGE HEADER
           ===================================================== */

        out.println("""
                <!DOCTYPE html>
                <html lang="en">

                <head>

                    <meta charset="UTF-8">

                    <meta name="viewport"
                          content="width=device-width, initial-scale=1.0">

                    <title>
                        RADAR - Transaction History
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
                            Transaction History
                        </h2>


                        <div class="radar-navigation">

                            <a href="dashboard.html">
                                Dashboard
                            </a>

                            <a href="transaction.html">
                                New Transaction
                            </a>

                            <a href="alerts">
                                Fraud Alerts
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
                                        ID
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
                                        Date
                                    </th>

                                    <th>
                                        Status
                                    </th>

                                    <th>
                                        Risk Score
                                    </th>

                                </tr>

                            </thead>

                            <tbody>
                """);


        /* =====================================================
           DATABASE QUERY
           ===================================================== */

        String sql = """
                SELECT transaction_id,
                       amount,
                       merchant,
                       location,
                       txn_timestamp,
                       status,
                       risk_score
                FROM transactions
                WHERE user_id = ?
                ORDER BY txn_timestamp DESC
                """;


        try (
                Connection connection =
                        DBConnection.getConnection();

                PreparedStatement statement =
                        connection.prepareStatement(sql)
        ) {

            statement.setInt(1, userId);


            try (
                    ResultSet resultSet =
                            statement.executeQuery()
            ) {

                boolean found = false;


                while (resultSet.next()) {

                    found = true;


                    out.println("<tr>");


                    /* ID */

                    out.println(
                            "<td>"
                            + resultSet.getInt(
                                    "transaction_id")
                            + "</td>"
                    );


                    /* AMOUNT */

                    out.println(
                            "<td>"
                            + String.format(
                                    "₹%.2f",
                                    resultSet.getDouble(
                                            "amount"))
                            + "</td>"
                    );


                    /* MERCHANT */

                    out.println(
                            "<td>"
                            + escapeHtml(
                                    resultSet.getString(
                                            "merchant"))
                            + "</td>"
                    );


                    /* LOCATION */

                    out.println(
                            "<td>"
                            + escapeHtml(
                                    resultSet.getString(
                                            "location"))
                            + "</td>"
                    );


                    /* DATE */

                    out.println(
                            "<td>"
                            + escapeHtml(
                                    String.valueOf(
                                            resultSet.getTimestamp(
                                                    "txn_timestamp")))
                            + "</td>"
                    );


                    /* STATUS */

                    String status =
                            resultSet.getString("status");

                    String statusClass =
                            "status";


                    if ("FLAGGED".equalsIgnoreCase(status)) {

                        statusClass =
                                "radar-status-fraud";

                    } else if ("APPROVED".equalsIgnoreCase(status)) {

                        statusClass =
                                "radar-status-false";

                    } else if ("PENDING".equalsIgnoreCase(status)) {

                        statusClass =
                                "radar-status-open";
                    }


                    out.println(
                            "<td>"
                            + "<span class=\""
                            + statusClass
                            + "\">"
                            + escapeHtml(status)
                            + "</span>"
                            + "</td>"
                    );


                    /* RISK SCORE */

                    double riskScore =
                            resultSet.getDouble(
                                    "risk_score");


                    out.println(
                            "<td>"
                            + "<span class=\"radar-risk-score\">"
                            + String.format(
                                    "%.2f%%",
                                    riskScore)
                            + "</span>"
                            + "</td>"
                    );


                    out.println("</tr>");
                }


                /* =================================================
                   NO TRANSACTIONS
                   ================================================= */

                if (!found) {

                    out.println("""
                            <tr>

                                <td colspan="7">

                                    <div class="radar-message">

                                        No transactions found.

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

                        <td colspan="7">

                            <div class="radar-message">

                                Unable to load transaction history.
                                Please try again later.

                            </div>

                        </td>

                    </tr>
                    """);
        }


        /* =====================================================
           FOOTER / NAVIGATION
           ===================================================== */

        out.println("""
                            </tbody>

                        </table>

                        </div>


                        <div class="radar-navigation">

                            <a href="transaction.html">
                                Enter New Transaction
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
                    TRANSACTION INTELLIGENCE
                    &nbsp; • &nbsp;
                    RISK ANALYSIS

                </footer>


                </body>

                </html>
                """);
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
package com.frauddetection.servlet;

import com.frauddetection.service.FraudDetectionService;
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

@WebServlet("/transaction")
public class TransactionServlet extends HttpServlet {

    private static final int MAX_MERCHANT_LENGTH = 150;
    private static final int MAX_LOCATION_LENGTH = 150;

    @Override
    protected void doPost(
            HttpServletRequest request,
            HttpServletResponse response)
            throws ServletException, IOException {

        HttpSession session =
                request.getSession(false);

        if (session == null ||
                session.getAttribute("userId") == null) {

            response.sendRedirect(
                    request.getContextPath() + "/login.html"
            );

            return;
        }

        int userId =
                (Integer) session.getAttribute("userId");

        String amountText =
                request.getParameter("amount");

        String merchant =
                request.getParameter("merchant");

        String location =
                request.getParameter("location");

        /*
         * ==========================================
         * INPUT VALIDATION
         * ==========================================
         */

        if (amountText == null ||
                amountText.trim().isEmpty()) {

            showError(
                    response,
                    "Invalid amount",
                    "Amount is required."
            );

            return;
        }

        if (merchant == null ||
                merchant.trim().isEmpty()) {

            showError(
                    response,
                    "Invalid merchant",
                    "Merchant name is required."
            );

            return;
        }

        if (location == null ||
                location.trim().isEmpty()) {

            showError(
                    response,
                    "Invalid location",
                    "Location is required."
            );

            return;
        }

        merchant = merchant.trim();
        location = location.trim();

        /*
         * Prevent values larger than the database columns.
         */

        if (merchant.length() > MAX_MERCHANT_LENGTH) {

            showError(
                    response,
                    "Invalid merchant",
                    "Merchant name is too long."
            );

            return;
        }

        if (location.length() > MAX_LOCATION_LENGTH) {

            showError(
                    response,
                    "Invalid location",
                    "Location is too long."
            );

            return;
        }

        /*
         * ==========================================
         * PARSE AND VALIDATE AMOUNT
         * ==========================================
         */

        double amount;

        try {

            amount =
                    Double.parseDouble(
                            amountText.trim()
                    );

        } catch (NumberFormatException e) {

            showError(
                    response,
                    "Invalid amount",
                    "Please enter a valid numeric amount."
            );

            return;
        }

        /*
         * Reject NaN and Infinity.
         */

        if (!Double.isFinite(amount)) {

            showError(
                    response,
                    "Invalid amount",
                    "Amount must be a valid finite number."
            );

            return;
        }

        /*
         * Amount must be positive.
         */

        if (amount <= 0) {

            showError(
                    response,
                    "Invalid amount",
                    "Amount must be greater than zero."
            );

            return;
        }

        /*
         * Database DECIMAL(12,2) supports values up to
         * 9,999,999,999.99.
         */

        if (amount > 9999999999.99) {

            showError(
                    response,
                    "Invalid amount",
                    "Amount exceeds the maximum allowed value."
            );

            return;
        }

        /*
         * ==========================================
         * CREATE TRANSACTION
         * ==========================================
         */

        try {

            int transactionId;

            String sql = """
                    INSERT INTO transactions
                    (
                        user_id,
                        amount,
                        merchant,
                        location,
                        status,
                        risk_score
                    )
                    VALUES
                    (?, ?, ?, ?, 'PENDING', 0)
                    """;

            try (Connection connection =
                         DBConnection.getConnection();
                 PreparedStatement statement =
                         connection.prepareStatement(
                                 sql,
                                 java.sql.Statement
                                         .RETURN_GENERATED_KEYS)) {

                statement.setInt(1, userId);

                statement.setDouble(
                        2,
                        amount
                );

                statement.setString(
                        3,
                        merchant
                );

                statement.setString(
                        4,
                        location
                );

                statement.executeUpdate();

                try (var keys =
                             statement.getGeneratedKeys()) {

                    if (!keys.next()) {

                        throw new Exception(
                                "Could not create transaction ID."
                        );
                    }

                    transactionId =
                            keys.getInt(1);
                }
            }

            /*
             * ==========================================
             * RUN FRAUD DETECTION
             * ==========================================
             */

            double riskScore =
                    FraudDetectionService
                            .analyzeTransaction(
                                    userId,
                                    amount,
                                    merchant,
                                    location,
                                    transactionId
                            );

            /*
             * ==========================================
             * DETERMINE TRANSACTION STATUS
             * ==========================================
             */

            String status;

            if (riskScore >= 50.0) {

                status = "FLAGGED";

            } else {

                status = "APPROVED";
            }

            /*
             * ==========================================
             * UPDATE TRANSACTION
             * ==========================================
             */

            String updateSql = """
                    UPDATE transactions
                    SET status = ?,
                        risk_score = ?
                    WHERE transaction_id = ?
                    """;

            try (Connection connection =
                         DBConnection.getConnection();
                 PreparedStatement statement =
                         connection.prepareStatement(
                                 updateSql)) {

                statement.setString(
                        1,
                        status
                );

                statement.setDouble(
                        2,
                        riskScore
                );

                statement.setInt(
                        3,
                        transactionId
                );

                statement.executeUpdate();
            }

            /*
             * ==========================================
             * SHOW RESULT
             * ==========================================
             */

            response.setContentType(
                    "text/html;charset=UTF-8"
            );

            response.getWriter().println("""
                    <!DOCTYPE html>

                    <html>

                    <head>

                        <meta charset="UTF-8">

                        <title>
                            Transaction Result
                        </title>

                        <style>

                            body {
                                font-family: Arial, sans-serif;
                                background: #f4f6f8;
                                text-align: center;
                                padding-top: 80px;
                            }

                            .box {
                                background: white;
                                width: 500px;
                                margin: auto;
                                padding: 30px;
                                border-radius: 12px;
                                box-shadow:
                                    0 4px 15px
                                    rgba(0,0,0,0.15);
                            }

                            a {
                                display: inline-block;
                                margin-top: 20px;
                                text-decoration: none;
                            }

                        </style>

                    </head>

                    <body>

                    <div class="box">

                        <h1>
                            Transaction Result
                        </h1>
                    """);

            response.getWriter().println(
                    "<p><strong>Transaction ID:</strong> " +
                    transactionId +
                    "</p>"
            );

            response.getWriter().println(
                    "<p><strong>Risk Score:</strong> " +
                    String.format(
                            "%.2f",
                            riskScore
                    ) +
                    "%</p>"
            );

            response.getWriter().println(
                    "<p><strong>Status:</strong> " +
                    status +
                    "</p>"
            );

            if ("FLAGGED".equals(status)) {

                response.getWriter().println("""
                        <h2>
                            ⚠ Fraud Alert Generated
                        </h2>

                        <p>
                            This transaction has been
                            flagged for review.
                        </p>

                        <a href="alerts">
                            View Fraud Alerts
                        </a>

                        <br><br>
                        """);

            } else {

                response.getWriter().println("""
                        <h2>
                            ✓ Transaction Approved
                        </h2>

                        <br>
                        """);
            }

            response.getWriter().println("""
                        <a href="transaction.html">
                            Enter Another Transaction
                        </a>

                        <br><br>

                        <a href="transaction-history">
                            Transaction History
                        </a>

                        <br><br>

                        <a href="dashboard.html">
                            Back to Dashboard
                        </a>

                    </div>

                    </body>

                    </html>
                    """);

        } catch (Exception e) {

            e.printStackTrace();

            showError(
                    response,
                    "Transaction Error",
                    "The transaction could not be processed. Please try again."
            );
        }
    }

    /*
     * ==========================================
     * ERROR PAGE
     * ==========================================
     */

    private void showError(
            HttpServletResponse response,
            String title,
            String message)
            throws IOException {

        response.setStatus(
                HttpServletResponse.SC_BAD_REQUEST
        );

        response.setContentType(
                "text/html;charset=UTF-8"
        );

        response.getWriter().println(
                "<!DOCTYPE html>" +
                "<html>" +
                "<head>" +
                "<meta charset='UTF-8'>" +
                "<title>" +
                escapeHtml(title) +
                "</title>" +
                "</head>" +
                "<body>" +
                "<h2>" +
                escapeHtml(title) +
                "</h2>" +
                "<p>" +
                escapeHtml(message) +
                "</p>" +
                "<a href='transaction.html'>" +
                "Try Again" +
                "</a>" +
                "</body>" +
                "</html>"
        );
    }

    /*
     * ==========================================
     * HTML ESCAPING
     * ==========================================
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
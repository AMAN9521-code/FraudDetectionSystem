package com.frauddetection.servlet;

import com.frauddetection.util.DBConnection;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.mindrot.jbcrypt.BCrypt;

import java.io.IOException;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

@WebServlet("/register")
public class RegisterServlet extends HttpServlet {

    @Override
    protected void doGet(
            HttpServletRequest request,
            HttpServletResponse response)
            throws ServletException, IOException {

        response.sendRedirect(
                request.getContextPath() + "/register.html"
        );
    }

    @Override
    protected void doPost(
            HttpServletRequest request,
            HttpServletResponse response)
            throws ServletException, IOException {

        request.setCharacterEncoding("UTF-8");

        String name = request.getParameter("name");
        String email = request.getParameter("email");
        String password = request.getParameter("password");
        String confirmPassword = request.getParameter("confirmPassword");

        name = name == null ? "" : name.trim();
        email = email == null ? "" : email.trim().toLowerCase();

        response.setContentType("text/html;charset=UTF-8");

        if (name.isEmpty()
                || email.isEmpty()
                || password == null
                || confirmPassword == null) {

            showError(
                    response,
                    request,
                    "Please fill in all registration fields."
            );
            return;
        }

        if (name.length() > 100) {
            showError(
                    response,
                    request,
                    "Name must be 100 characters or fewer."
            );
            return;
        }

        if (email.length() > 150) {
            showError(
                    response,
                    request,
                    "Email address is too long."
            );
            return;
        }

        if (!email.matches("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$")) {
            showError(
                    response,
                    request,
                    "Please enter a valid email address."
            );
            return;
        }

        if (password.length() < 6) {
            showError(
                    response,
                    request,
                    "Password must contain at least 6 characters."
            );
            return;
        }

        if (!password.equals(confirmPassword)) {
            showError(
                    response,
                    request,
                    "Passwords do not match."
            );
            return;
        }

        String checkSql =
                "SELECT user_id FROM users WHERE email = ?";

        String insertSql =
                "INSERT INTO users " +
                "(name, email, password_hash, role) " +
                "VALUES (?, ?, ?, 'USER')";

        try (Connection connection =
                     DBConnection.getConnection()) {

            // Check whether email already exists
            try (PreparedStatement checkStatement =
                         connection.prepareStatement(checkSql)) {

                checkStatement.setString(1, email);

                try (ResultSet resultSet =
                             checkStatement.executeQuery()) {

                    if (resultSet.next()) {

                        showError(
                                response,
                                request,
                                "An account with this email already exists."
                        );

                        return;
                    }
                }
            }

            // BCrypt password hashing
            String passwordHash =
                    BCrypt.hashpw(
                            password,
                            BCrypt.gensalt(12)
                    );

            // Create USER account
            try (PreparedStatement insertStatement =
                         connection.prepareStatement(insertSql)) {

                insertStatement.setString(1, name);
                insertStatement.setString(2, email);
                insertStatement.setString(3, passwordHash);

                insertStatement.executeUpdate();
            }

            showSuccess(response, request);

        } catch (SQLException e) {

            e.printStackTrace();

            showError(
                    response,
                    request,
                    "Registration could not be completed. Please try again."
            );
        }
    }

    private void showSuccess(
            HttpServletResponse response,
            HttpServletRequest request)
            throws IOException {

        PrintWriter out = response.getWriter();

        String contextPath = request.getContextPath();

        out.println("""
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport"
                          content="width=device-width, initial-scale=1.0">

                    <title>RADAR - Registration Successful</title>

                    <link rel="stylesheet"
                          href="%s/style.css">
                </head>

                <body class="radar-servlet-page">

                    <div class="radar-glow"></div>

                    <header class="radar-servlet-header">
                        <div>
                            <h1 class="radar-title">RADAR</h1>

                            <p class="radar-subtitle">
                                RISK ANALYSIS AND DETECTION OF ANONYMOUS RESPONSE
                            </p>
                        </div>
                    </header>

                    <main class="radar-servlet-content">

                        <section class="radar-servlet-panel">

                            <h2 class="radar-page-title">
                                Registration Successful
                            </h2>

                            <p class="radar-message radar-success-message">
                                Your USER account has been created successfully.
                            </p>

                            <p class="radar-admin-description">
                                You can now sign in using your registered
                                email address and password.
                            </p>

                            <div class="radar-navigation">

                                <a href="%s/login.html"
                                   class="radar-button">
                                    GO TO LOGIN
                                </a>

                            </div>

                        </section>

                    </main>

                    <footer class="radar-footer">
                        RADAR • Secure Fraud Detection System
                    </footer>

                </body>
                </html>
                """.formatted(
                        contextPath,
                        contextPath
                ));
    }

    private void showError(
            HttpServletResponse response,
            HttpServletRequest request,
            String message)
            throws IOException {

        PrintWriter out = response.getWriter();

        String contextPath = request.getContextPath();

        out.println("""
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport"
                          content="width=device-width, initial-scale=1.0">

                    <title>RADAR - Registration Error</title>

                    <link rel="stylesheet"
                          href="%s/style.css">
                </head>

                <body class="radar-servlet-page">

                    <div class="radar-glow"></div>

                    <header class="radar-servlet-header">
                        <div>
                            <h1 class="radar-title">RADAR</h1>

                            <p class="radar-subtitle">
                                RISK ANALYSIS AND DETECTION OF ANONYMOUS RESPONSE
                            </p>
                        </div>
                    </header>

                    <main class="radar-servlet-content">

                        <section class="radar-servlet-panel">

                            <h2 class="radar-page-title">
                                Registration Failed
                            </h2>

                            <p class="radar-message radar-error-message">
                                %s
                            </p>

                            <div class="radar-navigation">

                                <a href="%s/register.html"
                                   class="radar-button">
                                    TRY AGAIN
                                </a>

                                <a href="%s/login.html"
                                   class="radar-button radar-button-secondary">
                                    BACK TO LOGIN
                                </a>

                            </div>

                        </section>

                    </main>

                    <footer class="radar-footer">
                        RADAR • Secure Fraud Detection System
                    </footer>

                </body>
                </html>
                """.formatted(
                        contextPath,
                        escapeHtml(message),
                        contextPath,
                        contextPath
                ));
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
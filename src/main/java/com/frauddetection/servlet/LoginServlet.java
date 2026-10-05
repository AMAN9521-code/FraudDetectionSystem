package com.frauddetection.servlet;

import com.frauddetection.util.DBConnection;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.mindrot.jbcrypt.BCrypt;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

@WebServlet("/login")
public class LoginServlet extends HttpServlet {

    @Override
    protected void doPost(
            HttpServletRequest request,
            HttpServletResponse response)
            throws ServletException, IOException {

        String email = request.getParameter("email");
        String password = request.getParameter("password");

        // ==========================================
        // INPUT VALIDATION
        // ==========================================

        if (email == null ||
                password == null ||
                email.trim().isEmpty() ||
                password.isEmpty()) {

            response.setContentType(
                    "text/html;charset=UTF-8"
            );

            response.getWriter().println(
                    "<h2>Invalid email or password</h2>" +
                    "<a href='login.html'>Try Again</a>"
            );

            return;
        }

        email = email.trim();

        // ==========================================
        // FIND USER BY EMAIL
        // ==========================================

        String sql =
                "SELECT user_id, name, email, " +
                "password_hash, role " +
                "FROM users " +
                "WHERE email = ?";

        try (Connection connection =
                     DBConnection.getConnection();
             PreparedStatement statement =
                     connection.prepareStatement(sql)) {

            statement.setString(1, email);

            try (ResultSet resultSet =
                         statement.executeQuery()) {

                if (!resultSet.next()) {

                    showInvalidLogin(response);
                    return;
                }

                String storedPasswordHash =
                        resultSet.getString("password_hash");

                // ==========================================
                // VERIFY PASSWORD
                // ==========================================

                boolean passwordMatches = false;

                try {
                    passwordMatches =
                            BCrypt.checkpw(
                                    password,
                                    storedPasswordHash
                            );
                } catch (Exception ignored) {
                    passwordMatches = false;
                }

                if (!passwordMatches) {

                    showInvalidLogin(response);
                    return;
                }

                // ==========================================
                // RECORD LOGIN (login_history + last_login)
                // ==========================================

                recordLogin(
                        connection,
                        resultSet.getInt("user_id"),
                        getClientIp(request)
                );

                // ==========================================
                // CREATE SESSION
                // ==========================================

                HttpSession session =
                        request.getSession(true);

                session.setAttribute(
                        "userId",
                        resultSet.getInt("user_id")
                );

                session.setAttribute(
                        "userName",
                        resultSet.getString("name")
                );

                session.setAttribute(
                        "userEmail",
                        resultSet.getString("email")
                );

                session.setAttribute(
                        "userRole",
                        resultSet.getString("role")
                );

                // Prevent session fixation
                request.changeSessionId();

                response.sendRedirect(
                        "dashboard.html"
                );
            }

        } catch (Exception e) {

            e.printStackTrace();

            response.setContentType(
                    "text/html;charset=UTF-8"
            );

            response.getWriter().println(
                    "<h2>Login Error</h2>" +
                    "<p>Please try again later.</p>" +
                    "<a href='login.html'>Back to Login</a>"
            );
        }
    }

    // ==========================================
    // SAVE LOGIN ACTIVITY
    // A logging problem must never block a login,
    // so any error here is printed and ignored.
    // ==========================================

    private void recordLogin(
            Connection connection,
            int userId,
            String ipAddress) {

        try (PreparedStatement historyStatement =
                     connection.prepareStatement(
                             "INSERT INTO login_history " +
                             "(user_id, ip_address) VALUES (?, ?)")) {

            historyStatement.setInt(1, userId);
            historyStatement.setString(2, ipAddress);
            historyStatement.executeUpdate();

        } catch (Exception e) {
            e.printStackTrace();
        }

        try (PreparedStatement updateStatement =
                     connection.prepareStatement(
                             "UPDATE users " +
                             "SET last_login = CURRENT_TIMESTAMP " +
                             "WHERE user_id = ?")) {

            updateStatement.setInt(1, userId);
            updateStatement.executeUpdate();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // ==========================================
    // CLIENT IP (works behind Railway's proxy)
    // ==========================================

    private String getClientIp(HttpServletRequest request) {

        String forwarded =
                request.getHeader("X-Forwarded-For");

        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }

        return request.getRemoteAddr();
    }

    private void showInvalidLogin(
            HttpServletResponse response)
            throws IOException {

        response.setContentType(
                "text/html;charset=UTF-8"
        );

        response.getWriter().println(
                "<h2>Invalid email or password</h2>" +
                "<a href='login.html'>Try Again</a>"
        );
    }
}
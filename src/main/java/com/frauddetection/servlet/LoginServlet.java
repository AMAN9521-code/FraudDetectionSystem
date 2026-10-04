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
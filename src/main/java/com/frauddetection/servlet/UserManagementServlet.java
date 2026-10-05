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

@WebServlet("/admin-users")
public class UserManagementServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        HttpSession session = request.getSession(false);
        if (session == null || session.getAttribute("userId") == null) {
            response.sendRedirect("login.html");
            return;
        }
        if (!"ADMIN".equalsIgnoreCase((String) session.getAttribute("userRole"))) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
            return;
        }

        response.setContentType("text/html;charset=UTF-8");
        StringBuilder html = new StringBuilder();

        html.append("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <title>RADAR - User Management</title>
              <link rel="icon" type="image/svg+xml" href="favicon.svg">
              <link rel="stylesheet" href="style.css">
            </head>
            <body class="radar-servlet-page">
              <div class="radar-glow"></div>
              <main class="radar-servlet-content">
                <section class="radar-servlet-panel">
                  <div class="radar-welcome">
                    <h2>User Management</h2>
                    <p>Registered users and their login activity</p>
                  </div>
                  <div class="radar-report-section">
                    <h2 class="radar-page-title">All Users</h2>
                    <div class="radar-servlet-table-wrapper">
                      <table class="radar-servlet-table">
                        <thead><tr>
                          <th>ID</th><th>Name</th><th>Email</th><th>Role</th>
                          <th>Registered</th><th>Last Login</th><th>Logins</th>
                          <th>Transactions</th><th>Flagged</th>
                        </tr></thead>
                        <tbody>
            """);

        String usersSql = """
            SELECT u.user_id, u.name, u.email, u.role, u.created_at, u.last_login,
              (SELECT COUNT(*) FROM login_history l WHERE l.user_id = u.user_id) AS login_count,
              (SELECT COUNT(*) FROM transactions t WHERE t.user_id = u.user_id) AS txn_count,
              (SELECT COUNT(*) FROM transactions t
                 WHERE t.user_id = u.user_id AND t.status = 'FLAGGED') AS flagged_count
            FROM users u
            ORDER BY u.last_login IS NULL, u.last_login DESC, u.user_id
            """;

        String historySql = """
            SELECT u.name, u.email, l.login_time, l.ip_address
            FROM login_history l
            JOIN users u ON u.user_id = l.user_id
            ORDER BY l.login_time DESC
            LIMIT 50
            """;

        try (Connection connection = DBConnection.getConnection()) {

            try (PreparedStatement ps = connection.prepareStatement(usersSql);
                 ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    String lastLogin = rs.getString("last_login");
                    html.append("<tr>")
                        .append(td(String.valueOf(rs.getInt("user_id"))))
                        .append(td(rs.getString("name")))
                        .append(td(rs.getString("email")))
                        .append(td(rs.getString("role")))
                        .append(td(rs.getString("created_at")))
                        .append(td(lastLogin == null ? "Never" : lastLogin))
                        .append(td(String.valueOf(rs.getInt("login_count"))))
                        .append(td(String.valueOf(rs.getInt("txn_count"))))
                        .append(td(String.valueOf(rs.getInt("flagged_count"))))
                        .append("</tr>");
                }
            }

            html.append("""
                        </tbody>
                      </table>
                    </div>
                  </div>
                  <div class="radar-report-section">
                    <h2 class="radar-page-title">Recent Logins (last 50)</h2>
                    <div class="radar-servlet-table-wrapper">
                      <table class="radar-servlet-table">
                        <thead><tr>
                          <th>Name</th><th>Email</th><th>Login Time</th><th>IP Address</th>
                        </tr></thead>
                        <tbody>
                """);

            try (PreparedStatement ps = connection.prepareStatement(historySql);
                 ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    html.append("<tr>")
                        .append(td(rs.getString("name")))
                        .append(td(rs.getString("email")))
                        .append(td(rs.getString("login_time")))
                        .append(td(rs.getString("ip_address")))
                        .append("</tr>");
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
            html.append("<tr><td colspan='9'>Unable to load user data.</td></tr>");
        }

        html.append("""
                        </tbody>
                      </table>
                    </div>
                  </div>
                  <div class="radar-navigation">
                    <a class="radar-servlet-button" href="admin">Administration</a>
                    <a class="radar-servlet-button" href="audit-log">Audit Log</a>
                    <a class="radar-servlet-button" href="dashboard.html">Dashboard</a>
                  </div>
                </section>
              </main>
            </body>
            </html>
            """);

        response.getWriter().println(html);
    }

    private static String td(String value) {
        return "<td>" + escape(value) + "</td>";
    }

    // Names and emails are typed by users, so escape them to block script injection
    private static String escape(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }
}

package com.frauddetection.servlet;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;

@WebServlet("/session-info")
public class SessionInfoServlet extends HttpServlet {

    @Override
    protected void doGet(
            HttpServletRequest request,
            HttpServletResponse response)
            throws ServletException, IOException {

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        // Prevent caching of session information
        response.setHeader(
                "Cache-Control",
                "no-cache, no-store, must-revalidate"
        );

        response.setHeader("Pragma", "no-cache");
        response.setDateHeader("Expires", 0);

        // Get current session without creating a new one
        HttpSession session = request.getSession(false);

        // Check login status
        if (session == null ||
                session.getAttribute("userId") == null) {

            response.setStatus(
                    HttpServletResponse.SC_UNAUTHORIZED
            );

            response.getWriter().write(
                    "{\"role\":null}"
            );

            return;
        }

        // Read role from current session
        String role = (String) session.getAttribute("userRole");

        if (role == null) {
            response.setStatus(
                    HttpServletResponse.SC_UNAUTHORIZED
            );

            response.getWriter().write(
                    "{\"role\":null}"
            );

            return;
        }

        // Return role to dashboard
        if ("ADMIN".equalsIgnoreCase(role)) {

            response.getWriter().write(
                    "{\"role\":\"ADMIN\"}"
            );

        } else {

            response.getWriter().write(
                    "{\"role\":\"USER\"}"
            );
        }
    }
}

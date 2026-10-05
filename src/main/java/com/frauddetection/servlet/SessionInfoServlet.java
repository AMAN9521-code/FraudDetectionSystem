package com.frauddetection.servlet;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;

/**
 * Tells the dashboard page whether the current visitor is an ADMIN or a USER,
 * so the page can hide admin-only cards and links.
 *
 * This is only for the UI. The real protection is AdminFilter, which blocks
 * admin URLs on the server no matter what the page shows.
 */
@WebServlet("/session-info")
public class SessionInfoServlet extends HttpServlet {

    @Override
    protected void doGet(
            HttpServletRequest request,
            HttpServletResponse response)
            throws ServletException, IOException {

        response.setContentType("application/json;charset=UTF-8");
        response.setHeader("Cache-Control", "no-store");

        HttpSession session = request.getSession(false);

        if (session == null ||
                session.getAttribute("userId") == null) {

            response.getWriter().print("{\"loggedIn\":false,\"role\":\"NONE\"}");
            return;
        }

        String role = (String) session.getAttribute("userRole");
        boolean isAdmin = "ADMIN".equalsIgnoreCase(role);

        response.getWriter().print(
                "{\"loggedIn\":true,\"role\":\"" +
                (isAdmin ? "ADMIN" : "USER") +
                "\"}"
        );
    }
}
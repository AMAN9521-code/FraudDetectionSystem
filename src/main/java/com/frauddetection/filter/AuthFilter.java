package com.frauddetection.filter;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;

@WebFilter(urlPatterns = {
        "/dashboard.html",
        "/transaction.html",
        "/transaction",
        "/transaction-history",
        "/fraud-alerts",
        "/alerts",
        "/import-transactions",
        "/review-alert",
        "/reports",
        "/admin",
        "/update-config",
        "/algorithm-params",
        "/update-algorithm-params",
        "/audit-log",
        "/admin-users"
})
public class AuthFilter implements Filter {

    @Override
    public void doFilter(
            ServletRequest request,
            ServletResponse response,
            FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest =
                (HttpServletRequest) request;

        HttpServletResponse httpResponse =
                (HttpServletResponse) response;

        HttpSession session =
                httpRequest.getSession(false);

        boolean loggedIn =
                session != null &&
                session.getAttribute("userId") != null;

        if (!loggedIn) {

            httpResponse.sendRedirect(
                    httpRequest.getContextPath() + "/login.html"
            );

            return;
        }

        chain.doFilter(request, response);
    }
}
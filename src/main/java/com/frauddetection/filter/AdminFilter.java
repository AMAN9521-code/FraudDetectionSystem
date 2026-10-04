package com.frauddetection.filter;

import jakarta.servlet.Filter;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;

@WebFilter(urlPatterns = {
        "/admin",
        "/update-config",
        "/algorithm-params",
        "/update-algorithm-params",
        "/audit-log",
        "/review-alert"
})
public class AdminFilter implements Filter {

    @Override
    public void doFilter(
            jakarta.servlet.ServletRequest request,
            jakarta.servlet.ServletResponse response,
            jakarta.servlet.FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest =
                (HttpServletRequest) request;

        HttpServletResponse httpResponse =
                (HttpServletResponse) response;

        HttpSession session =
                httpRequest.getSession(false);

        if (session == null ||
                session.getAttribute("userId") == null) {

            httpResponse.sendRedirect(
                    httpRequest.getContextPath() + "/login.html"
            );

            return;
        }

        String role =
                (String) session.getAttribute("userRole");

        if (!"ADMIN".equals(role)) {

            httpResponse.setStatus(
                    HttpServletResponse.SC_FORBIDDEN
            );

            httpResponse.setContentType(
                    "text/html;charset=UTF-8"
            );

            httpResponse.getWriter().println(
                    "<!DOCTYPE html>" +
                    "<html><head><title>Access Denied</title></head>" +
                    "<body>" +
                    "<h1>403 - Access Denied</h1>" +
                    "<p>You do not have permission to access this page.</p>" +
                    "<a href='dashboard.html'>Back to Dashboard</a>" +
                    "</body></html>"
            );

            return;
        }

        chain.doFilter(request, response);
    }
}
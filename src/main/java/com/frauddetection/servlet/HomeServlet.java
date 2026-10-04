package com.frauddetection.servlet;

import com.frauddetection.util.DBConnection;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.PrintWriter;
import java.sql.Connection;

@WebServlet("/home")
public class HomeServlet extends HttpServlet {

    @Override
    protected void doGet(
            HttpServletRequest request,
            HttpServletResponse response)
            throws ServletException, IOException {

        response.setContentType(
                "text/html;charset=UTF-8"
        );

        PrintWriter out =
                response.getWriter();

        out.println("""
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <title>Fraud Detection System</title>

                    <style>
                        body {
                            font-family: Arial, sans-serif;
                            background: #f4f6f8;
                            text-align: center;
                            padding-top: 80px;
                        }

                        .box {
                            background: white;
                            width: 550px;
                            margin: auto;
                            padding: 30px;
                            border-radius: 12px;
                            box-shadow:
                                0 4px 15px
                                rgba(0,0,0,0.15);
                        }

                        .success {
                            color: green;
                        }

                        .error {
                            color: #b00020;
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
                        AI-Powered Fraud Detection System
                    </h1>

                    <h2>
                        Server is working!
                    </h2>
                """);

        try (Connection connection =
                     DBConnection.getConnection()) {

            out.println("""
                    <h2 class="success">
                        Database Connected Successfully!
                    </h2>

                    <p>
                        Java → JDBC → MySQL is working.
                    </p>
                    """);

        } catch (Exception e) {

            /*
             * Log the technical error on the server,
             * but NEVER expose it to the user.
             */
            e.printStackTrace();

            out.println("""
                    <h2 class="error">
                        Database Connection Failed
                    </h2>

                    <p>
                        The application could not connect
                        to the database.
                    </p>

                    <p>
                        Please try again later.
                    </p>
                    """);
        }

        out.println("""
                    <a href="login.html">
                        Go to Login
                    </a>

                </div>

                </body>
                </html>
                """);
    }
}
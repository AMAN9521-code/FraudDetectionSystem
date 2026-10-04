package com.frauddetection.servlet;

import com.frauddetection.service.FraudDetectionService;
import com.frauddetection.util.DBConnection;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.MultipartConfig;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.Part;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

@WebServlet("/import-transactions")
@MultipartConfig(
        fileSizeThreshold = 1024 * 64,
        maxFileSize = 10L * 1024 * 1024,
        maxRequestSize = 12L * 1024 * 1024
)
public class ImportTransactionsServlet extends HttpServlet {

    private static final int MAX_ROWS = 10000;

    @Override
    protected void doGet(
            HttpServletRequest request,
            HttpServletResponse response)
            throws ServletException, IOException {

        HttpSession session = request.getSession(false);

        if (session == null ||
                session.getAttribute("userId") == null) {

            response.sendRedirect(
                    request.getContextPath() + "/login.html");

            return;
        }

        response.setContentType("text/html;charset=UTF-8");

        response.getWriter().println(page(
                "Import Transaction History",
                """
                <div class="radar-servlet-content">

                    <div class="radar-servlet-panel radar-import-panel">

                        <h2>Import Transaction History</h2>

                        <p class="radar-admin-description">
                            Upload transaction-history data from a payment
                            platform or a normalized transaction CSV.
                            RADAR will analyze every valid transaction.
                        </p>

                        <form class="radar-servlet-form"
                              method="post"
                              action="import-transactions"
                              enctype="multipart/form-data">

                            <label for="csvFile">
                                Transaction History CSV
                            </label>

                            <input
                                id="csvFile"
                                type="file"
                                name="csvFile"
                                accept=".csv,text/csv"
                                required>

                            <button
                                class="radar-servlet-button"
                                type="submit">
                                UPLOAD &amp; ANALYZE
                            </button>

                        </form>

                        <div class="radar-import-format">

                            <h3>Supported CSV Format</h3>

                            <p>
                                Recommended columns:
                            </p>

                            <p>
                                <strong>Date</strong>,
                                <strong>Amount</strong>,
                                <strong>Merchant</strong>,
                                <strong>Location</strong>,
                                <strong>Transaction ID</strong>
                            </p>

                            <p>
                                Transaction ID is optional.
                            </p>

                            <p>
                                Location is optional.
                            </p>

                        </div>

                        <div class="radar-import-example">

                            <h3>Example CSV</h3>

                            <pre>Date,Amount,Merchant,Location,Transaction ID
2026-09-01 10:15:00,250,Amazon,Delhi,PAY001
2026-09-01 10:17:00,85000,Unknown Merchant,Mumbai,PAY002
2026-09-01 10:18:00,90000,Unknown Merchant,Mumbai,PAY003
2026-09-01 11:30:00,500,Swiggy,Delhi,PAY004</pre>

                        </div>

                        <div class="radar-navigation">

                            <a class="radar-servlet-button"
                               href="dashboard.html">
                                Dashboard
                            </a>

                            <a class="radar-servlet-button"
                               href="transaction-history">
                                Transaction History
                            </a>

                        </div>

                    </div>

                </div>
                """
        ));
    }

    @Override
    protected void doPost(
            HttpServletRequest request,
            HttpServletResponse response)
            throws ServletException, IOException {

        HttpSession session = request.getSession(false);

        if (session == null ||
                session.getAttribute("userId") == null) {

            response.sendRedirect(
                    request.getContextPath() + "/login.html");

            return;
        }

        int userId =
                (Integer) session.getAttribute("userId");

        Part filePart = request.getPart("csvFile");

        if (filePart == null ||
                filePart.getSize() == 0) {

            showError(
                    response,
                    "No CSV Selected",
                    "Please select a transaction-history CSV file.");

            return;
        }

        String fileName =
                filePart.getSubmittedFileName();

        if (fileName == null ||
                !fileName.toLowerCase(Locale.ROOT)
                        .endsWith(".csv")) {

            showError(
                    response,
                    "Invalid File",
                    "Only CSV files are supported.");

            return;
        }

        int imported = 0;
        int duplicates = 0;
        int invalid = 0;
        int suspicious = 0;

        List<String> errors =
                new ArrayList<>();

        try (
                BufferedReader reader =
                        new BufferedReader(
                                new InputStreamReader(
                                        filePart.getInputStream(),
                                        StandardCharsets.UTF_8));

                Connection connection =
                        DBConnection.getConnection()
        ) {

            String headerLine =
                    reader.readLine();

            if (headerLine == null ||
                    headerLine.trim().isEmpty()) {

                showError(
                        response,
                        "Empty CSV",
                        "The CSV does not contain a header row.");

                return;
            }

            List<String> headers =
                    parseCsvLine(headerLine);

            Map<String, Integer> headerMap =
                    buildHeaderMap(headers);

            Integer amountIndex =
                    findHeader(
                            headerMap,
                            "amount",
                            "transaction amount",
                            "amount (inr)",
                            "debit amount",
                            "credit amount");

            Integer merchantIndex =
                    findHeader(
                            headerMap,
                            "merchant",
                            "merchant name",
                            "description",
                            "transaction details",
                            "recipient",
                            "paid to",
                            "receiver");

            Integer dateIndex =
                    findHeader(
                            headerMap,
                            "date",
                            "transaction date",
                            "timestamp",
                            "transaction timestamp",
                            "datetime",
                            "transaction date & time");

            Integer locationIndex =
                    findHeader(
                            headerMap,
                            "location",
                            "city",
                            "transaction location");

            Integer referenceIndex =
                    findHeader(
                            headerMap,
                            "transaction id",
                            "transaction_id",
                            "reference",
                            "reference id",
                            "reference_id",
                            "utr",
                            "upi transaction id",
                            "txn id");

            if (amountIndex == null ||
                    merchantIndex == null) {

                showError(
                        response,
                        "Unsupported CSV Format",
                        "The CSV must contain Amount and Merchant or Description columns.");

                return;
            }

            String line;

            int rowNumber = 1;

            while ((line = reader.readLine()) != null) {

                rowNumber++;

                if (line.trim().isEmpty()) {
                    continue;
                }

                if (rowNumber > MAX_ROWS + 1) {

                    errors.add(
                            "Stopped after " +
                            MAX_ROWS +
                            " transaction rows.");

                    break;
                }

                try {

                    List<String> fields =
                            parseCsvLine(line);

                    if (fields.size() <= amountIndex ||
                            fields.size() <= merchantIndex) {

                        invalid++;

                        addError(
                                errors,
                                rowNumber,
                                "Not enough columns.");

                        continue;
                    }

                    double amount =
                            parseAmount(
                                    fields.get(amountIndex));

                    if (!Double.isFinite(amount) ||
                            amount <= 0 ||
                            amount > 9999999999.99) {

                        invalid++;

                        addError(
                                errors,
                                rowNumber,
                                "Invalid amount.");

                        continue;
                    }

                    String merchant =
                            clean(
                                    fields.get(merchantIndex));

                    if (merchant.isEmpty() ||
                            merchant.length() > 150) {

                        invalid++;

                        addError(
                                errors,
                                rowNumber,
                                "Invalid merchant.");

                        continue;
                    }

                    String location =
                            locationIndex != null &&
                            fields.size() > locationIndex
                                    ? clean(fields.get(locationIndex))
                                    : "Imported";

                    if (location.isEmpty()) {
                        location = "Imported";
                    }

                    if (location.length() > 150) {

                        invalid++;

                        addError(
                                errors,
                                rowNumber,
                                "Location is too long.");

                        continue;
                    }

                    Timestamp transactionTime =
                            dateIndex != null &&
                            fields.size() > dateIndex
                                    ? parseTimestamp(
                                            fields.get(dateIndex))
                                    : new Timestamp(
                                            System.currentTimeMillis());

                    String reference =
                            referenceIndex != null &&
                            fields.size() > referenceIndex
                                    ? clean(
                                            fields.get(referenceIndex))
                                    : "";

                    if (reference.isEmpty()) {

                        reference =
                                sha256(
                                        transactionTime.getTime()
                                                + "|" +
                                        amount
                                                + "|" +
                                        merchant.toLowerCase(
                                                Locale.ROOT)
                                                + "|" +
                                        location.toLowerCase(
                                                Locale.ROOT));
                    }

                    if (reference.length() > 150) {

                        reference =
                                reference.substring(0, 150);
                    }

                    if (sourceReferenceExists(
                            connection,
                            userId,
                            reference)) {

                        duplicates++;
                        continue;
                    }

                    int transactionId =
                            insertTransaction(
                                    connection,
                                    userId,
                                    amount,
                                    merchant,
                                    location,
                                    transactionTime,
                                    reference);

                    double riskScore =
                            FraudDetectionService.analyzeTransaction(
                                    userId,
                                    amount,
                                    merchant,
                                    location,
                                    transactionId,
                                    transactionTime);

                    String status =
                            riskScore >= 50.0
                                    ? "FLAGGED"
                                    : "APPROVED";

                    updateTransaction(
                            connection,
                            transactionId,
                            status,
                            riskScore);

                    if (riskScore >= 50.0) {
                        suspicious++;
                    }

                    imported++;

                } catch (Exception rowError) {

                    invalid++;

                    addError(
                            errors,
                            rowNumber,
                            "Could not process row.");

                    rowError.printStackTrace();
                }
            }

            logImport(
                    connection,
                    userId,
                    imported,
                    duplicates,
                    invalid,
                    suspicious,
                    fileName);

        } catch (Exception e) {

            e.printStackTrace();

            showError(
                    response,
                    "Import Failed",
                    "RADAR could not process the uploaded CSV.");

            return;
        }

        response.setContentType(
                "text/html;charset=UTF-8");

        StringBuilder body =
                new StringBuilder();

        body.append("""
                <div class="radar-servlet-content">

                    <div class="radar-servlet-panel radar-import-result">

                        <h2>Import Complete</h2>

                        <div class="radar-import-stats">
                """);

        stat(
                body,
                "Transactions Imported",
                imported);

        stat(
                body,
                "Suspicious Transactions",
                suspicious);

        stat(
                body,
                "Duplicates Skipped",
                duplicates);

        stat(
                body,
                "Invalid Rows",
                invalid);

        body.append("""
                        </div>
                """);

        if (!errors.isEmpty()) {

            body.append(
                    "<div class=\"radar-import-errors\">" +
                    "<h3>Row Notes</h3><ul>");

            int shown = 0;

            for (String error : errors) {

                if (shown++ >= 10) {
                    break;
                }

                body.append("<li>")
                        .append(escapeHtml(error))
                        .append("</li>");
            }

            body.append("</ul></div>");
        }

        body.append("""
                        <div class="radar-navigation">

                            <a class="radar-servlet-button"
                               href="transaction-history">
                                View Transaction History
                            </a>

                            <a class="radar-servlet-button"
                               href="alerts">
                                View Fraud Alerts
                            </a>

                            <a class="radar-servlet-button"
                               href="reports">
                                View Reports
                            </a>

                            <a class="radar-servlet-button"
                               href="import-transactions">
                                Import Another CSV
                            </a>

                        </div>

                    </div>

                </div>
                """);

        response.getWriter().println(
                page(
                        "Import Result",
                        body.toString()));
    }

    private static int insertTransaction(
            Connection connection,
            int userId,
            double amount,
            String merchant,
            String location,
            Timestamp transactionTime,
            String reference)
            throws Exception {

        String sql = """
                INSERT INTO transactions
                (
                    user_id,
                    amount,
                    merchant,
                    location,
                    txn_timestamp,
                    status,
                    risk_score,
                    source_reference
                )
                VALUES (?, ?, ?, ?, ?, 'PENDING', 0, ?)
                """;

        try (
                PreparedStatement statement =
                        connection.prepareStatement(
                                sql,
                                Statement.RETURN_GENERATED_KEYS)
        ) {

            statement.setInt(1, userId);
            statement.setDouble(2, amount);
            statement.setString(3, merchant);
            statement.setString(4, location);
            statement.setTimestamp(5, transactionTime);
            statement.setString(6, reference);

            statement.executeUpdate();

            try (
                    ResultSet keys =
                            statement.getGeneratedKeys()
            ) {

                if (!keys.next()) {
                    throw new Exception(
                            "Could not create transaction ID.");
                }

                return keys.getInt(1);
            }
        }
    }

    private static void updateTransaction(
            Connection connection,
            int transactionId,
            String status,
            double riskScore)
            throws Exception {

        String sql =
                "UPDATE transactions " +
                "SET status = ?, risk_score = ? " +
                "WHERE transaction_id = ?";

        try (
                PreparedStatement statement =
                        connection.prepareStatement(sql)
        ) {

            statement.setString(1, status);
            statement.setDouble(2, riskScore);
            statement.setInt(3, transactionId);

            statement.executeUpdate();
        }
    }

    private static boolean sourceReferenceExists(
            Connection connection,
            int userId,
            String reference)
            throws Exception {

        String sql =
                "SELECT transaction_id " +
                "FROM transactions " +
                "WHERE user_id = ? " +
                "AND source_reference = ? " +
                "LIMIT 1";

        try (
                PreparedStatement statement =
                        connection.prepareStatement(sql)
        ) {

            statement.setInt(1, userId);
            statement.setString(2, reference);

            try (
                    ResultSet resultSet =
                            statement.executeQuery()
            ) {

                return resultSet.next();
            }
        }
    }

    private static void logImport(
            Connection connection,
            int userId,
            int imported,
            int duplicates,
            int invalid,
            int suspicious,
            String fileName)
            throws Exception {

        String action =
                "Imported CSV transaction history: " +
                safeFileName(fileName) +
                " | imported=" + imported +
                ", suspicious=" + suspicious +
                ", duplicates=" + duplicates +
                ", invalid=" + invalid;

        String sql =
                "INSERT INTO audit_log " +
                "(user_id, action) VALUES (?, ?)";

        try (
                PreparedStatement statement =
                        connection.prepareStatement(sql)
        ) {

            statement.setInt(1, userId);
            statement.setString(2, action);

            statement.executeUpdate();
        }
    }

    private static String safeFileName(
            String name) {

        if (name == null) {
            return "CSV";
        }

        name =
                name.replaceAll("[\\r\\n]", "");

        return name.length() > 80
                ? name.substring(0, 80)
                : name;
    }

    private static double parseAmount(
            String value) {

        String cleaned =
                value == null
                        ? ""
                        : value.trim()
                            .replace("₹", "")
                            .replace("INR", "")
                            .replace(",", "")
                            .trim();

        return Double.parseDouble(cleaned);
    }

    private static Timestamp parseTimestamp(
            String value) {

        String text = clean(value);

        if (text.isEmpty()) {

            return new Timestamp(
                    System.currentTimeMillis());
        }

        List<DateTimeFormatter> formats =
                Arrays.asList(

                        DateTimeFormatter.ofPattern(
                                "yyyy-MM-dd HH:mm:ss"),

                        DateTimeFormatter.ofPattern(
                                "yyyy-MM-dd HH:mm"),

                        DateTimeFormatter.ofPattern(
                                "dd-MM-yyyy HH:mm:ss"),

                        DateTimeFormatter.ofPattern(
                                "dd-MM-yyyy HH:mm"),

                        DateTimeFormatter.ofPattern(
                                "dd/MM/yyyy HH:mm:ss"),

                        DateTimeFormatter.ofPattern(
                                "dd/MM/yyyy HH:mm"),

                        DateTimeFormatter.ofPattern(
                                "MM/dd/yyyy HH:mm:ss"),

                        DateTimeFormatter.ofPattern(
                                "MM/dd/yyyy HH:mm"),

                        DateTimeFormatter.ISO_LOCAL_DATE_TIME
                );

        for (DateTimeFormatter formatter :
                formats) {

            try {

                return Timestamp.valueOf(
                        LocalDateTime.parse(
                                text,
                                formatter));

            } catch (DateTimeParseException ignored) {
            }
        }

        List<DateTimeFormatter> dateFormats =
                Arrays.asList(

                        DateTimeFormatter.ofPattern(
                                "yyyy-MM-dd"),

                        DateTimeFormatter.ofPattern(
                                "dd-MM-yyyy"),

                        DateTimeFormatter.ofPattern(
                                "dd/MM/yyyy"),

                        DateTimeFormatter.ofPattern(
                                "MM/dd/yyyy")
                );

        for (DateTimeFormatter formatter :
                dateFormats) {

            try {

                LocalDate date =
                        LocalDate.parse(
                                text,
                                formatter);

                return Timestamp.from(
                        date.atStartOfDay(
                                ZoneId.systemDefault())
                                .toInstant());

            } catch (DateTimeParseException ignored) {
            }
        }

        throw new IllegalArgumentException(
                "Unsupported transaction date format.");
    }

    private static List<String> parseCsvLine(
            String line) {

        List<String> fields =
                new ArrayList<>();

        StringBuilder current =
                new StringBuilder();

        boolean quoted = false;

        for (int i = 0;
             i < line.length();
             i++) {

            char c = line.charAt(i);

            if (c == '"') {

                if (quoted &&
                        i + 1 < line.length() &&
                        line.charAt(i + 1) == '"') {

                    current.append('"');
                    i++;

                } else {

                    quoted = !quoted;
                }

            } else if (
                    c == ',' &&
                    !quoted) {

                fields.add(
                        current.toString().trim());

                current.setLength(0);

            } else {

                current.append(c);
            }
        }

        fields.add(
                current.toString().trim());

        return fields;
    }

    private static Map<String, Integer>
    buildHeaderMap(
            List<String> headers) {

        Map<String, Integer> map =
                new HashMap<>();

        for (int i = 0;
             i < headers.size();
             i++) {

            String normalized =
                    normalizeHeader(
                            headers.get(i));

            if (!normalized.isEmpty()) {
                map.put(normalized, i);
            }
        }

        return map;
    }

    private static Integer findHeader(
            Map<String, Integer> map,
            String... names) {

        for (String name : names) {

            Integer index =
                    map.get(
                            normalizeHeader(name));

            if (index != null) {
                return index;
            }
        }

        return null;
    }

    private static String normalizeHeader(
            String value) {

        return clean(value)
                .toLowerCase(Locale.ROOT)
                .replace("_", " ")
                .replace("-", " ")
                .replaceAll("\\s+", " ");
    }

    private static String clean(
            String value) {

        if (value == null) {
            return "";
        }

        return value.trim()
                .replaceAll("[\\r\\n]", "");
    }

    private static String sha256(
            String input)
            throws Exception {

        MessageDigest digest =
                MessageDigest.getInstance(
                        "SHA-256");

        byte[] bytes =
                digest.digest(
                        input.getBytes(
                                StandardCharsets.UTF_8));

        StringBuilder result =
                new StringBuilder();

        for (byte b : bytes) {

            result.append(
                    String.format(
                            "%02x",
                            b));
        }

        return result.toString();
    }

    private static void addError(
            List<String> errors,
            int row,
            String message) {

        if (errors.size() < 100) {

            errors.add(
                    "Row " +
                    row +
                    ": " +
                    message);
        }
    }

    private static void stat(
            StringBuilder body,
            String label,
            int value) {

        body.append(
                "<div class=\"radar-import-stat\">" +
                "<span>")
                .append(
                        escapeHtml(label))
                .append(
                        "</span><strong>")
                .append(value)
                .append(
                        "</strong></div>");
    }

    private static String page(
            String title,
            String body) {

        return """
                <!DOCTYPE html>
                <html lang="en">

                <head>

                    <meta charset="UTF-8">

                    <meta name="viewport"
                          content="width=device-width, initial-scale=1.0">

                    <title>RADAR - %s</title>

                    <link rel="stylesheet"
                          href="style.css">

                </head>

                <body class="radar-servlet-page">

                    <div class="radar-glow"></div>

                    <header class="radar-servlet-header">

                        <h1>RADAR</h1>

                        <p>
                            Risk Analysis and Detection of Anonymous Response
                        </p>

                    </header>

                    %s

                    <footer class="radar-footer">

                        RADAR &nbsp; • &nbsp;
                        RISK ANALYSIS AND DETECTION OF ANONYMOUS RESPONSE

                    </footer>

                </body>

                </html>
                """.formatted(
                        escapeHtml(title),
                        body);
    }

    private static void showError(
            HttpServletResponse response,
            String title,
            String message)
            throws IOException {

        response.setContentType(
                "text/html;charset=UTF-8");

        response.getWriter().println(
                page(
                        "Import Error",
                        """
                        <div class="radar-servlet-content">

                            <div class="radar-servlet-panel">

                                <h2>%s</h2>

                                <p>%s</p>

                                <div class="radar-navigation">

                                    <a class="radar-servlet-button"
                                       href="import-transactions">
                                        Back to Import
                                    </a>

                                    <a class="radar-servlet-button"
                                       href="dashboard.html">
                                        Dashboard
                                    </a>

                                </div>

                            </div>

                        </div>
                        """.formatted(
                                escapeHtml(title),
                                escapeHtml(message))));
    }

    private static String escapeHtml(
            String value) {

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
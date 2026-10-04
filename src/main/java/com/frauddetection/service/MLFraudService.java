package com.frauddetection.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;

public class MLFraudService {

    private static final String LOCAL_ML_API_URL =
            "http://127.0.0.1:5000/predict";

    private static final HttpClient HTTP_CLIENT =
            HttpClient.newHttpClient();

    private static final ObjectMapper OBJECT_MAPPER =
            new ObjectMapper();

    private MLFraudService() {
    }

    public static double predictFraudProbability(
            double amount,
            String merchant,
            String location)
            throws Exception {

        /*
         * Cloud deployment:
         * Railway will provide ML_API_URL.
         */
        String mlApiUrl =
                System.getenv("ML_API_URL");

        /*
         * Local development:
         * If ML_API_URL is not configured,
         * continue using the local Flask service.
         */
        if (mlApiUrl == null
                || mlApiUrl.isBlank()) {

            mlApiUrl =
                    LOCAL_ML_API_URL;
        }

        String json = OBJECT_MAPPER.writeValueAsString(
                new MLRequest(
                        amount,
                        merchant,
                        location
                )
        );

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(mlApiUrl))
                .header(
                        "Content-Type",
                        "application/json"
                )
                .POST(
                        HttpRequest.BodyPublishers.ofString(
                                json,
                                StandardCharsets.UTF_8
                        )
                )
                .build();

        HttpResponse<String> response =
                HTTP_CLIENT.send(
                        request,
                        HttpResponse.BodyHandlers.ofString()
                );

        if (response.statusCode() != 200) {
            throw new IOException(
                    "ML service returned HTTP "
                            + response.statusCode()
                            + ": "
                            + response.body()
            );
        }

        JsonNode result =
                OBJECT_MAPPER.readTree(
                        response.body()
                );

        if (!result.has("fraud_probability")) {
            throw new IOException(
                    "ML service response did not contain fraud_probability"
            );
        }

        return result
                .get("fraud_probability")
                .asDouble();
    }

    private record MLRequest(
            double amount,
            String merchant,
            String location
    ) {
    }
}
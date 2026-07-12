package com.papairs.auth.e2e.validation;

import com.papairs.auth.e2e.AbstractE2ETest;
import com.papairs.auth.model.User;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@DisplayName("Token Validation")
public class TokenValidationTest extends AbstractE2ETest {

    @Test
    @DisplayName("Should validate and return userId for valid token")
    public void validateValidToken() throws Exception {
        String response = fixtures.registerUser(TEST_EMAIL_1, VALID_PASSWORD);
        String token = fixtures.loginUser(TEST_EMAIL_1, VALID_PASSWORD);

        String id = objectMapper.readTree(response).get("id").asText();

        mockMvc.perform(post("/api/auth/validate")
                        .header(AUTH_HEADER, bearerToken(token)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(id));
    }

    @Test
    @DisplayName("Should reject validation with invalid token")
    public void rejectInvalidToken() throws Exception {
        mockMvc.perform(post("/api/auth/validate")
                        .header(AUTH_HEADER, bearerToken("invalid-token-xyz")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Should reject validation with expired token")
    public void rejectExpiredToken() throws Exception {
        User user = fixtures.createUserDirectly(TEST_EMAIL_1, VALID_PASSWORD);
        String expiredToken = fixtures.createExpiredSession(user.getId());

        mockMvc.perform(post("/api/auth/validate")
                        .header(AUTH_HEADER, bearerToken(expiredToken)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.detail").value(containsString("Session expired")));
    }

    @Test
    @DisplayName("Should reject validation without Authorization header")
    public void rejectValidationWithoutAuthHeader() throws Exception {
        mockMvc.perform(post("/api/auth/validate"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Should reject validation with malformed Authorization header")
    public void rejectValidationWithMalformedAuthHeader() throws Exception {
        mockMvc.perform(post("/api/auth/validate")
                        .header(AUTH_HEADER, "NotBearer sometoken"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Should reject validation with empty Bearer token")
    public void rejectValidationWithEmptyBearerToken() throws Exception {
        mockMvc.perform(post("/api/auth/validate")
                        .header(AUTH_HEADER, "Bearer "))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Should reject validation for deactivated user")
    public void rejectValidationForDeactivatedUser() throws Exception {
        fixtures.registerUser(TEST_EMAIL_1, VALID_PASSWORD);
        String token = fixtures.loginUser(TEST_EMAIL_1, VALID_PASSWORD);

        fixtures.deactivateUser(TEST_EMAIL_1);

        mockMvc.perform(post("/api/auth/validate")
                        .header(AUTH_HEADER, bearerToken(token)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.detail").value(containsString("User account is deactivated")));
    }
}

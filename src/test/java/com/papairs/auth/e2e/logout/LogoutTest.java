package com.papairs.auth.e2e.logout;

import com.papairs.auth.e2e.AbstractE2ETest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@DisplayName("User Logout")
public class LogoutTest extends AbstractE2ETest {

    @Test
    @DisplayName("Should logout successfully with valid token")
    public void logoutWithValidToken() throws Exception {
        String token = fixtures.registerAndLoginUser(TEST_EMAIL_1, VALID_PASSWORD);

        mockMvc.perform(post("/api/auth/logout")
                        .header(AUTH_HEADER, bearerToken(token)))
                .andExpect(status().isNoContent());

        fixtures.verifyTokenIsInvalid(token);
    }

    @Test
    @DisplayName("Should reject with invalid token for security")
    public void returnSuccessWithInvalidToken() throws Exception {
        mockMvc.perform(post("/api/auth/logout")
                        .header(AUTH_HEADER, bearerToken("invalid-token-12345")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Should reject logout without Authorization header")
    public void rejectLogoutWithoutAuthHeader() throws Exception {
        mockMvc.perform(post("/api/auth/logout"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Should reject logout with malformed Authorization header")
    public void rejectLogoutWithMalformedAuthHeader() throws Exception {
        mockMvc.perform(post("/api/auth/logout")
                        .header(AUTH_HEADER, "NotBearer sometoken"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Should reject logout with empty Bearer token")
    public void rejectLogoutWithEmptyBearerToken() throws Exception {
        mockMvc.perform(post("/api/auth/logout")
                        .header(AUTH_HEADER, "Bearer "))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Should reject logout with whitespace-only Bearer token")
    public void rejectLogoutWithWhitespaceOnlyToken() throws Exception {
        mockMvc.perform(post("/api/auth/logout")
                        .header(AUTH_HEADER, "Bearer    "))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Should only invalidate the specific session, not all user sessions")
    public void onlyInvalidateSpecificSession() throws Exception {
        fixtures.registerUser(TEST_EMAIL_1, VALID_PASSWORD);

        String token1 = fixtures.loginUser(TEST_EMAIL_1, VALID_PASSWORD);
        String token2 = fixtures.loginUser(TEST_EMAIL_1, VALID_PASSWORD);

        mockMvc.perform(post("/api/auth/logout")
                        .header(AUTH_HEADER, bearerToken(token1)))
                .andExpect(status().isNoContent());

        fixtures.verifyTokenIsInvalid(token1);

        fixtures.verifyTokenIsValid(token2);
    }
}

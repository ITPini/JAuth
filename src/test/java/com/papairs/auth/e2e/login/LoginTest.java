package com.papairs.auth.e2e.login;

import com.papairs.auth.e2e.AbstractE2ETest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@DisplayName("User Login")
public class LoginTest extends AbstractE2ETest {

    @Test
    @DisplayName("Should login successfully with valid credentials")
    public void loginWithValidCredentials() throws Exception {
        fixtures.registerUser(TEST_EMAIL_1, VALID_PASSWORD);

        String requestBody = """
            {
                "email": "%s",
                "password": "%s"
            }
            """.formatted(TEST_EMAIL_1, VALID_PASSWORD);

        mockMvc.perform(post("/api/auth/login")
                        .contentType(CONTENT_TYPE_JSON)
                        .content(requestBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").exists())
                .andExpect(jsonPath("$.sessionId").exists())
                .andExpect(jsonPath("$.expiresAt").exists())
                .andExpect(jsonPath("$.user.id").exists())
                .andExpect(jsonPath("$.user.email").value(TEST_EMAIL_1));
    }

    @Test
    @DisplayName("Should reject login with non-existent email")
    public void rejectLoginWithNonExistentEmail() throws Exception {
        String requestBody = """
            {
                "email": "nonexistent@example.com",
                "password": "%s"
            }
            """.formatted(VALID_PASSWORD);

        mockMvc.perform(post("/api/auth/login")
                        .contentType(CONTENT_TYPE_JSON)
                        .content(requestBody))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.detail").value("Invalid credentials"));
    }

    @Test
    @DisplayName("Should reject login with incorrect password")
    public void rejectLoginWithIncorrectPassword() throws Exception {
        fixtures.registerUser(TEST_EMAIL_1, VALID_PASSWORD);

        String requestBody = """
            {
                "email": "%s",
                "password": "WrongPass@123"
            }
            """.formatted(TEST_EMAIL_1);

        mockMvc.perform(post("/api/auth/login")
                        .contentType(CONTENT_TYPE_JSON)
                        .content(requestBody))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.detail").value(containsString("Invalid credentials")));
    }

    @Test
    @DisplayName("Should reject login with blank email")
    public void rejectLoginWithBlankEmail() throws Exception {
        String requestBody = """
            {
                "email": "   ",
                "password": "%s"
            }
            """.formatted(VALID_PASSWORD);

        mockMvc.perform(post("/api/auth/login")
                        .contentType(CONTENT_TYPE_JSON)
                        .content(requestBody))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.details", hasItem(containsString("email"))));
    }

    @Test
    @DisplayName("Should reject login with blank password")
    public void rejectLoginWithBlankPassword() throws Exception {
        String requestBody = """
            {
                "email": "test@example.com",
                "password": "   "
            }
            """;

        mockMvc.perform(post("/api/auth/login")
                        .contentType(CONTENT_TYPE_JSON)
                        .content(requestBody))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.details", hasItem(containsString("password"))));
    }

    @Test
    @DisplayName("Should reject login with invalid email format")
    public void rejectLoginWithInvalidEmailFormat() throws Exception {
        String requestBody = """
            {
                "email": "not-an-email",
                "password": "%s"
            }
            """.formatted(VALID_PASSWORD);

        mockMvc.perform(post("/api/auth/login")
                        .contentType(CONTENT_TYPE_JSON)
                        .content(requestBody))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.details", hasItem(containsString("email"))));
    }

    @Test
    @DisplayName("Should reject login for deactivated user account")
    public void rejectLoginForDeactivatedAccount() throws Exception {
        fixtures.createDeactivatedUser(TEST_EMAIL_1, VALID_PASSWORD);

        String requestBody = """
            {
                "email": "%s",
                "password": "%s"
            }
            """.formatted(TEST_EMAIL_1, VALID_PASSWORD);

        mockMvc.perform(post("/api/auth/login")
                        .contentType(CONTENT_TYPE_JSON)
                        .content(requestBody))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.detail").value("Account is deactivated"));
    }

    @Test
    @DisplayName("Should create new session on each login")
    public void createNewSessionOnEachLogin() throws Exception {
        fixtures.registerUser(TEST_EMAIL_1, VALID_PASSWORD);

        String token1 = fixtures.loginUser(TEST_EMAIL_1, VALID_PASSWORD);
        String token2 = fixtures.loginUser(TEST_EMAIL_1, VALID_PASSWORD);

        assert !token1.equals(token2) : "Each login should create a new session token";

        fixtures.verifyTokenIsValid(token1);
        fixtures.verifyTokenIsValid(token2);
    }

    @Test
    @DisplayName("Should return same error message for non-existent email and wrong password")
    public void returnGenericErrorForSecurityReasons() throws Exception {
        fixtures.registerUser(TEST_EMAIL_1, VALID_PASSWORD);

        String wrongPasswordRequest = """
            {
                "email": "%s",
                "password": "WrongPass@123"
            }
            """.formatted(TEST_EMAIL_1);

        String wrongPasswordResponse = mockMvc.perform(post("/api/auth/login")
                        .contentType(CONTENT_TYPE_JSON)
                        .content(wrongPasswordRequest))
                .andExpect(status().isUnauthorized())
                .andReturn()
                .getResponse()
                .getContentAsString();

        String nonExistentEmailRequest = """
            {
                "email": "nonexistent@example.com",
                "password": "%s"
            }
            """.formatted(VALID_PASSWORD);

        String nonExistentEmailResponse = mockMvc.perform(post("/api/auth/login")
                        .contentType(CONTENT_TYPE_JSON)
                        .content(nonExistentEmailRequest))
                .andExpect(status().isUnauthorized())
                .andReturn()
                .getResponse()
                .getContentAsString();

        String wrongPasswordMessage = objectMapper.readTree(wrongPasswordResponse).get("detail").asText();
        String nonExistentMessage = objectMapper.readTree(nonExistentEmailResponse).get("detail").asText();

        assert wrongPasswordMessage.equals(nonExistentMessage) : 
            "Error messages should be identical for security reasons";
    }
}

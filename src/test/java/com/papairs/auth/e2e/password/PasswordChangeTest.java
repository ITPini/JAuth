package com.papairs.auth.e2e.password;

import com.papairs.auth.e2e.AbstractE2ETest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@DisplayName("Password Change")
public class PasswordChangeTest extends AbstractE2ETest {

    @Test
    @DisplayName("Should change password successfully with valid credentials")
    public void changePasswordWithValidCredentials() throws Exception {
        fixtures.registerUser(TEST_EMAIL_1, VALID_PASSWORD);
        String token = fixtures.loginUser(TEST_EMAIL_1, VALID_PASSWORD);

        String requestBody = """
            {
                "oldPassword": "%s",
                "newPassword": "%s",
                "confirmPassword": "%s"
            }
            """.formatted(VALID_PASSWORD, VALID_PASSWORD_2, VALID_PASSWORD_2);

        mockMvc.perform(post("/api/auth/change-password")
                        .header(AUTH_HEADER, bearerToken(token))
                        .contentType(CONTENT_TYPE_JSON)
                        .content(requestBody))
                .andExpect(status().isNoContent());

        fixtures.verifyTokenIsInvalid(token);

        fixtures.loginUser(TEST_EMAIL_1, VALID_PASSWORD_2);
    }

    @Test
    @DisplayName("Should reject password change with incorrect old password")
    public void rejectIncorrectOldPassword() throws Exception {
        fixtures.registerUser(TEST_EMAIL_1, VALID_PASSWORD);
        String token = fixtures.loginUser(TEST_EMAIL_1, VALID_PASSWORD);

        String requestBody = """
            {
                "oldPassword": "WrongOld@123",
                "newPassword": "%s",
                "confirmPassword": "%s"
            }
            """.formatted(VALID_PASSWORD_2, VALID_PASSWORD_2);

        mockMvc.perform(post("/api/auth/change-password")
                        .header(AUTH_HEADER, bearerToken(token))
                        .contentType(CONTENT_TYPE_JSON)
                        .content(requestBody))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value(containsString("incorrect")));
    }

    @Test
    @DisplayName("Should reject password change when new password same as old")
    public void rejectSamePasswordAsOld() throws Exception {
        fixtures.registerUser(TEST_EMAIL_1, VALID_PASSWORD);
        String token = fixtures.loginUser(TEST_EMAIL_1, VALID_PASSWORD);

        String requestBody = """
            {
                "oldPassword": "%s",
                "newPassword": "%s",
                "confirmPassword": "%s"
            }
            """.formatted(VALID_PASSWORD, VALID_PASSWORD, VALID_PASSWORD);

        mockMvc.perform(post("/api/auth/change-password")
                        .header(AUTH_HEADER, bearerToken(token))
                        .contentType(CONTENT_TYPE_JSON)
                        .content(requestBody))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value(containsString("different")));
    }

    @Test
    @DisplayName("Should reject password change when confirm password doesn't match")
    public void rejectMismatchedConfirmPassword() throws Exception {
        fixtures.registerUser(TEST_EMAIL_1, VALID_PASSWORD);
        String token = fixtures.loginUser(TEST_EMAIL_1, VALID_PASSWORD);

        String requestBody = """
            {
                "oldPassword": "%s",
                "newPassword": "%s",
                "confirmPassword": "DifferentPass@999"
            }
            """.formatted(VALID_PASSWORD, VALID_PASSWORD_2);

        mockMvc.perform(post("/api/auth/change-password")
                        .header(AUTH_HEADER, bearerToken(token))
                        .contentType(CONTENT_TYPE_JSON)
                        .content(requestBody))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value(containsString("match")));
    }

    @Test
    @DisplayName("Should reject password change with blank old password")
    public void rejectBlankOldPassword() throws Exception {
        fixtures.registerUser(TEST_EMAIL_1, VALID_PASSWORD);
        String token = fixtures.loginUser(TEST_EMAIL_1, VALID_PASSWORD);

        String requestBody = """
            {
                "oldPassword": "   ",
                "newPassword": "%s",
                "confirmPassword": "%s"
            }
            """.formatted(VALID_PASSWORD_2, VALID_PASSWORD_2);

        mockMvc.perform(post("/api/auth/change-password")
                        .header(AUTH_HEADER, bearerToken(token))
                        .contentType(CONTENT_TYPE_JSON)
                        .content(requestBody))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.details", hasItem(containsString("oldPassword"))));
    }

    @Test
    @DisplayName("Should reject password change with blank new password")
    public void rejectBlankNewPassword() throws Exception {
        fixtures.registerUser(TEST_EMAIL_1, VALID_PASSWORD);
        String token = fixtures.loginUser(TEST_EMAIL_1, VALID_PASSWORD);

        String requestBody = """
            {
                "oldPassword": "%s",
                "newPassword": "   ",
                "confirmPassword": "   "
            }
            """.formatted(VALID_PASSWORD);

        mockMvc.perform(post("/api/auth/change-password")
                        .header(AUTH_HEADER, bearerToken(token))
                        .contentType(CONTENT_TYPE_JSON)
                        .content(requestBody))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.details", hasItem(containsString("newPassword"))));
    }

    @Test
    @DisplayName("Should reject password change with blank confirm password")
    public void rejectBlankConfirmPassword() throws Exception {
        fixtures.registerUser(TEST_EMAIL_1, VALID_PASSWORD);
        String token = fixtures.loginUser(TEST_EMAIL_1, VALID_PASSWORD);

        String requestBody = """
            {
                "oldPassword": "%s",
                "newPassword": "%s",
                "confirmPassword": "   "
            }
            """.formatted(VALID_PASSWORD, VALID_PASSWORD_2);

        mockMvc.perform(post("/api/auth/change-password")
                        .header(AUTH_HEADER, bearerToken(token))
                        .contentType(CONTENT_TYPE_JSON)
                        .content(requestBody))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.details", hasItem(containsString("confirmPassword"))));
    }

    @Test
    @DisplayName("Should reject password change with new password too short")
    public void rejectNewPasswordTooShort() throws Exception {
        fixtures.registerUser(TEST_EMAIL_1, VALID_PASSWORD);
        String token = fixtures.loginUser(TEST_EMAIL_1, VALID_PASSWORD);

        String requestBody = """
            {
                "oldPassword": "%s",
                "newPassword": "Ab1@xyz",
                "confirmPassword": "Ab1@xyz"
            }
            """.formatted(VALID_PASSWORD);

        mockMvc.perform(post("/api/auth/change-password")
                        .header(AUTH_HEADER, bearerToken(token))
                        .contentType(CONTENT_TYPE_JSON)
                        .content(requestBody))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.details", hasItem(containsString("8"))));
    }

    @Test
    @DisplayName("Should reject password change with new password too long")
    public void rejectNewPasswordTooLong() throws Exception {
        fixtures.registerUser(TEST_EMAIL_1, VALID_PASSWORD);
        String token = fixtures.loginUser(TEST_EMAIL_1, VALID_PASSWORD);

        String longPassword = "Ab1@" + "x".repeat(125);

        String requestBody = """
            {
                "oldPassword": "%s",
                "newPassword": "%s",
                "confirmPassword": "%s"
            }
            """.formatted(VALID_PASSWORD, longPassword, longPassword);

        mockMvc.perform(post("/api/auth/change-password")
                        .header(AUTH_HEADER, bearerToken(token))
                        .contentType(CONTENT_TYPE_JSON)
                        .content(requestBody))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.details", hasItem(containsString("128"))));
    }

    @Test
    @DisplayName("Should reject password change without Authorization header")
    public void rejectPasswordChangeWithoutAuthHeader() throws Exception {
        String requestBody = """
            {
                "oldPassword": "%s",
                "newPassword": "%s",
                "confirmPassword": "%s"
            }
            """.formatted(VALID_PASSWORD, VALID_PASSWORD_2, VALID_PASSWORD_2);

        mockMvc.perform(post("/api/auth/change-password")
                        .contentType(CONTENT_TYPE_JSON)
                        .content(requestBody))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(containsString("Authorization")));
    }

    @Test
    @DisplayName("Should reject password change with invalid token")
    public void rejectPasswordChangeWithInvalidToken() throws Exception {
        String requestBody = """
            {
                "oldPassword": "%s",
                "newPassword": "%s",
                "confirmPassword": "%s"
            }
            """.formatted(VALID_PASSWORD, VALID_PASSWORD_2, VALID_PASSWORD_2);

        mockMvc.perform(post("/api/auth/change-password")
                        .header(AUTH_HEADER, bearerToken("invalid-token-xyz"))
                        .contentType(CONTENT_TYPE_JSON)
                        .content(requestBody))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value(containsString("Invalid")));
    }

    @Test
    @DisplayName("Should invalidate all user sessions after password change")
    public void invalidateAllSessionsAfterPasswordChange() throws Exception {
        fixtures.registerUser(TEST_EMAIL_1, VALID_PASSWORD);

        String token1 = fixtures.loginUser(TEST_EMAIL_1, VALID_PASSWORD);
        String token2 = fixtures.loginUser(TEST_EMAIL_1, VALID_PASSWORD);
        String token3 = fixtures.loginUser(TEST_EMAIL_1, VALID_PASSWORD);

        String requestBody = """
            {
                "oldPassword": "%s",
                "newPassword": "%s",
                "confirmPassword": "%s"
            }
            """.formatted(VALID_PASSWORD, VALID_PASSWORD_2, VALID_PASSWORD_2);

        mockMvc.perform(post("/api/auth/change-password")
                        .header(AUTH_HEADER, bearerToken(token1))
                        .contentType(CONTENT_TYPE_JSON)
                        .content(requestBody))
                .andExpect(status().isNoContent());

        fixtures.verifyTokenIsInvalid(token1);
        fixtures.verifyTokenIsInvalid(token2);
        fixtures.verifyTokenIsInvalid(token3);
    }

    @Test
    @DisplayName("Should reject password change with new password missing uppercase")
    public void rejectNewPasswordMissingUppercase() throws Exception {
        fixtures.registerUser(TEST_EMAIL_1, VALID_PASSWORD);
        String token = fixtures.loginUser(TEST_EMAIL_1, VALID_PASSWORD);

        String requestBody = """
            {
                "oldPassword": "%s",
                "newPassword": "test@1234",
                "confirmPassword": "test@1234"
            }
            """.formatted(VALID_PASSWORD);

        mockMvc.perform(post("/api/auth/change-password")
                        .header(AUTH_HEADER, bearerToken(token))
                        .contentType(CONTENT_TYPE_JSON)
                        .content(requestBody))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.details", hasItem(containsString("uppercase"))));
    }

    @Test
    @DisplayName("Should reject password change with new password missing lowercase")
    public void rejectNewPasswordMissingLowercase() throws Exception {
        fixtures.registerUser(TEST_EMAIL_1, VALID_PASSWORD);
        String token = fixtures.loginUser(TEST_EMAIL_1, VALID_PASSWORD);

        String requestBody = """
            {
                "oldPassword": "%s",
                "newPassword": "TEST@1234",
                "confirmPassword": "TEST@1234"
            }
            """.formatted(VALID_PASSWORD);

        mockMvc.perform(post("/api/auth/change-password")
                        .header(AUTH_HEADER, bearerToken(token))
                        .contentType(CONTENT_TYPE_JSON)
                        .content(requestBody))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.details", hasItem(containsString("lowercase"))));
    }

    @Test
    @DisplayName("Should reject password change with new password missing digit")
    public void rejectNewPasswordMissingDigit() throws Exception {
        fixtures.registerUser(TEST_EMAIL_1, VALID_PASSWORD);
        String token = fixtures.loginUser(TEST_EMAIL_1, VALID_PASSWORD);

        String requestBody = """
            {
                "oldPassword": "%s",
                "newPassword": "Test@abcd",
                "confirmPassword": "Test@abcd"
            }
            """.formatted(VALID_PASSWORD);

        mockMvc.perform(post("/api/auth/change-password")
                        .header(AUTH_HEADER, bearerToken(token))
                        .contentType(CONTENT_TYPE_JSON)
                        .content(requestBody))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.details", hasItem(containsString("number"))));
    }

    @Test
    @DisplayName("Should reject password change with new password missing special character")
    public void rejectNewPasswordMissingSpecialCharacter() throws Exception {
        fixtures.registerUser(TEST_EMAIL_1, VALID_PASSWORD);
        String token = fixtures.loginUser(TEST_EMAIL_1, VALID_PASSWORD);

        String requestBody = """
            {
                "oldPassword": "%s",
                "newPassword": "Test12345",
                "confirmPassword": "Test12345"
            }
            """.formatted(VALID_PASSWORD);

        mockMvc.perform(post("/api/auth/change-password")
                        .header(AUTH_HEADER, bearerToken(token))
                        .contentType(CONTENT_TYPE_JSON)
                        .content(requestBody))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.details", hasItem(containsString("special"))));
    }
}

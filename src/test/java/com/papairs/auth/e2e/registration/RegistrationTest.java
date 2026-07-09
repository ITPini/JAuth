package com.papairs.auth.e2e.registration;

import com.papairs.auth.e2e.AbstractE2ETest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@DisplayName("User Registration")
public class RegistrationTest extends AbstractE2ETest {

    @Test
    @DisplayName("Should register new user with valid email and password")
    public void registerNewUserWithValidCredentials() throws Exception {
        String requestBody = """
            {
                "email": "newuser@example.com",
                "password": "%s"
            }
            """.formatted(VALID_PASSWORD);

        mockMvc.perform(post("/api/auth/register")
                        .contentType(CONTENT_TYPE_JSON)
                        .content(requestBody))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").exists())
                .andExpect(jsonPath("$.email").value("newuser@example.com"))
                .andExpect(jsonPath("$.emailVerified").value(false))
                .andExpect(jsonPath("$.active").value(true));

        fixtures.verifyUserExists("newuser@example.com");
    }

    @Test
    @DisplayName("Should reject registration with already registered email")
    public void rejectDuplicateEmail() throws Exception {
        fixtures.registerUser("existing@example.com", VALID_PASSWORD);

        String requestBody = """
            {
                "email": "existing@example.com",
                "password": "%s"
            }
            """.formatted(VALID_PASSWORD);

        mockMvc.perform(post("/api/auth/register")
                        .contentType(CONTENT_TYPE_JSON)
                        .content(requestBody))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").value(containsString("already registered")));
    }

    @Test
    @DisplayName("Should reject registration with invalid email format")
    public void rejectInvalidEmailFormat() throws Exception {
        String requestBody = """
            {
                "email": "not-an-email",
                "password": "%s"
            }
            """.formatted(VALID_PASSWORD);

        mockMvc.perform(post("/api/auth/register")
                        .contentType(CONTENT_TYPE_JSON)
                        .content(requestBody))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.details", hasItem(containsString("email"))));
    }

    @Test
    @DisplayName("Should reject registration with blank email")
    public void rejectBlankEmail() throws Exception {
        String requestBody = """
            {
                "email": "   ",
                "password": "%s"
            }
            """.formatted(VALID_PASSWORD);

        mockMvc.perform(post("/api/auth/register")
                        .contentType(CONTENT_TYPE_JSON)
                        .content(requestBody))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.details", hasItem(containsString("email"))));
    }

    @Test
    @DisplayName("Should reject registration with null email")
    public void rejectNullEmail() throws Exception {
        String requestBody = """
            {
                "email": null,
                "password": "%s"
            }
            """.formatted(VALID_PASSWORD);

        mockMvc.perform(post("/api/auth/register")
                        .contentType(CONTENT_TYPE_JSON)
                        .content(requestBody))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.details", hasItem(containsString("email"))));
    }

    @Test
    @DisplayName("Should reject registration with email exceeding 255 characters")
    public void rejectEmailTooLong() throws Exception {
        String longEmail = "a".repeat(250) + "@test.com";

        String requestBody = """
            {
                "email": "%s",
                "password": "%s"
            }
            """.formatted(longEmail, VALID_PASSWORD);

        mockMvc.perform(post("/api/auth/register")
                        .contentType(CONTENT_TYPE_JSON)
                        .content(requestBody))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.details", hasItem(containsString("255"))));
    }

    @Test
    @DisplayName("Should reject registration with blank password")
    public void rejectBlankPassword() throws Exception {
        String requestBody = """
            {
                "email": "test@example.com",
                "password": "   "
            }
            """;

        mockMvc.perform(post("/api/auth/register")
                        .contentType(CONTENT_TYPE_JSON)
                        .content(requestBody))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.details", hasItem(containsString("password"))));
    }

    @Test
    @DisplayName("Should reject registration with null password")
    public void rejectNullPassword() throws Exception {
        String requestBody = """
            {
                "email": "test@example.com",
                "password": null
            }
            """;

        mockMvc.perform(post("/api/auth/register")
                        .contentType(CONTENT_TYPE_JSON)
                        .content(requestBody))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.details", hasItem(containsString("password"))));
    }

    @Test
    @DisplayName("Should reject registration with password shorter than 8 characters")
    public void rejectPasswordTooShort() throws Exception {
        String requestBody = """
            {
                "email": "test@example.com",
                "password": "Ab1@xyz"
            }
            """;

        mockMvc.perform(post("/api/auth/register")
                        .contentType(CONTENT_TYPE_JSON)
                        .content(requestBody))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.details", hasItem(containsString("8"))));
    }

    @Test
    @DisplayName("Should reject registration with password exceeding 128 characters")
    public void rejectPasswordTooLong() throws Exception {
        String longPassword = "Ab1@" + "x".repeat(125);

        String requestBody = """
            {
                "email": "test@example.com",
                "password": "%s"
            }
            """.formatted(longPassword);

        mockMvc.perform(post("/api/auth/register")
                        .contentType(CONTENT_TYPE_JSON)
                        .content(requestBody))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.details", hasItem(containsString("128"))));
    }

    @Test
    @DisplayName("Should reject registration with password missing uppercase letter")
    public void rejectPasswordMissingUppercase() throws Exception {
        String requestBody = """
            {
                "email": "test@example.com",
                "password": "test@1234"
            }
            """;

        mockMvc.perform(post("/api/auth/register")
                        .contentType(CONTENT_TYPE_JSON)
                        .content(requestBody))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.details", hasItem(containsString("uppercase"))));
    }

    @Test
    @DisplayName("Should reject registration with password missing lowercase letter")
    public void rejectPasswordMissingLowercase() throws Exception {
        String requestBody = """
            {
                "email": "test@example.com",
                "password": "TEST@1234"
            }
            """;

        mockMvc.perform(post("/api/auth/register")
                        .contentType(CONTENT_TYPE_JSON)
                        .content(requestBody))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.details", hasItem(containsString("lowercase"))));
    }

    @Test
    @DisplayName("Should reject registration with password missing digit")
    public void rejectPasswordMissingDigit() throws Exception {
        String requestBody = """
            {
                "email": "test@example.com",
                "password": "Test@abcd"
            }
            """;

        mockMvc.perform(post("/api/auth/register")
                        .contentType(CONTENT_TYPE_JSON)
                        .content(requestBody))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.details", hasItem(containsString("number"))));
    }

    @Test
    @DisplayName("Should reject registration with password missing special character")
    public void rejectPasswordMissingSpecialCharacter() throws Exception {
        String requestBody = """
            {
                "email": "test@example.com",
                "password": "Test12345"
            }
            """;

        mockMvc.perform(post("/api/auth/register")
                        .contentType(CONTENT_TYPE_JSON)
                        .content(requestBody))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.details", hasItem(containsString("special"))));
    }
}

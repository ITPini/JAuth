package com.papairs.auth.e2e.fixture;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.papairs.auth.model.Session;
import com.papairs.auth.model.User;
import com.papairs.auth.repository.SessionRepository;
import com.papairs.auth.repository.UserRepository;
import com.papairs.auth.security.Sha256TokenHasher;
import com.papairs.auth.security.TokenHasher;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDateTime;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

public class TestFixtures {

    private final MockMvc mockMvc;
    private final ObjectMapper objectMapper;
    private final UserRepository userRepository;
    private final SessionRepository sessionRepository;
    private final String contentTypeJson;
    private final BCryptPasswordEncoder passwordEncoder;
    private final TokenHasher tokenHasher;

    public TestFixtures(MockMvc mockMvc, ObjectMapper objectMapper,
                        UserRepository userRepository, SessionRepository sessionRepository,
                        String contentTypeJson) {
        this.mockMvc = mockMvc;
        this.objectMapper = objectMapper;
        this.userRepository = userRepository;
        this.sessionRepository = sessionRepository;
        this.contentTypeJson = contentTypeJson;
        this.passwordEncoder = new BCryptPasswordEncoder();
        this.tokenHasher = new Sha256TokenHasher();
    }

    /**
     * Register a new user via API
     */
    public String registerUser(String email, String password) throws Exception {
        String requestBody = """
            {
                "email": "%s",
                "password": "%s"
            }
            """.formatted(email, password);

        return mockMvc.perform(post("/api/auth/register")
                        .contentType(contentTypeJson)
                        .content(requestBody))
                .andExpect(status().isCreated())
                .andReturn()
                .getResponse()
                .getContentAsString();
    }

    /**
     * Create a user directly in the database (bypassing API)
     */
    public User createUserDirectly(String email, String password) {
        User user = new User(email);
        user.setPasswordHash(passwordEncoder.encode(password));
        user.setIsActive(true);
        user.setEmailVerified(false);
        return userRepository.save(user);
    }

    /**
     * Create a deactivated user directly in the database
     */
    public User createDeactivatedUser(String email, String password) {
        User user = new User(email);
        user.setPasswordHash(passwordEncoder.encode(password));
        user.setIsActive(false);
        user.setEmailVerified(false);
        return userRepository.save(user);
    }

    /**
     * Login a user and return the session token
     */
    public String loginUser(String email, String password) throws Exception {
        String requestBody = """
            {
                "email": "%s",
                "password": "%s"
            }
            """.formatted(email, password);

        String response = mockMvc.perform(post("/api/auth/login")
                        .contentType(contentTypeJson)
                        .content(requestBody))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();

        return objectMapper.readTree(response).get("token").asText();
    }

    /**
     * Register and login a user, returning the session token
     */
    public String registerAndLoginUser(String email, String password) throws Exception {
        registerUser(email, password);
        return loginUser(email, password);
    }

    /**
     * Create an expired session directly in the database.
     * Returns the plaintext token that can be used in API calls.
     * The hashed version is stored in the database.
     */
    public String createExpiredSession(String userId) {
        String plaintextToken = "expired-test-token-" + System.currentTimeMillis();
        String hashedToken = tokenHasher.hash(plaintextToken);
        
        Session session = new Session();
        session.setUserId(userId);
        session.setTokenHash(hashedToken);
        session.setExpiresAt(LocalDateTime.now().minusHours(1));
        session.setLastActiveAt(LocalDateTime.now().minusHours(2));
        sessionRepository.save(session);
        
        return plaintextToken;
    }

    /**
     * Verify that a token is valid
     */
    public void verifyTokenIsValid(String token) throws Exception {
        mockMvc.perform(post("/api/auth/validate")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").exists());
    }

    /**
     * Verify that a token is invalid
     */
    public void verifyTokenIsInvalid(String token) throws Exception {
        mockMvc.perform(post("/api/auth/validate")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    /**
     * Verify that a token is invalid due to expiration
     */
    public void verifyTokenIsExpired(String token) throws Exception {
        mockMvc.perform(post("/api/auth/validate")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    /**
     * Verify that a user exists by email
     */
    public void verifyUserExists(String email) {
        assert userRepository.existsByEmail(email) : "User with email " + email + " should exist";
    }

    /**
     * Verify that a user does not exist by email
     */
    public void verifyUserDoesNotExist(String email) {
        assert !userRepository.existsByEmail(email) : "User with email " + email + " should not exist";
    }

    /**
     * Verify that a user is active
     */
    public void verifyUserIsActive(String userId) {
        User user = userRepository.findById(userId).orElseThrow();
        assert user.getIsActive() : "User should be active";
    }

    /**
     * Verify that a user is deactivated
     */
    public void verifyUserIsDeactivated(String userId) {
        User user = userRepository.findById(userId).orElseThrow();
        assert !user.getIsActive() : "User should be deactivated";
    }

    /**
     * Verify that a session exists for user
     */
    public void verifySessionExistsForUser(String userId) {
        assert !sessionRepository.findByUserId(userId).isEmpty() : "Session should exist for user";
    }

    /**
     * Verify that no sessions exist for user
     */
    public void verifyNoSessionsForUser(String userId) {
        assert sessionRepository.findByUserId(userId).isEmpty() : "No sessions should exist for user";
    }

    /**
     * Get session count for user
     */
    public int getSessionCountForUser(String userId) {
        return sessionRepository.findByUserId(userId).size();
    }

    /**
     * Deactivate a user by email
     */
    public void deactivateUser(String email) {
        User user = userRepository.findByEmail(email).orElseThrow();
        user.setIsActive(false);
        userRepository.save(user);
    }

    /**
     * Get user by email
     */
    public User getUserByEmail(String email) {
        return userRepository.findByEmail(email).orElseThrow();
    }

    /**
     * Check if a session exists by plaintext token
     */
    public boolean sessionExistsByToken(String plaintextToken) {
        String hashedToken = tokenHasher.hash(plaintextToken);
        return sessionRepository.findByTokenHash(hashedToken).isPresent();
    }
}

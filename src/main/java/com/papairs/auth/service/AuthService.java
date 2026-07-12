package com.papairs.auth.service;

import com.papairs.auth.exception.AuthenticationException;
import com.papairs.auth.exception.InvalidTokenException;
import com.papairs.auth.exception.UserAlreadyExistsException;
import com.papairs.auth.exception.UserDeactivatedException;
import com.papairs.auth.model.Session;
import com.papairs.auth.model.User;
import com.papairs.auth.service.result.LoginResult;
import com.papairs.auth.service.result.SessionCreationResult;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
public class AuthService {

    private final UserService userService;
    private final SessionService sessionService;

    public AuthService(SessionService sessionService, UserService userService) {
        this.userService = userService;
        this.sessionService = sessionService;
    }

    /**
     * Register a new user
     * @param email email
     * @param password unhashed password
     * @return User entity if successful, else throw exception
     */
    @Transactional
    public User register(String email, String password) {
        if (userService.emailExists(email)) {
            throw new UserAlreadyExistsException("Email already registered");
        }

        return userService.createUser(email, password)
                .orElseThrow(() -> new AuthenticationException("Failed to create user"));
    }

    /**
     * Authenticate user login
     *
     * Firstly, check if user exists
     * Check if user is active
     * Check if password matches
     * Update last login timestamp
     * Create session and return token
     *
     * @param email email
     * @param password unhashed password
     * @return LoginResponse with session token and user details, else throw exception
     */
    @Transactional
    public LoginResult login(String email, String password) {
        User user = userService.findByEmail(email)
                .orElseThrow(() -> new AuthenticationException("Invalid credentials"));

        if (!userService.isActive(user)) {
            throw new UserDeactivatedException("Account is deactivated");
        }

        if (!userService.verifyPassword(password, user.getPasswordHash())) {
            throw new AuthenticationException("Invalid credentials");
        }

        SessionCreationResult sessionResult = sessionService.createSession(user.getId());
        userService.updateLastLogin(user.getId());

        return new LoginResult(sessionResult, user);
    }

    /**
     * Logout user by deleting session
     * @param sessionId session ID
     * Does not throw error if session not found for security reasons
     */
    public void logoutBySessionId(String sessionId) {
        sessionService.deleteById(sessionId);
    }

    /**
     * Validate session token and return userId only
     * OPTIMIZED for high-frequency validation endpoint
     * Does NOT load full User entity for performance
     * TODO: Implement email verification
     * @param sessionId session ID
     * @return userId if valid, else throw exception
     */
    @Transactional
    public String validateTokenBySession(String sessionId) {
        LocalDateTime now = LocalDateTime.now();

        Optional<String> userId = userService.findValidUserId(sessionId, now);

        if (userId.isPresent()) {
            sessionService.touchLastActive(sessionId, now);
            return userId.get();
        }

        Session session = sessionService.findById(sessionId)
                .orElseThrow(() -> new AuthenticationException("Invalid token"));

        if (sessionService.isExpired(session)) {
            throw new InvalidTokenException("Session expired");
        }

        throw new UserDeactivatedException("User account is deactivated");
    }

    public Session findSessionByToken(String token) {
        return sessionService.findByToken(token)
                .orElseThrow(() -> new AuthenticationException("Invalid session ID"));
    }

    /**
     * Change user password and deletes all previous sessions
     * @param userId user ID
     * @param oldPassword old unhashed password
     * @param newPassword new unhashed password
     */
    @Transactional
    public void changePasswordByUserId(String userId, String oldPassword, String newPassword) {
        User user = userService.findById(userId)
                .orElseThrow(() -> new AuthenticationException("User not found"));

        if (!userService.verifyPassword(oldPassword, user.getPasswordHash())) {
            throw new AuthenticationException("Old password is incorrect");
        }

        userService.changePassword(user.getId(), newPassword);

        sessionService.deleteAllUserSessions(user.getId());
    }

    /**
     * Delete user and all associated sessions
     * @param userId user ID
     */
    @Transactional
    public void deleteUser(String userId) {
        userService.deleteUser(userId);
        sessionService.deleteAllUserSessions(userId);
    }
}

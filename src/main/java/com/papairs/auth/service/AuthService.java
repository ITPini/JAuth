package com.papairs.auth.service;

import com.papairs.auth.dto.request.ChangePasswordRequest;
import com.papairs.auth.dto.request.LoginRequest;
import com.papairs.auth.dto.request.RegisterRequest;
import com.papairs.auth.dto.response.LoginResponse;
import com.papairs.auth.dto.response.SessionCreationResult;
import com.papairs.auth.dto.response.UserResponse;
import com.papairs.auth.exception.AuthenticationException;
import com.papairs.auth.exception.InvalidTokenException;
import com.papairs.auth.exception.UserAlreadyExistsException;
import com.papairs.auth.exception.UserDeactivatedException;
import com.papairs.auth.model.Session;
import com.papairs.auth.model.User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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
     * @param request registration request
     * @return User entity if successful, else throw exception
     */
    @Transactional
    public User register(RegisterRequest request) {
        if (userService.emailExists(request.email())) {
            throw new UserAlreadyExistsException("Email already registered");
        }

        return userService.createUser(request.email(), request.password())
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
     * @param request login request
     * @return LoginResponse with session token and user details, else throw exception
     */
    @Transactional
    public LoginResponse login(LoginRequest request) {
        User user = userService.findByEmail(request.email())
                .orElseThrow(() -> new AuthenticationException("Invalid credentials"));

        if (!userService.isActive(user)) {
            throw new UserDeactivatedException("Account is deactivated");
        }

        if (!userService.verifyPassword(request.password(), user.getPasswordHash())) {
            throw new AuthenticationException("Invalid credentials");
        }

        SessionCreationResult sessionResult = sessionService.createSession(user.getId());
        userService.updateLastLogin(user.getId());

        return new LoginResponse(
                sessionResult.token(),
                sessionResult.sessionId(),
                sessionResult.expiresAt(),
                UserResponse.from(user)
        );
    }

    /**
     * Logout user by deleting session
     * @param token unhashed session token
     * Does not throw error if session not found for security reasons
     */
    @Transactional
    public void logout(String token) {
        sessionService.deleteByToken(token);
    }

    /**
     * Validate session and return user information <p>
     * Firstly, check if session exists <p>
     * Check if session is expired, if so delete it <p>
     * Check if user exists <p>
     * Check if user is active, if not delete session <p>
     * Lastly, update session last active timestamp <p>
     * @param token session token
     * @return User entity if valid, else throw exception
     */
    @Transactional
    public User validateTokenForUser(String token) {
        Session session = sessionService.findByToken(token)
                .orElseThrow(() -> new InvalidTokenException("Invalid session token"));

        if (sessionService.isExpired(session)) {
            sessionService.delete(session);
            throw new InvalidTokenException("Session expired");
        }

        User user = userService.findById(session.getUserId())
                .orElseThrow(() -> new AuthenticationException("User not found for session"));

        if (!userService.isActive(user)) {
            sessionService.delete(session);
            throw new UserDeactivatedException("User account is deactivated");
        }

        sessionService.updateLastActive(session);

        return user;
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
    public ValidationResponse validateTokenBySession(String sessionId) {
        LocalDateTime now = LocalDateTime.now();

        Optional<String> userId = userService.findValidUserId(sessionId, now);

        if (userId.isPresent()) {
            sessionService.touchLastActive(sessionId, now);
            return new ValidationResponse(userId.get());
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
     * Change user password
     * TODO: Write custom annotation to validate newPassword and confirmPassword match to accumulate all validation errors in ChangePasswordRequest
     * @param token session token
     * @param request change password request
     */
    @Transactional
    public void changePassword(String token, ChangePasswordRequest request) {
        User user = validateTokenForUser(token);

        if (!request.isNewPasswordDifferent()) {
            throw new AuthenticationException("New password must be different from old password");
        }

        if (!request.isNewPasswordConfirmed()) {
            throw new AuthenticationException("New password and confirmation password do not match");
        }

        if (!userService.verifyPassword(request.oldPassword(), user.getPasswordHash())) {
            throw new AuthenticationException("Old password is incorrect");
        }

        userService.changePassword(user.getId(), request.newPassword());

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

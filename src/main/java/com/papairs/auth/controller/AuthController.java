package com.papairs.auth.controller;

import com.papairs.auth.dto.request.ChangePasswordRequest;
import com.papairs.auth.dto.request.LoginRequest;
import com.papairs.auth.dto.request.RegisterRequest;
import com.papairs.auth.dto.response.*;
import com.papairs.auth.exception.InvalidAuthHeaderException;
import com.papairs.auth.model.User;
import com.papairs.auth.service.AuthService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    /**
     * Login user
     * @param request login request
     * @return {@link LoginResponse} with user details and token or error message
     */
    @PostMapping("/login")
    @ResponseStatus(HttpStatus.OK)
    public LoginResponse login(@Valid @RequestBody LoginRequest request) {
        return authService.login(request);
    }

    /**
     * Logout user by invalidating session
     * Requires Authorization header: Bearer <token>
     * @param authHeader Authorization header containing Bearer token
     */
    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logout(@RequestHeader("Authorization") String authHeader) {
        String token = extractBearerToken(authHeader);
        authService.logout(token);
    }

    /**
     * Register a new user
     * @param request registration request
     * @return {@link UserResponse} with user details or error message
     * Does not return a sessionToken
     */
    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public UserResponse register(@Valid @RequestBody RegisterRequest request) {
        User user = authService.register(request);
        return UserResponse.from(user);
    }

    /**
     * Validate session token and return user information
     * Requires Authorization header: Bearer <token>
     * @param authHeader session token from Authorization header
     * @return {@link ValidationResponse} indicating if token is valid or not
     */
    @PostMapping("/validate")
    @ResponseStatus(HttpStatus.OK)
    public ValidationResponse validateToken(@RequestHeader("Authorization") String authHeader) {
        String token = extractBearerToken(authHeader);
        String userId = authService.validateTokenForUserId(token);
        return new ValidationResponse(userId);
    }

    /**
     * Change user password
     * Requires Authorization header: Bearer <token>
     * @param authHeader session token from Authorization header
     * @param request change password request
     */
    @PostMapping("/change-password")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void changePassword(
            @RequestHeader("Authorization") String authHeader,
            @Valid @RequestBody ChangePasswordRequest request
    ) {
        String token = extractBearerToken(authHeader);
        authService.changePassword(token, request);
    }

    /**
     * Delete user by userId (Internal use only)
     * @param userId user ID to delete
     */
    @DeleteMapping("/{userId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteUser(@PathVariable String userId) {
        authService.deleteUser(userId);
    }

    /**
     * Extract Bearer token from Authorization header
     * @param authHeader Authorization header value
     * @return extracted token
     */
    private String extractBearerToken(String authHeader) {
        if (authHeader == null || authHeader.isBlank()) {
            throw new InvalidAuthHeaderException("Authorization header is missing");
        }

        if (!authHeader.startsWith("Bearer ")) {
            throw new InvalidAuthHeaderException("Authorization header must start with 'Bearer '");
        }

        String token = authHeader.substring(7).trim();

        if (token.isBlank()) {
            throw new InvalidAuthHeaderException("Token is empty");
        }

        return token;
    }
}
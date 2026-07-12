package com.papairs.auth.controller;

import com.papairs.auth.dto.request.ChangePasswordRequest;
import com.papairs.auth.dto.request.LoginRequest;
import com.papairs.auth.dto.request.RegisterRequest;
import com.papairs.auth.dto.response.*;
import com.papairs.auth.model.User;
import com.papairs.auth.security.SessionPrincipal;
import com.papairs.auth.service.AuthService;
import com.papairs.auth.service.result.LoginResult;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
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
        LoginResult result = authService.login(request.email(), request.password());
        return new LoginResponse(
                result.session().token(),
                result.session().sessionId(),
                result.session().expiresAt(),
                UserResponse.from(result.user())
        );
    }

    /**
     * Logout user by invalidating session
     * Requires Authorization header: Bearer <token>
     * @param principal
     */
    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logout(@AuthenticationPrincipal SessionPrincipal principal) {
        authService.logoutBySessionId(principal.sessionId());
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
        User user = authService.register(request.email(), request.password());
        return UserResponse.from(user);
    }

    /**
     * Validate session token and return user information
     * Requires Authorization header: Bearer <token>
     * @param principal
     * @return {@link ValidationResponse} indicating if token is valid or not
     */
    @PostMapping("/validate")
    @ResponseStatus(HttpStatus.OK)
    public ValidationResponse validateToken(@AuthenticationPrincipal SessionPrincipal principal) {
        String userId = authService.validateTokenBySession(principal.sessionId());
        return new ValidationResponse(userId);
    }

    /**
     * Change password for authenticated user
     * Requires Authorization header: Bearer <token>
     * @param principal
     * @param request change password request containing old and new password
     */
    @PostMapping("/change-password")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void changePassword(
            @AuthenticationPrincipal SessionPrincipal principal,
            @Valid @RequestBody ChangePasswordRequest request
    ) {
        authService.changePasswordByUserId(principal.userId(), request.oldPassword(), request.newPassword());
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
}
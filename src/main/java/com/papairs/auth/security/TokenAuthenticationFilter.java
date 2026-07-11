package com.papairs.auth.security;

import com.papairs.auth.model.Session;
import com.papairs.auth.service.AuthService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class TokenAuthenticationFilter extends OncePerRequestFilter {

    private final AuthService authService;

    public TokenAuthenticationFilter(AuthService authService) {
        this.authService = authService;
    }

    /**
     * Extract Bearer token from Authorization header
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");

        if (authHeader != null && authHeader.regionMatches(true, 0, "Bearer ", 0, 7)) {

            String token = authHeader.substring(7).trim();

            if (!token.isBlank()) {
                try {
                    Session session = authService.findSessionByToken(token);
                    SessionPrincipal principal = new SessionPrincipal(session.getId(), session.getUserId());
                    SecurityContextHolder.getContext().setAuthentication(new SessionAuthenticationToken(principal));
                } catch (RuntimeException e) {
                    SecurityContextHolder.clearContext();
                }
            }
        }

        filterChain.doFilter(request, response);
    }
}

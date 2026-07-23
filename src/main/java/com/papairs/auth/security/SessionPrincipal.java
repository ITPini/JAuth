package com.papairs.auth.security;

public record SessionPrincipal(String sessionId, String userId) {}

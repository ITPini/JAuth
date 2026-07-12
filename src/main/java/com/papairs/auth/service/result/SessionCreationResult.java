package com.papairs.auth.service.result;

import java.time.LocalDateTime;

public record SessionCreationResult(
        String sessionId,
        String userId,
        String token,
        LocalDateTime expiresAt,
        LocalDateTime createdAt
) {}

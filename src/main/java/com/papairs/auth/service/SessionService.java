package com.papairs.auth.service;

import com.papairs.auth.dto.response.SessionCreationResult;
import com.papairs.auth.model.Session;
import com.papairs.auth.repository.SessionRepository;
import com.papairs.auth.security.TokenHasher;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

@Service
public class SessionService {

    @Value("${session.duration.hours:24}")
    private int sessionDurationHours;
    private final SessionRepository sessionRepository;
    private final SecureRandom secureRandom;
    private final TokenHasher tokenHasher;

    public SessionService(SessionRepository sessionRepository, TokenHasher tokenHasher) {
        this.sessionRepository = sessionRepository;
        this.tokenHasher = tokenHasher;
        this.secureRandom = new SecureRandom();
    }

    /**
     * Create a new session for a user
     * @param userId user ID
     * @return Session entity
     */
    @Transactional
    public SessionCreationResult createSession(String userId) {
        String plaintextToken = generateSecureToken();
        String tokenHash = tokenHasher.hash(plaintextToken);

        Session session = new Session();
        session.setId(UUID.randomUUID().toString());
        session.setUserId(userId);
        session.setTokenHash(tokenHash);
        session.setExpiresAt(LocalDateTime.now().plusHours(sessionDurationHours));
        session.setCreatedAt(LocalDateTime.now());
        session.setLastActiveAt(LocalDateTime.now());

        sessionRepository.save(session);

        return new SessionCreationResult(
                session.getId(),
                session.getUserId(),
                plaintextToken,
                session.getExpiresAt(),
                session.getCreatedAt()
        );
    }

    /**
     * Find a session by its token
     * Hashes the incoming plaintext token and looks up by hash
     * @param token session token
     * @return Optional<Session> if found, else empty
     */
    public Optional<Session> findByToken(String token) {
        return sessionRepository.findByTokenHash(tokenHasher.hash(token));
    }

    /**
     * Find a session by its ID
     * @param sessionId session ID
     * @return Optional<Session> if found, else empty
     */
    public Optional<Session> findById(String sessionId) {
        return sessionRepository.findById(sessionId);
    }

    /**
     * Update the last active timestamp of a session
     * @param sessionId session ID
     */
    @Transactional
    public void touchLastActive(String sessionId, LocalDateTime now) {
        sessionRepository.touchIfStale(sessionId, now, now.minusMinutes(5));
    }

    /**
     * Check if a session is expired
     * @param session Session entity
     * @return true if expired, else false
     */
    public boolean isExpired(Session session) {
        return session.getExpiresAt().isBefore(LocalDateTime.now());
    }

    /**
     * Delete a session by unhashed token (logout)
     * @param token unhashed session token
     */
    @Transactional
    public void deleteByToken(String token) {
        sessionRepository.deleteByTokenHash(tokenHasher.hash(token));
    }

    /**
     * Delete a specific session entity
     * @param session Session entity
     */
    @Transactional
    public void delete(Session session) {
        sessionRepository.delete(session);
    }

    /**
     * Delete all user sessions
     * @param userId user ID
     */
    @Transactional
    public void deleteAllUserSessions(String userId) {
        sessionRepository.deleteByUserId(userId);
    }

    /**
     * Delete all expired sessions (clean-up)
     */
    @Transactional
    public int deleteExpiredSessions() {
        return sessionRepository.deleteByExpiresAtBefore(LocalDateTime.now());
    }

    /**
     * Generate a cryptographically secure random token
     * @return secure random token string
     */
    private String generateSecureToken() {
        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }
}

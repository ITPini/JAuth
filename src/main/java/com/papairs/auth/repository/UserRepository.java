package com.papairs.auth.repository;

import com.papairs.auth.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, String> {

    /**
     * Find user by email address
     * @param email email address
     * @return Optional<User> if found, else empty
     */
    Optional<User> findByEmail(String email);

    /**
     * Check if email exists in database
     * @param email email address
     * @return true if exists, else false
     */
    boolean existsByEmail(String email);

    /**
     * Find all active users
     * @return List of active users
     */
    List<User> findByIsActiveTrue();

    /**
     * Find users by email verification status
     * @param verified email with verified status
     * @return List of users with the given email verification status
     */
    List<User> findByEmailVerified(boolean verified);

    /**
     * Update last login timestamp
     * @param userId user ID
     * @param loginTime login timestamp
     */
    @Modifying
    @Transactional
    @Query("UPDATE User u SET u.lastLoginAt = :loginTime WHERE u.id = :userId")
    void updateLastLoginAt(@Param("userId") String userId, @Param("loginTime") LocalDateTime loginTime);

    /**
     * Activate/Deactivate user account
     * @param userId user ID
     * @param active active status
     * @return number of rows affected
     */
    @Modifying
    @Transactional
    @Query("UPDATE User u SET u.isActive = :active WHERE u.id = :userId")
    int updateUserActiveStatus(@Param("userId") String userId, @Param("active") boolean active);

    /**
     * Mark email as verified
     * @param userId user ID
     * @return number of rows affected
     */
    @Modifying
    @Transactional
    @Query("UPDATE User u SET u.emailVerified = true WHERE u.id = :userId")
    int markEmailAsVerified(@Param("userId") String userId);

    /**
     * Update user password hash
     * @param userId user ID
     * @param passwordHash new password hash
     */
    @Modifying
    @Transactional
    @Query("UPDATE User u SET u.passwordHash = :passwordHash WHERE u.id = :userId")
    void updatePasswordHash(@Param("userId") String userId, @Param("passwordHash") String passwordHash);

    /**
     * Check if active user exists by ID
     * @param userId user ID
     * @return true if exists, false otherwise
     */
    boolean existsByIdAndIsActiveTrue(String userId);

    /**
     * Finds the user ID associated with a valid session.
     * @param sessionId session ID
     * @param now the current timestamp used to check session expiry
     * @return an {@link Optional} containing the user ID if the session is valid, or empty otherwise
     */
    @Query("""
    SELECT s.userId
    FROM Session s
    JOIN User u ON u.id = s.userId
    WHERE s.id = :sessionId
      AND s.expiresAt > :now
      AND u.isActive = true
    """)
    Optional<String> findValidUserId(String sessionId, LocalDateTime now);
}

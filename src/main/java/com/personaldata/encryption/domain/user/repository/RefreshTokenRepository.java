package com.personaldata.encryption.domain.user.repository;

import com.personaldata.encryption.domain.user.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

/**
 * 리프레시 토큰 정보에 접근하는 리포지토리
 */
@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    /**
     * 사용자 ID로 리프레시 토큰 조회
     *
     * @param userId 사용자 ID
     * @return 리프레시 토큰 (Optional)
     */
    Optional<RefreshToken> findByUserId(Long userId);

    /**
     * 토큰 값으로 리프레시 토큰 조회
     *
     * @param token 리프레시 토큰 값
     * @return 리프레시 토큰 (Optional)
     */
    Optional<RefreshToken> findByToken(String token);

    /**
     * 사용자 ID로 리프레시 토큰 삭제
     *
     * @param userId 사용자 ID
     */
    void deleteByUserId(Long userId);

    /**
     * 만료된 리프레시 토큰 삭제
     *
     * @param now 현재 시간
     * @return 삭제된 레코드 수
     */
    @Modifying
    @Query("DELETE FROM RefreshToken r WHERE r.expiresAt < :now")
    int deleteExpiredTokens(@Param("now") LocalDateTime now);

    /**
     * 토큰 값 유효성 검사 (존재 및 만료 여부 확인)
     *
     * @param token 리프레시 토큰 값
     * @param now 현재 시간
     * @return 유효한 토큰이 존재하면 true
     */
    @Query("SELECT COUNT(r) > 0 FROM RefreshToken r WHERE r.token = :token AND r.expiresAt > :now")
    boolean isTokenValid(@Param("token") String token, @Param("now") LocalDateTime now);
}
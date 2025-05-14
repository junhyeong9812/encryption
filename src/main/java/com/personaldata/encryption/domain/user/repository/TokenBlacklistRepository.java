package com.personaldata.encryption.domain.user.repository;

import com.personaldata.encryption.domain.user.entity.TokenBlacklist;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;

/**
 * 토큰 블랙리스트에 접근하는 리포지토리
 */
@Repository
public interface TokenBlacklistRepository extends JpaRepository<TokenBlacklist, Long> {

    /**
     * 토큰이 블랙리스트에 존재하는지 확인
     *
     * @param token 토큰
     * @return 블랙리스트에 존재하면 true
     */
    boolean existsByToken(String token);

    /**
     * 만료된 블랙리스트 토큰 제거
     *
     * @param now 현재 시간
     * @return 삭제된 레코드 수
     */
    @Modifying
    @Query("DELETE FROM TokenBlacklist tb WHERE tb.expiresAt < :now")
    int deleteExpiredTokens(@Param("now") LocalDateTime now);
}
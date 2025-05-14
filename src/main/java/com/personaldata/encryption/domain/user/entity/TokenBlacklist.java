package com.personaldata.encryption.domain.user.entity;

import com.personaldata.encryption.global.entity.BaseEntity;
import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * 블랙리스트에 등록된 토큰 정보를 저장하는 엔티티
 * 로그아웃하거나 보안 상의 이유로 무효화된 토큰을 관리합니다.
 */
@Entity
@Table(name = "token_blacklist")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class TokenBlacklist extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * 블랙리스트에 등록된 토큰
     */
    @Column(name = "token", nullable = false, length = 500)
    private String token;

    /**
     * 토큰 만료 일시
     * 만료된 토큰은 블랙리스트에서 자동 삭제 가능
     */
    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    /**
     * 토큰 무효화 사유
     */
    @Column(name = "reason", length = 100)
    private String reason;

    /**
     * 생성자
     */
    @Builder
    public TokenBlacklist(String token, LocalDateTime expiresAt, String reason) {
        this.token = token;
        this.expiresAt = expiresAt;
        this.reason = reason;
    }

    /**
     * 토큰 만료 여부 확인
     *
     * @return 만료 여부
     */
    public boolean isExpired() {
        return LocalDateTime.now().isAfter(this.expiresAt);
    }
}
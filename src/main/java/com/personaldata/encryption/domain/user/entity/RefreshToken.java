package com.personaldata.encryption.domain.user.entity;

import com.personaldata.encryption.global.entity.BaseEntity;
import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * 리프레시 토큰 정보를 저장하는 엔티티
 * 사용자의 리프레시 토큰을 관리하고 토큰 갱신을 지원합니다.
 */
@Entity
@Table(name = "refresh_tokens")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class RefreshToken extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * 사용자 ID (User 엔티티와의 연관관계)
     */
    @Column(name = "user_id", nullable = false, unique = true)
    private Long userId;

    /**
     * 리프레시 토큰 값
     */
    @Column(name = "token", nullable = false, length = 500)
    private String token;

    /**
     * 토큰 만료 일시
     */
    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    /**
     * 생성자
     */
    @Builder
    public RefreshToken(Long userId, String token, LocalDateTime expiresAt) {
        this.userId = userId;
        this.token = token;
        this.expiresAt = expiresAt;
    }

    /**
     * 토큰 값과 만료 일시 업데이트
     *
     * @param token 새 리프레시 토큰
     * @param expiresAt 새 만료 일시
     * @return 업데이트된 RefreshToken 엔티티
     */
    public RefreshToken updateToken(String token, LocalDateTime expiresAt) {
        this.token = token;
        this.expiresAt = expiresAt;
        return this;
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
package com.personaldata.encryption.global.security;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * JWT 토큰 정보를 담는 DTO 클래스
 */
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TokenInfo {

    /**
     * 토큰 타입 (Bearer)
     */
    private String grantType;

    /**
     * 액세스 토큰
     */
    private String accessToken;

    /**
     * 리프레시 토큰
     */
    private String refreshToken;

    /**
     * 액세스 토큰 만료 시간 (초)
     */
    private Long accessTokenExpiresIn;
}
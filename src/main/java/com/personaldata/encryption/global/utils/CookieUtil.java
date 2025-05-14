package com.personaldata.encryption.global.utils;

import com.personaldata.encryption.global.security.TokenInfo;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * 인증 관련 쿠키 처리 유틸리티
 */
@Slf4j
@Component
public class CookieUtil {

    @Value("${jwt.cookie.domain}")
    private String cookieDomain;

    @Value("${jwt.cookie.secure}")
    private boolean secureCookie;

    /**
     * 액세스 토큰과 리프레시 토큰을 HTTP-only 쿠키로 설정
     *
     * @param response   HTTP 응답 객체
     * @param tokenInfo  토큰 정보
     */
    public void addAuthCookies(HttpServletResponse response, TokenInfo tokenInfo) {
        // 액세스 토큰 쿠키
        addCookie(response, "access_token", tokenInfo.getAccessToken(),
                tokenInfo.getAccessTokenExpiresIn().intValue(), "/");

        // 리프레시 토큰 쿠키 (리프레시 엔드포인트에서만 접근 가능)
        addCookie(response, "refresh_token", tokenInfo.getRefreshToken(),
                60 * 60 * 24 * 14, "/api/auth/web/refresh");

        log.debug("인증 쿠키 추가 완료");
    }

    /**
     * 인증 쿠키 삭제 (로그아웃 시 사용)
     *
     * @param response HTTP 응답 객체
     */
    public void clearAuthCookies(HttpServletResponse response) {
        // 액세스 토큰 쿠키 삭제
        deleteCookie(response, "access_token", "/");

        // 리프레시 토큰 쿠키 삭제
        deleteCookie(response, "refresh_token", "/api/auth/web/refresh");

        log.debug("인증 쿠키 삭제 완료");
    }

    /**
     * HTTP-only 쿠키 추가
     *
     * @param response  HTTP 응답 객체
     * @param name      쿠키 이름
     * @param value     쿠키 값
     * @param maxAge    쿠키 유효 시간 (초)
     * @param path      쿠키 경로
     */
    private void addCookie(HttpServletResponse response, String name, String value, int maxAge, String path) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);
        cookie.setSecure(secureCookie);  // HTTPS 환경에서만 true로 설정
        cookie.setMaxAge(maxAge);
        cookie.setPath(path);

        if (cookieDomain != null && !cookieDomain.isEmpty()) {
            cookie.setDomain(cookieDomain);
        }

        // SameSite 속성 설정 (CSRF 방지)
        response.setHeader("Set-Cookie", response.getHeader("Set-Cookie") + "; SameSite=Strict");

        response.addCookie(cookie);
        log.debug("쿠키 추가: name={}, path={}, maxAge={}, secure={}", name, path, maxAge, secureCookie);
    }

    /**
     * 쿠키 삭제
     *
     * @param response  HTTP 응답 객체
     * @param name      쿠키 이름
     * @param path      쿠키 경로
     */
    private void deleteCookie(HttpServletResponse response, String name, String path) {
        Cookie cookie = new Cookie(name, "");
        cookie.setHttpOnly(true);
        cookie.setSecure(secureCookie);
        cookie.setMaxAge(0);  // 즉시 만료
        cookie.setPath(path);

        if (cookieDomain != null && !cookieDomain.isEmpty()) {
            cookie.setDomain(cookieDomain);
        }

        response.addCookie(cookie);
        log.debug("쿠키 삭제: name={}, path={}", name, path);
    }
}
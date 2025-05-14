package com.personaldata.encryption.global.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.Optional;

/**
 * JWT 인증 필터
 * 클라이언트 유형에 따라 다른 방식으로 토큰을 추출하고 인증합니다.
 * - 웹 클라이언트: HTTP-only 쿠키에서 토큰 추출
 * - 모바일 클라이언트: Authorization 헤더에서 토큰 추출
 */
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;

    @Value("${jwt.cookie.token-source-priority:cookie-first}")
    private String tokenSourcePriority;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        try {
            // 요청 경로 확인
            String requestPath = request.getRequestURI();

            // 토큰 추출 (클라이언트 유형에 따라 다른 소스에서 추출)
            String jwt = null;

            // 쿠키 우선 방식(기본값) 또는 헤더 우선 방식에 따라 토큰 소스 결정
            if ("cookie-first".equals(tokenSourcePriority)) {
                // 1. 먼저 쿠키에서 토큰 추출 시도
                jwt = extractTokenFromCookie(request, "access_token");

                // 2. 쿠키에 토큰이 없으면 헤더에서 추출 시도
                if (!StringUtils.hasText(jwt)) {
                    jwt = extractTokenFromHeader(request);
                    if (StringUtils.hasText(jwt)) {
                        log.debug("헤더에서 토큰 추출 성공");
                    }
                } else {
                    log.debug("쿠키에서 토큰 추출 성공");
                }
            } else { // header-first
                // 1. 먼저 헤더에서 토큰 추출 시도
                jwt = extractTokenFromHeader(request);

                // 2. 헤더에 토큰이 없으면 쿠키에서 추출 시도
                if (!StringUtils.hasText(jwt)) {
                    jwt = extractTokenFromCookie(request, "access_token");
                    if (StringUtils.hasText(jwt)) {
                        log.debug("쿠키에서 토큰 추출 성공");
                    }
                } else {
                    log.debug("헤더에서 토큰 추출 성공");
                }
            }

            // 토큰이 있고 유효한 경우 인증 정보 설정
            if (StringUtils.hasText(jwt) && jwtTokenProvider.validateToken(jwt)) {
                // 토큰에서 인증 정보 추출하여 SecurityContext에 설정
                Authentication authentication = jwtTokenProvider.getAuthentication(jwt);
                SecurityContextHolder.getContext().setAuthentication(authentication);
                log.debug("토큰 인증 성공: {}", authentication.getName());
            } else if (StringUtils.hasText(jwt)) {
                log.debug("유효하지 않은 JWT 토큰");
            } else {
                log.debug("JWT 토큰이 없습니다. 인증이 필요한 엔드포인트는 접근이 제한됩니다.");
            }
        } catch (Exception e) {
            log.error("인증 처리 중 예상치 못한 오류 발생: {}", e.getMessage(), e);
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }

    /**
     * HTTP 요청 헤더에서 토큰 추출
     *
     * @param request HTTP 요청
     * @return JWT 토큰 (없는 경우 null)
     */
    private String extractTokenFromHeader(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            String token = bearerToken.substring(7);
            log.debug("Authorization 헤더에서 토큰 추출: {}", maskToken(token));
            return token;
        }
        return null;
    }

    /**
     * HTTP 요청 쿠키에서 토큰 추출
     *
     * @param request HTTP 요청
     * @param cookieName 쿠키 이름
     * @return JWT 토큰 (없는 경우 null)
     */
    private String extractTokenFromCookie(HttpServletRequest request, String cookieName) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            Optional<Cookie> tokenCookie = Arrays.stream(cookies)
                    .filter(cookie -> cookieName.equals(cookie.getName()))
                    .findFirst();

            if (tokenCookie.isPresent()) {
                String token = tokenCookie.get().getValue();
                log.debug("쿠키에서 토큰 추출: {}", maskToken(token));
                return token;
            }
        }
        return null;
    }

    /**
     * 로그 출력용 토큰 마스킹
     *
     * @param token 원본 토큰
     * @return 마스킹된 토큰
     */
    private String maskToken(String token) {
        if (token == null || token.length() < 10) {
            return "***";
        }
        return token.substring(0, 5) + "..." + token.substring(token.length() - 5);
    }
}
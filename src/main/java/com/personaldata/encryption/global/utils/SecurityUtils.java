package com.personaldata.encryption.global.utils;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * 보안 관련 유틸리티 클래스
 * SecurityContext에서 인증 정보를 쉽게 가져오기 위한 정적 메서드 제공
 */
@Slf4j
public class SecurityUtils {

    /**
     * SecurityContext에서 현재 인증된 사용자의 이메일 추출
     *
     * @return 인증된 사용자의 이메일
     * @throws IllegalStateException 인증된 사용자가 없는 경우
     */
    public static String getCurrentUserEmail() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null && authentication.isAuthenticated() &&
                !authentication.getPrincipal().equals("anonymousUser")) {
            return authentication.getName();
        }

        log.warn("인증된 사용자 정보를 찾을 수 없습니다.");
        throw new IllegalStateException("인증된 사용자 정보를 찾을 수 없습니다.");
    }

    /**
     * SecurityContext에서 현재 인증된 사용자의 이메일 추출 (익명 허용)
     * 인증된 사용자가 없는 경우 "anonymous" 반환
     *
     * @return 인증된 사용자의 이메일 또는 "anonymous"
     */
    public static String getCurrentUserEmailOrAnonymous() {
        try {
            return getCurrentUserEmail();
        } catch (IllegalStateException e) {
            log.debug("인증되지 않은 사용자, 'anonymous' 반환");
            return "anonymous";
        }
    }

    /**
     * SecurityContext에서 현재 인증된 사용자의 ID 추출
     *
     * @return 인증된 사용자의 ID
     * @throws IllegalStateException 인증된 사용자가 없거나 ID를 찾을 수 없는 경우
     */
    public static Long getCurrentUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null && authentication.isAuthenticated() &&
                authentication.getDetails() instanceof Long) {
            return (Long) authentication.getDetails();
        }

        log.warn("인증된 사용자 ID 정보를 찾을 수 없습니다.");
        throw new IllegalStateException("인증된 사용자 ID 정보를 찾을 수 없습니다.");
    }

    /**
     * SecurityContext에서 현재 인증된 사용자의 ID 추출 (null 허용)
     * 인증된 사용자가 없는 경우 null 반환
     *
     * @return 인증된 사용자의 ID 또는 null
     */
    public static Long getCurrentUserIdOrNull() {
        try {
            return getCurrentUserId();
        } catch (IllegalStateException e) {
            log.debug("인증된 사용자 ID 정보를 찾을 수 없어 null 반환");
            return null;
        }
    }

    /**
     * 현재 인증된 사용자가 관리자인지 확인
     *
     * @return 관리자 여부
     */
    public static boolean isCurrentUserAdmin() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null && authentication.isAuthenticated()) {
            return authentication.getAuthorities().stream()
                    .anyMatch(authority -> authority.getAuthority().equals("ROLE_ADMIN"));
        }

        return false;
    }

    /**
     * 현재 인증된 사용자가 특정 역할을 가지고 있는지 확인
     *
     * @param role 확인할 역할 (예: "ROLE_USER", "ROLE_ADMIN")
     * @return 해당 역할 보유 여부
     */
    public static boolean hasRole(String role) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null && authentication.isAuthenticated()) {
            return authentication.getAuthorities().stream()
                    .anyMatch(authority -> authority.getAuthority().equals(role));
        }

        return false;
    }

    /**
     * 현재 요청이 인증된 사용자에 의한 것인지 확인
     *
     * @return 인증된 사용자 여부
     */
    public static boolean isAuthenticated() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication != null && authentication.isAuthenticated() &&
                !authentication.getPrincipal().equals("anonymousUser");
    }
}
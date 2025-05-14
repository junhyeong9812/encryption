package com.personaldata.encryption.domain.user.entity.enums;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * 사용자 역할을 정의하는 열거형 클래스
 * Spring Security에서 인증 및 권한 관리에 사용됩니다.
 */
@Getter
@RequiredArgsConstructor
public enum UserRole {
    USER("ROLE_USER", "일반 사용자"),
    ADMIN("ROLE_ADMIN", "관리자");

    private final String key;
    private final String description;

    /**
     * 문자열로 된 역할 키를 UserRole 열거형으로 변환
     *
     * @param key 역할 키 문자열 (예: "ROLE_USER")
     * @return 해당하는 UserRole 열거형 값, 없으면 USER 반환
     */
    public static UserRole fromKey(String key) {
        for (UserRole role : UserRole.values()) {
            if (role.getKey().equals(key)) {
                return role;
            }
        }
        return USER; // 기본값은 USER
    }
}
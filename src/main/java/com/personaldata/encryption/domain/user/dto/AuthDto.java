package com.personaldata.encryption.domain.user.dto;

import com.personaldata.encryption.global.security.TokenInfo;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * 인증 관련 DTO 모음
 */
public class AuthDto {

    /**
     * 회원가입 요청 DTO
     */
    @Getter
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class SignupRequest {

        @NotBlank(message = "이름은 필수 입력값입니다.")
        @Size(min = 2, max = 50, message = "이름은 2~50자 사이여야 합니다.")
        private String name;

        @NotBlank(message = "이메일은 필수 입력값입니다.")
        @Email(message = "이메일 형식이 올바르지 않습니다.")
        private String email;

        @NotBlank(message = "비밀번호는 필수 입력값입니다.")
        @Size(min = 8, max = 100, message = "비밀번호는 8자 이상이어야 합니다.")
        @Pattern(regexp = "^(?=.*[a-zA-Z])(?=.*[0-9])(?=.*[!@#$%^&*])[a-zA-Z0-9!@#$%^&*]{8,}$",
                message = "비밀번호는 영문, 숫자, 특수문자를 포함해야 합니다.")
        private String password;

        @NotBlank(message = "전화번호는 필수 입력값입니다.")
        @Pattern(regexp = "^[0-9]{10,11}$", message = "전화번호 형식이 올바르지 않습니다.")
        private String phone;

        private String ssn; // 주민등록번호 (선택)

        private AddressDto address; // 주소 정보 (선택)
    }

    /**
     * 웹 클라이언트용 응답 DTO (토큰 정보 제외)
     */
    @Getter
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class WebResponseDto {
        private String email;
        private String role;
        private String maskedName;
        private boolean authenticated;
    }

    /**
     * 모바일 클라이언트용 응답 DTO (토큰 정보 포함)
     */
    @Getter
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class MobileResponseDto {
        private String email;
        private String role;
        private String maskedName;
        private TokenInfo token; // JWT 토큰 정보
    }

    /**
     * 로그인 요청 DTO
     */
    @Getter
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class LoginRequest {

        @NotBlank(message = "이메일은 필수 입력값입니다.")
        @Email(message = "이메일 형식이 올바르지 않습니다.")
        private String email;

        @NotBlank(message = "비밀번호는 필수 입력값입니다.")
        private String password;
    }

    /**
     * 비밀번호 변경 요청 DTO
     */
    @Getter
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class PasswordChangeRequest {

        @NotBlank(message = "현재 비밀번호는 필수 입력값입니다.")
        private String currentPassword;

        @NotBlank(message = "새 비밀번호는 필수 입력값입니다.")
        @Size(min = 8, max = 100, message = "비밀번호는 8자 이상이어야 합니다.")
        @Pattern(regexp = "^(?=.*[a-zA-Z])(?=.*[0-9])(?=.*[!@#$%^&*])[a-zA-Z0-9!@#$%^&*]{8,}$",
                message = "비밀번호는 영문, 숫자, 특수문자를 포함해야 합니다.")
        private String newPassword;

        @NotBlank(message = "비밀번호 확인은 필수 입력값입니다.")
        private String confirmPassword;
    }

    /**
     * 토큰 갱신 요청 DTO
     */
    @Getter
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class TokenRefreshRequest {

        @NotBlank(message = "리프레시 토큰은 필수 입력값입니다.")
        private String refreshToken;
    }
}
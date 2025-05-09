package com.personaldata.encryption.domain.user.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 인증 관련 DTO 클래스들
 */
public class AuthDto {

    /**
     * 로그인 요청 DTO
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class LoginRequest {

        @NotBlank(message = "이메일은 필수 항목입니다.")
        @Email(message = "유효한 이메일 형식이 아닙니다.")
        private String email;

        @NotBlank(message = "비밀번호는 필수 항목입니다.")
        private String password;
    }

    /**
     * 회원가입 요청 DTO
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class SignupRequest {

        @NotBlank(message = "이름은 필수 항목입니다.")
        @Size(min = 2, max = 50, message = "이름은 2자 이상 50자 이하로 입력해주세요.")
        private String name;

        @NotBlank(message = "전화번호는 필수 항목입니다.")
        @Pattern(regexp = "^(01[016789])-?(\\d{3,4})-?(\\d{4})$", message = "유효한 전화번호 형식이 아닙니다.")
        private String phone;

        @Pattern(regexp = "^\\d{2}(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])-?[1-4]\\d{6}$",
                message = "유효한 주민등록번호 형식이 아닙니다.")
        private String ssn;

        @NotBlank(message = "이메일은 필수 항목입니다.")
        @Email(message = "유효한 이메일 형식이 아닙니다.")
        private String email;

        @NotBlank(message = "비밀번호는 필수 항목입니다.")
        @Size(min = 8, max = 100, message = "비밀번호는 8자 이상이어야 합니다.")
        @Pattern(regexp = "^(?=.*[a-zA-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$",
                message = "비밀번호는 영문자, 숫자, 특수문자를 포함해야 합니다.")
        private String password;

        // 주소 정보 (선택 사항)
        private AddressDto address;
    }

    /**
     * 비밀번호 변경 요청 DTO
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class PasswordChangeRequest {

        @NotBlank(message = "현재 비밀번호는 필수 항목입니다.")
        private String currentPassword;

        @NotBlank(message = "새 비밀번호는 필수 항목입니다.")
        @Size(min = 8, max = 100, message = "비밀번호는 8자 이상이어야 합니다.")
        @Pattern(regexp = "^(?=.*[a-zA-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$",
                message = "비밀번호는 영문자, 숫자, 특수문자를 포함해야 합니다.")
        private String newPassword;

        @NotBlank(message = "비밀번호 확인은 필수 항목입니다.")
        private String confirmPassword;
    }

    /**
     * 로그인 응답 DTO
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class LoginResponse {

        private String email;
        private String role;
        private String maskedName;  // 민감 정보는 마스킹 처리하여 응답
    }
}
package com.personaldata.encryption.domain.user.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 사용자 정보 수정 요청 DTO
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserUpdateRequestDto {

    @NotBlank(message = "이름은 필수 입력 항목입니다")
    private String name;

    @NotBlank(message = "전화번호는 필수 입력 항목입니다")
    private String phone;

    @Email(message = "유효한 이메일 형식이어야 합니다")
    @NotBlank(message = "이메일은 필수 입력 항목입니다")
    private String email;

    private AddressDto address;
}
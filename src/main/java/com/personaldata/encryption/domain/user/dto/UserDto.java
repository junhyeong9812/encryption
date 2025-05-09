package com.personaldata.encryption.domain.user.dto;

import com.personaldata.encryption.domain.user.entity.User;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 사용자 정보 전송 객체
 * 암호화된 데이터와 복호화된 데이터를 모두 포함
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserDto {

    private Long id;

    // 복호화된 이름 (UI 표시용)
    private String name;

    // 마스킹된 이름 (UI 표시용)
    private String maskedName;

    // 복호화된 전화번호 (UI 표시용)
    private String phone;

    // 마스킹된 전화번호 (UI 표시용)
    private String maskedPhone;

    // 복호화된 주민등록번호 (UI 표시용)
    private String ssn;

    // 마스킹된 주민등록번호 (UI 표시용)
    private String maskedSsn;

    // 이메일 (평문)
    private String email;

    // 주소 정보
    private AddressDto address;

    /**
     * 엔티티를 DTO로 변환 (복호화된 정보 포함)
     */
    public static UserDto fromEntity(User user, String decryptedName, String decryptedPhone, String decryptedSsn) {
        return UserDto.builder()
                .id(user.getId())
                .name(decryptedName)
                .maskedName(maskName(decryptedName))
                .phone(decryptedPhone)
                .maskedPhone(maskPhone(decryptedPhone))
                .ssn(decryptedSsn)
                .maskedSsn(maskSsn(decryptedSsn))
                .email(user.getEmail())
                .address(user.getAddress() != null ? AddressDto.fromEntity(user.getAddress()) : null)
                .build();
    }

    /**
     * 엔티티를 DTO로 변환 (복호화된 정보 제외 - SSN 추가)
     */
    public static UserDto fromEntity(User user, String decryptedName, String decryptedPhone) {
        return UserDto.builder()
                .id(user.getId())
                .name(decryptedName)
                .maskedName(maskName(decryptedName))
                .phone(decryptedPhone)
                .maskedPhone(maskPhone(decryptedPhone))
                .maskedSsn("******-*******") // SSN 정보 없이 마스킹
                .email(user.getEmail())
                .address(user.getAddress() != null ? AddressDto.fromEntity(user.getAddress()) : null)
                .build();
    }

    /**
     * 엔티티를 DTO로 변환 (마스킹된 정보만 포함 - 민감 정보 제외)
     */
    public static UserDto fromEntityMasked(User user) {
        return UserDto.builder()
                .id(user.getId())
                .maskedName("***") // 실제 이름 대신 마스킹 처리
                .maskedPhone("***-****-****") // 실제 번호 대신 마스킹 처리
                .maskedSsn("******-*******") // 실제 주민번호 대신 마스킹 처리
                .email(user.getEmail())
                .address(user.getAddress() != null ? AddressDto.fromEntityMasked(user.getAddress()) : null)
                .build();
    }

    /**
     * 이름 마스킹 처리
     */
    private static String maskName(String name) {
        if (name == null || name.length() <= 1) {
            return "***";
        }

        // 첫 글자만 표시하고 나머지는 *로 마스킹
        return name.substring(0, 1) + "*".repeat(name.length() - 1);
    }

    /**
     * 전화번호 마스킹 처리
     */
    private static String maskPhone(String phone) {
        if (phone == null || phone.length() < 7) {
            return "***-****-****";
        }

        // 전화번호 형식에 따라 마스킹 처리
        String[] parts = phone.split("-");
        if (parts.length == 3) {
            // xxx-xxxx-xxxx 형식
            return parts[0] + "-****-" + parts[2];
        } else {
            // 그 외 형식
            int length = phone.length();
            String prefix = phone.substring(0, 3);
            String suffix = phone.substring(length - 4);
            return prefix + "-****-" + suffix;
        }
    }

    /**
     * 주민등록번호 마스킹 처리
     */
    private static String maskSsn(String ssn) {
        if (ssn == null || ssn.length() < 7) {
            return "******-*******";
        }

        // 주민등록번호 형식에 따라 마스킹 처리
        String[] parts = ssn.split("-");
        if (parts.length == 2) {
            // xxxxxx-xxxxxxx 형식
            return parts[0] + "-*******";
        } else {
            // 그 외 형식일 경우
            if (ssn.length() == 13) {
                return ssn.substring(0, 6) + "-*******";
            } else {
                return "******-*******"; // 알 수 없는 형식이면 전체 마스킹
            }
        }
    }
}
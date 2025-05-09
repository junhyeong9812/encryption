package com.personaldata.encryption.domain.user.dto;

import com.personaldata.encryption.domain.user.entity.Address;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 주소 정보 전송 객체
 * 암호화된 데이터와 복호화된 데이터를 모두 포함
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AddressDto {

    private Long id;

    // 우편번호
    private String zipCode;

    // 시/도 (평문)
    private String region;

    // 시/도 코드
    private String regionCode;

    // 구/군 (평문)
    private String city;

    // 구/군 코드
    private String cityCode;

    // 복호화된 상세 주소 (UI 표시용)
    private String detail;

    // 마스킹된 상세 주소 (UI 표시용)
    private String maskedDetail;

    /**
     * 엔티티를 DTO로 변환 (복호화된 정보 포함)
     */
    public static AddressDto fromEntity(Address address) {
        return AddressDto.builder()
                .id(address.getId())
                .zipCode(address.getZipCode())
                .region(address.getRegion())
                .regionCode(address.getRegionCode())
                .city(address.getCity())
                .cityCode(address.getCityCode())
                .build();
    }

    /**
     * 엔티티를 DTO로 변환 (마스킹된 정보만 포함 - 민감 정보 제외)
     */
    public static AddressDto fromEntityMasked(Address address) {
        return AddressDto.builder()
                .id(address.getId())
                .zipCode(address.getZipCode())
                .region(address.getRegion())
                .regionCode(address.getRegionCode())
                .city(address.getCity())
                .cityCode(address.getCityCode())
                .maskedDetail("*****") // 실제 상세 주소 대신 마스킹 처리
                .build();
    }

    /**
     * 엔티티를 DTO로 변환 (복호화된 상세 주소 포함)
     */
    public static AddressDto fromEntityWithDetail(Address address, String decryptedDetail) {
        AddressDto dto = fromEntity(address);
        dto.setDetail(decryptedDetail);
        dto.setMaskedDetail(maskDetail(decryptedDetail));
        return dto;
    }

    /**
     * 상세 주소 마스킹 처리
     */
    private static String maskDetail(String detail) {
        if (detail == null || detail.isEmpty()) {
            return "*****";
        }

        // 상세 주소의 일부만 표시하고 나머지는 *로 마스킹
        int visibleLength = Math.min(5, detail.length() / 3);
        return detail.substring(0, visibleLength) + "*".repeat(detail.length() - visibleLength);
    }
}
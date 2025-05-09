package com.personaldata.encryption.domain.user.entity;

import com.personaldata.encryption.global.entity.BaseEntity;
import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * 주소 정보를 저장하는 엔티티
 * 암호화된 상세 주소와 검색용 지역 정보를 함께 관리
 */
@Entity
@Table(name = "addresses")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Address extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * 우편번호
     */
    @Column(name = "zip_code")
    private String zipCode;

    /**
     * 시/도 (평문 저장, 검색용)
     */
    @Column(name = "region")
    private String region;

    /**
     * 시/도 코드 (검색용)
     */
    @Column(name = "region_code")
    private String regionCode;

    /**
     * 구/군 (평문 저장, 검색용)
     */
    @Column(name = "city")
    private String city;

    /**
     * 구/군 코드 (검색용)
     */
    @Column(name = "city_code")
    private String cityCode;

    /**
     * 암호화된 상세 주소 (복호화 가능한 암호화)
     */
    @Column(name = "detail_encrypted", nullable = false)
    private String detailEncrypted;

    /**
     * 결정적 암호화된 상세 주소 키워드 (검색용)
     */
    @Column(name = "detail_searchable")
    private String detailSearchable;

    /**
     * 사용자 참조 (양방향 매핑)
     */
    @OneToOne(mappedBy = "address")
    private User user;

    /**
     * 생성자
     */
    @Builder
    public Address(String zipCode, String region, String regionCode, String city,
                   String cityCode, String detailEncrypted, String detailSearchable) {
        this.zipCode = zipCode;
        this.region = region;
        this.regionCode = regionCode;
        this.city = city;
        this.cityCode = cityCode;
        this.detailEncrypted = detailEncrypted;
        this.detailSearchable = detailSearchable;
    }

    /**
     * 주소 정보 업데이트
     */
    public void updateAddress(String zipCode, String region, String regionCode, String city,
                              String cityCode, String detailEncrypted, String detailSearchable) {
        this.zipCode = zipCode;
        this.region = region;
        this.regionCode = regionCode;
        this.city = city;
        this.cityCode = cityCode;
        this.detailEncrypted = detailEncrypted;
        this.detailSearchable = detailSearchable;
    }
}
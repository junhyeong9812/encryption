package com.personaldata.encryption.global.entity;

import jakarta.persistence.Column;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.MappedSuperclass;
import lombok.Getter;
import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.LastModifiedBy;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

/**
 * 모든 엔티티의 기본 속성을 정의하는 기본 엔티티 클래스
 * 시간 정보 및 작성자/수정자 정보를 공통적으로 관리
 */
@Getter
@MappedSuperclass
@EntityListeners(AuditingEntityListener.class)
public abstract class BaseEntity extends BaseTimeEntity {

    /**
     * 엔티티 생성자 정보
     */
    @CreatedBy
    @Column(name = "created_by", updatable = false)
    private String createdBy;

    /**
     * 엔티티 마지막 수정자 정보
     */
    @LastModifiedBy
    @Column(name = "updated_by")
    private String updatedBy;
}
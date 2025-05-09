package com.personaldata.encryption.global.config;

import com.querydsl.jpa.impl.JPAQueryFactory;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.transaction.annotation.EnableTransactionManagement;

/**
 * Querydsl 및 JPA 관련 설정을 담당하는 설정 클래스
 * - JPAQueryFactory 빈 등록
 * - 트랜잭션 관리 활성화
 * - JPA 저장소 활성화
 */
@Configuration
@EnableTransactionManagement
@EnableJpaRepositories(basePackages = "com.personaldata.encryption")
public class QuerydslConfig {

    @PersistenceContext
    private EntityManager entityManager;

    /**
     * JPAQueryFactory 빈 등록
     * 이 빈을 통해 Querydsl을 사용한 타입-세이프 쿼리 생성 가능
     *
     * @return JPAQueryFactory 인스턴스
     */
    @Bean
    public JPAQueryFactory jpaQueryFactory() {
        return new JPAQueryFactory(entityManager);
    }
}
package com.personaldata.encryption.global.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.AuditorAware;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;

/**
 * JPA Auditing 설정 클래스
 * 생성자와 수정자 정보를 자동으로 관리
 */
@Configuration
@EnableJpaAuditing(auditorAwareRef = "auditorProvider")
public class AuditingConfig {

    /**
     * AuditorAware 구현체 빈을 등록
     * Spring Security의 SecurityContext에서 현재 인증된 사용자 정보를 가져옴
     *
     * @return AuditorAware<String> 구현체
     */
    @Bean
    public AuditorAware<String> auditorProvider() {
        return () -> {
            // SecurityContext에서 Authentication 객체 가져오기
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            // 인증 정보가 있고 인증되었으면 사용자 ID 반환, 없으면 "system" 반환
            if (authentication != null && authentication.isAuthenticated()) {
                return Optional.ofNullable(authentication.getName());
            }

            return Optional.of("system");
        };
    }
}
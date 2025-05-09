package com.personaldata.encryption.global.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * 스프링 시큐리티 설정 클래스
 * 개발 환경에서는 간소화된 설정 사용
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /**
     * 보안 필터 체인 설정
     * - API 엔드포인트에 대한 접근 권한 설정
     * - 세션 관리 설정
     * - CSRF 보호 설정
     *
     * @param http HttpSecurity 설정 객체
     * @return 구성된 SecurityFilterChain
     * @throws Exception 보안 설정 중 발생할 수 있는 예외
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // 개발 환경용 간소화된 설정
        http
                // CSRF 보호 비활성화 (API 서버용)
                .csrf(csrf -> csrf.disable())

                // 세션 관리 설정 (무상태 REST API용)
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // 요청 경로별
                .authorizeHttpRequests(authorize -> authorize
                        // Swagger UI 및 API 문서 접근 허용
                        .requestMatchers("/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()
                        // 건강 체크 및 정보 엔드포인트 접근 허용
                        .requestMatchers("/actuator/health", "/actuator/info").permitAll()
                        // 개발 환경에서는 모든 API 접근 허용
                        .requestMatchers("/api/**").permitAll()
                        // 그 외 모든 요청은 인증 필요
                        .anyRequest().authenticated()
                );

        return http.build();
    }
}
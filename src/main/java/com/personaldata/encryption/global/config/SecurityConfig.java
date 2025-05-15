package com.personaldata.encryption.global.config;

import com.personaldata.encryption.global.security.JwtAuthenticationFilter;
import com.personaldata.encryption.global.security.JwtTokenProvider;
import com.personaldata.encryption.global.utils.CookieUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

/**
 * 스프링 시큐리티 설정 클래스
 * 웹/모바일 클라이언트에 대한 인증 설정
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final UserDetailsService userDetailsService;
    private final JwtTokenProvider jwtTokenProvider;

    /**
     * 비밀번호 인코더 빈 등록
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 웹 클라이언트용 보안 필터 체인 구성
     */
    @Bean
    @Order(1)
    public SecurityFilterChain webSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                // CSRF 보호 활성화 (웹 클라이언트는 CSRF 공격에 취약)
                .securityMatcher("/api/auth/web/**", "/api/web/**")
                .csrf(csrf -> csrf.ignoringRequestMatchers("/api/auth/web/login", "/api/auth/web/signup"))

                // 쿠키 기반 인증에는 세션 활성화
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // JWT 인증 필터 추가
                .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)

                // 요청 경로별 접근 권한 설정
                .authorizeHttpRequests(authorize -> authorize
                        // 공개 API 경로
                        .requestMatchers("/api/auth/web/login", "/api/auth/web/signup").permitAll()
                        .requestMatchers("/api/auth/web/refresh").permitAll()
                        .requestMatchers("/api/auth/web/status").permitAll()

                        // 관리자 전용 API
                        .requestMatchers("/api/web/admin/**").hasRole("ADMIN")

                        // 그 외 모든 요청은 인증 필요
                        .anyRequest().authenticated()
                );

        // 인증 관리자 설정
        configureAuthenticationManager(http);

        return http.build();
    }

    /**
     * 모바일 클라이언트용 보안 필터 체인 구성
     */
    @Bean
    @Order(2)
    public SecurityFilterChain mobileSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                // CSRF 보호 비활성화 (모바일 API는 CSRF 공격에 덜 취약)
                .securityMatcher("/api/auth/mobile/**", "/api/mobile/**")
                .csrf(AbstractHttpConfigurer::disable)

                // 세션 관리 설정 (JWT 사용으로 서버에서 세션 유지하지 않음)
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // JWT 인증 필터 추가
                .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)

                // 요청 경로별 접근 권한 설정
                .authorizeHttpRequests(authorize -> authorize
                        // 공개 API 경로
                        .requestMatchers("/api/auth/mobile/login", "/api/auth/mobile/signup").permitAll()
                        .requestMatchers("/api/auth/mobile/refresh").permitAll()

                        // 관리자 전용 API
                        .requestMatchers("/api/mobile/admin/**").hasRole("ADMIN")

                        // 그 외 모든 요청은 인증 필요
                        .anyRequest().authenticated()
                );

        // 인증 관리자 설정
        configureAuthenticationManager(http);

        return http.build();
    }

    /**
     * 기타 공개 API에 대한 보안 필터 체인 구성
     */
    @Bean
    @Order(3)
    public SecurityFilterChain publicSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                // CSRF 보호 비활성화 (API 서버용)
                .securityMatcher("/api-docs/**", "/swagger-ui/**", "/actuator/**")
                .csrf(AbstractHttpConfigurer::disable)

                // 세션 관리 설정
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // 요청 경로별 접근 권한 설정
                .authorizeHttpRequests(authorize -> authorize
                        // 공개 API 경로
                        .requestMatchers("/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()
                        .requestMatchers("/actuator/health", "/actuator/info").permitAll()

                        // 그 외는 인증 필요
                        .anyRequest().authenticated()
                );

        return http.build();
    }

    /**
     * 기본 보안 필터 체인 구성 (나머지 모든 경로에 적용)
     */
    @Bean
    @Order(4)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                // CSRF 보호 비활성화 (API 서버용)
                .csrf(AbstractHttpConfigurer::disable)

                // CORS 설정
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                // 세션 관리 설정
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // JWT 인증 필터 추가
                .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)

                // 요청 경로별 접근 권한 설정
                .authorizeHttpRequests(authorize -> authorize
                        // 그 외 모든 요청은 인증 필요
                        .anyRequest().authenticated()
                );

        // 인증 관리자 설정
        configureAuthenticationManager(http);

        return http.build();
    }

    /**
     * JWT 인증 필터 빈 등록
     */
    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter(jwtTokenProvider);
    }

    /**
     * 인증 관리자 설정 및 등록
     */
    private void configureAuthenticationManager(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }

    /**
     * 인증 관리자 빈 등록
     */
    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        return http.getSharedObject(AuthenticationManagerBuilder.class).build();
    }

    /**
     * CORS 설정
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("*")); // 운영 환경에서는 구체적인 출처 지정 필요
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Cache-Control", "Content-Type"));
        configuration.setExposedHeaders(List.of("Authorization")); // Authorization 헤더 노출
        configuration.setMaxAge(3600L); // 1시간 동안 preflight 요청 캐싱

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
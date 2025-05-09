package com.personaldata.encryption.global.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * 비밀번호 암호화를 위한 설정 클래스
 * Spring Security의 PasswordEncoder를 빈으로 등록
 */
@Configuration
public class PasswordEncoderConfig {

    /**
     * BCrypt 알고리즘을 사용하는 PasswordEncoder 빈 생성
     *
     * @return PasswordEncoder 구현체
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12); // 강도(strength) 설정: 10-12가 권장됨
    }
}
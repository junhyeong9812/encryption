package com.personaldata.encryption.domain.user.service;

import com.personaldata.encryption.domain.user.entity.User;
import com.personaldata.encryption.domain.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Spring Security의 UserDetailsService 구현체
 * 사용자 인증 정보를 로드하는 역할
 */
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    /**
     * 이메일로 사용자 정보 로드
     *
     * @param email 사용자 이메일 (로그인 ID)
     * @return UserDetails 구현체 (User 엔티티)
     * @throws UsernameNotFoundException 사용자를 찾을 수 없는 경우
     */
    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("이메일 '" + email + "'을 가진 사용자를 찾을 수 없습니다."));
    }
}
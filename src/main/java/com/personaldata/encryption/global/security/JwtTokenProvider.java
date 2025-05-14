package com.personaldata.encryption.global.security;

import com.personaldata.encryption.domain.user.entity.TokenBlacklist;
import com.personaldata.encryption.domain.user.entity.User;
import com.personaldata.encryption.domain.user.entity.enums.UserRole;
import com.personaldata.encryption.domain.user.repository.TokenBlacklistRepository;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.Date;

/**
 * JWT 토큰 생성, 검증 및 관리를 담당하는 컴포넌트
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.access-token-expiration}")
    private long accessTokenValidityMs;

    @Value("${jwt.refresh-token-expiration}")
    private long refreshTokenValidityMs;

    private final UserDetailsService userDetailsService;
    private final TokenBlacklistRepository tokenBlacklistRepository;

    /**
     * 시크릿 키를 이용하여 서명용 Key 객체 생성
     *
     * @return JWT 서명에 사용할 Key 객체
     */
    private Key getSigningKey() {
        byte[] keyBytes = secretKey.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * 사용자 정보로 액세스 토큰과 리프레시 토큰 생성
     *
     * @param user 사용자 엔티티
     * @return 생성된 토큰 정보 DTO
     */
    public TokenInfo generateTokenPair(User user) {
        try {
            long now = System.currentTimeMillis();

            // 액세스 토큰 생성
            Date accessTokenExpiresAt = new Date(now + accessTokenValidityMs);
            String accessToken = Jwts.builder()
                    .setSubject(user.getEmail())
                    .setIssuedAt(new Date(now))
                    .setExpiration(accessTokenExpiresAt)
                    .claim("id", user.getId())
                    .claim("role", user.getRole())
                    .signWith(getSigningKey(), SignatureAlgorithm.HS512)
                    .compact();

            // 리프레시 토큰 생성
            Date refreshTokenExpiresAt = new Date(now + refreshTokenValidityMs);
            String refreshToken = Jwts.builder()
                    .setSubject(user.getEmail())
                    .setIssuedAt(new Date(now))
                    .setExpiration(refreshTokenExpiresAt)
                    .claim("id", user.getId())
                    .signWith(getSigningKey(), SignatureAlgorithm.HS512)
                    .compact();

            log.info("토큰 생성 완료: 이메일={}, 액세스 토큰 만료={}, 리프레시 토큰 만료={}",
                    user.getEmail(), accessTokenExpiresAt, refreshTokenExpiresAt);

            return TokenInfo.builder()
                    .grantType("Bearer")
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .accessTokenExpiresIn(accessTokenValidityMs / 1000) // 초 단위로 변환
                    .build();
        } catch (Exception e) {
            log.error("토큰 생성 실패: 이메일={}, 오류={}", user.getEmail(), e.getMessage(), e);
            throw new RuntimeException("토큰 생성 중 오류가 발생했습니다.");
        }
    }

    /**
     * 토큰에서 사용자 이메일 추출
     *
     * @param token JWT 토큰
     * @return 사용자 이메일
     */
    public String getEmailFromToken(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            String email = claims.getSubject();
            log.debug("토큰에서 이메일 추출: {}", email);
            return email;
        } catch (ExpiredJwtException e) {
            log.warn("만료된 토큰에서 이메일 추출 시도: {}", e.getMessage());
            throw new IllegalArgumentException("만료된 토큰입니다.");
        } catch (JwtException e) {
            log.warn("유효하지 않은 토큰에서 이메일 추출 시도: {}", e.getMessage());
            throw new IllegalArgumentException("유효하지 않은 토큰입니다.");
        } catch (Exception e) {
            log.error("토큰에서 이메일 추출 중 예상치 못한 오류: {}", e.getMessage(), e);
            throw new IllegalArgumentException("토큰에서 이메일을 추출하는 중 오류가 발생했습니다.");
        }
    }

    /**
     * 토큰에서 사용자 ID 추출
     *
     * @param token JWT 토큰
     * @return 사용자 ID
     */
    public Long getUserIdFromToken(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            Long userId = claims.get("id", Long.class);
            log.debug("토큰에서 사용자 ID 추출: {}", userId);
            return userId;
        } catch (ExpiredJwtException e) {
            log.warn("만료된 토큰에서 사용자 ID 추출 시도: {}", e.getMessage());
            throw new IllegalArgumentException("만료된 토큰입니다.");
        } catch (JwtException e) {
            log.warn("유효하지 않은 토큰에서 사용자 ID 추출 시도: {}", e.getMessage());
            throw new IllegalArgumentException("유효하지 않은 토큰입니다.");
        } catch (Exception e) {
            log.error("토큰에서 사용자 ID 추출 중 예상치 못한 오류: {}", e.getMessage(), e);
            throw new IllegalArgumentException("토큰에서 사용자 ID를 추출하는 중 오류가 발생했습니다.");
        }
    }

    /**
     * 토큰에서 역할 정보 추출
     *
     * @param token JWT 토큰
     * @return 사용자 역할
     */
    public UserRole getRoleFromToken(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            String role = claims.get("role", String.class);
            log.debug("토큰에서 역할 추출: {}", role);
            return UserRole.fromKey(role);
        } catch (ExpiredJwtException e) {
            log.warn("만료된 토큰에서 역할 추출 시도: {}", e.getMessage());
            throw new IllegalArgumentException("만료된 토큰입니다.");
        } catch (JwtException e) {
            log.warn("유효하지 않은 토큰에서 역할 추출 시도: {}", e.getMessage());
            throw new IllegalArgumentException("유효하지 않은 토큰입니다.");
        } catch (Exception e) {
            log.error("토큰에서 역할 추출 중 예상치 못한 오류: {}", e.getMessage(), e);
            throw new IllegalArgumentException("토큰에서 역할을 추출하는 중 오류가 발생했습니다.");
        }
    }

    /**
     * 액세스 토큰 생성 (단독)
     *
     * @param user 사용자 엔티티
     * @return 생성된 액세스 토큰
     */
    public String generateAccessToken(User user) {
        try {
            long now = System.currentTimeMillis();
            Date accessTokenExpiresAt = new Date(now + accessTokenValidityMs);

            return Jwts.builder()
                    .setSubject(user.getEmail())
                    .setIssuedAt(new Date(now))
                    .setExpiration(accessTokenExpiresAt)
                    .claim("id", user.getId())
                    .claim("role", user.getRole())
                    .signWith(getSigningKey(), SignatureAlgorithm.HS512)
                    .compact();
        } catch (Exception e) {
            log.error("액세스 토큰 생성 실패: 이메일={}, 오류={}", user.getEmail(), e.getMessage(), e);
            throw new RuntimeException("액세스 토큰 생성 중 오류가 발생했습니다.");
        }
    }

    /**
     * 토큰 유효성 검증
     *
     * @param token JWT 토큰
     * @return 유효성 여부
     */
    public boolean validateToken(String token) {
        try {
            // 블랙리스트 확인
            if (tokenBlacklistRepository.existsByToken(token)) {
                log.warn("블랙리스트에 등록된 토큰");
                return false;
            }

            // 토큰 서명 검증
            Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token);
            log.debug("토큰 검증 성공");
            return true;
        } catch (ExpiredJwtException e) {
            log.warn("만료된 토큰: {}", e.getMessage());
            return false;
        } catch (SignatureException e) {
            log.warn("유효하지 않은 토큰 서명: {}", e.getMessage());
            return false;
        } catch (MalformedJwtException e) {
            log.warn("잘못된 형식의 토큰: {}", e.getMessage());
            return false;
        } catch (UnsupportedJwtException e) {
            log.warn("지원되지 않는 토큰: {}", e.getMessage());
            return false;
        } catch (IllegalArgumentException e) {
            log.warn("잘못된 인자의 토큰: {}", e.getMessage());
            return false;
        } catch (Exception e) {
            log.error("토큰 검증 중 예상치 못한 오류: {}", e.getMessage(), e);
            return false;
        }
    }

    /**
     * 토큰에서 Authentication 객체 생성
     *
     * @param token JWT 토큰
     * @return 인증 객체
     */
    public Authentication getAuthentication(String token) {
        try {
            String email = getEmailFromToken(token);
            Long userId = getUserIdFromToken(token);
            String role = getRoleFromToken(token).getKey();

            // 사용자 정보 로드
            UserDetails userDetails = userDetailsService.loadUserByUsername(email);

            // Authentication 객체 생성 (userId를 details에 저장)
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    userDetails, null, Collections.singleton(new SimpleGrantedAuthority(role)));
            authentication.setDetails(userId);

            return authentication;
        } catch (Exception e) {
            log.error("인증 객체 생성 중 오류: {}", e.getMessage(), e);
            throw new IllegalArgumentException("인증 객체 생성 중 오류가 발생했습니다.");
        }
    }

    /**
     * 토큰 무효화 (블랙리스트에 추가)
     *
     * @param token 무효화할 토큰
     * @param reason 무효화 사유
     */
    public void invalidateToken(String token, String reason) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            // 토큰 만료 시간
            Date expiresAt = claims.getExpiration();
            LocalDateTime expiresAtLocalDateTime = LocalDateTime.now().plusSeconds(
                    (expiresAt.getTime() - System.currentTimeMillis()) / 1000);

            // 블랙리스트에 추가
            TokenBlacklist blacklist = TokenBlacklist.builder()
                    .token(token)
                    .expiresAt(expiresAtLocalDateTime)
                    .reason(reason)
                    .build();

            tokenBlacklistRepository.save(blacklist);
            log.info("토큰을 블랙리스트에 추가: 만료={}, 사유={}", expiresAt, reason);
        } catch (ExpiredJwtException e) {
            log.info("이미 만료된 토큰이므로 블랙리스트에 추가하지 않음");
        } catch (Exception e) {
            log.error("토큰 무효화 중 오류: {}", e.getMessage(), e);
            throw new IllegalArgumentException("토큰 무효화 중 오류가 발생했습니다.");
        }
    }

    /**
     * 토큰 만료 시간 타임스탬프 조회 (액세스 토큰)
     *
     * @return 만료 시간 타임스탬프 (밀리초)
     */
    public long getAccessTokenExpirationTimestamp() {
        return System.currentTimeMillis() + accessTokenValidityMs;
    }

    /**
     * 토큰 만료 시간 타임스탬프 조회 (리프레시 토큰)
     *
     * @return 만료 시간 타임스탬프 (밀리초)
     */
    public long getRefreshTokenExpirationTimestamp() {
        return System.currentTimeMillis() + refreshTokenValidityMs;
    }
}
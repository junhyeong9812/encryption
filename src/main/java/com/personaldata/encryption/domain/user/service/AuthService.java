package com.personaldata.encryption.domain.user.service;

import com.personaldata.encryption.domain.user.dto.AddressDto;
import com.personaldata.encryption.domain.user.dto.AuthDto;
import com.personaldata.encryption.domain.user.entity.Address;
import com.personaldata.encryption.domain.user.entity.RefreshToken;
import com.personaldata.encryption.domain.user.entity.User;
import com.personaldata.encryption.domain.user.repository.RefreshTokenRepository;
import com.personaldata.encryption.domain.user.repository.TokenBlacklistRepository;
import com.personaldata.encryption.domain.user.repository.UserRepository;
import com.personaldata.encryption.global.security.JwtTokenProvider;
import com.personaldata.encryption.global.security.TokenInfo;
import com.personaldata.encryption.global.utils.EncryptionUtil;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

/**
 * 사용자 인증 관련 서비스
 * 회원가입, 로그인, 토큰 관리 등 인증 관련 기능 통합
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final TokenBlacklistRepository tokenBlacklistRepository;
    private final PasswordEncoder passwordEncoder;
    private final EncryptionUtil encryptionUtil;
    private final UserIndexService userIndexService;
    private final JwtTokenProvider jwtTokenProvider;

    /**
     * 사용자 회원가입
     *
     * @param request 회원가입 요청 DTO
     * @return 생성된 사용자 엔티티
     */
    @Transactional
    public User signup(AuthDto.SignupRequest request) {
        // 이메일 중복 확인
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new IllegalArgumentException("이미 사용 중인 이메일입니다.");
        }

        // 이름 암호화
        String nameEncrypted = encryptionUtil.encryptStrongly(request.getName());
        String nameSearchable = encryptionUtil.deterministicEncrypt(request.getName());
        String nameInitial = encryptionUtil.extractKoreanInitials(request.getName());

        // 전화번호 암호화
        String phoneEncrypted = encryptionUtil.encryptStrongly(request.getPhone());
        String phonePrefix = "";
        String phoneSuffix = "";
        if (request.getPhone() != null) {
            // 전화번호 앞 3자리를 결정적 암호화하여 검색에 활용
            if (request.getPhone().length() >= 3) {
                phonePrefix = encryptionUtil.deterministicEncrypt(request.getPhone().substring(0, 3));
            }

            // 전화번호 뒤 4자리를 결정적 암호화하여 검색에 활용
            if (request.getPhone().length() >= 4) {
                int phoneLength = request.getPhone().length();
                phoneSuffix = encryptionUtil.deterministicEncrypt(
                        request.getPhone().substring(phoneLength - 4));
            }
        }

        // 주민등록번호 암호화 (있는 경우)
        String ssnEncrypted = null;
        String ssnPrefix = null;
        String ssnGenderDigit = null;

        if (request.getSsn() != null && !request.getSsn().isEmpty()) {
            ssnEncrypted = encryptionUtil.encryptStrongly(request.getSsn());

            // 주민등록번호 앞 6자리(생년월일)를 결정적 암호화하여 검색에 활용
            if (request.getSsn().length() >= 6) {
                ssnPrefix = encryptionUtil.deterministicEncrypt(request.getSsn().substring(0, 6));
            }

            // 주민등록번호 성별자리를 결정적 암호화하여 검색에 활용
            String genderDigit = encryptionUtil.extractSsnGenderDigit(request.getSsn());
            if (!genderDigit.isEmpty()) {
                ssnGenderDigit = encryptionUtil.deterministicEncrypt(genderDigit);
            }
        }

        // 비밀번호 암호화
        String encodedPassword = passwordEncoder.encode(request.getPassword());

        // 주소 생성 (있는 경우)
        Address address = null;
        if (request.getAddress() != null) {
            AddressDto addressDto = request.getAddress();
            String detailEncrypted = encryptionUtil.encryptStrongly(addressDto.getDetail());
            String detailSearchable = encryptionUtil.deterministicEncrypt(addressDto.getDetail());

            address = Address.builder()
                    .zipCode(addressDto.getZipCode())
                    .region(addressDto.getRegion())
                    .regionCode(addressDto.getRegionCode())
                    .city(addressDto.getCity())
                    .cityCode(addressDto.getCityCode())
                    .detailEncrypted(detailEncrypted)
                    .detailSearchable(detailSearchable)
                    .build();
        }

        // 사용자 생성
        User user = User.builder()
                .nameEncrypted(nameEncrypted)
                .nameSearchable(nameSearchable)
                .nameInitial(nameInitial)
                .phoneEncrypted(phoneEncrypted)
                .phonePrefix(phonePrefix)
                .phoneSuffix(phoneSuffix)
                .ssnEncrypted(ssnEncrypted)
                .ssnPrefix(ssnPrefix)
                .ssnGenderDigit(ssnGenderDigit)
                .email(request.getEmail())
                .password(encodedPassword)
                .role("ROLE_USER")
                .enabled(true)
                .accountNonLocked(true)
                .accountNonExpired(true)
                .credentialsNonExpired(true)
                .address(address)
                .build();

        // 사용자 저장
        User savedUser = userRepository.save(user);

        // 검색 인덱스 생성
        userIndexService.indexUser(savedUser);

        return savedUser;
    }

    /**
     * 사용자 로그인
     *
     * @param request 로그인 요청 DTO
     * @return 인증된 사용자 정보
     */
    @Transactional(readOnly = true)
    public User login(AuthDto.LoginRequest request) {
        // 이메일로 사용자 조회
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new BadCredentialsException("이메일 또는 비밀번호가 일치하지 않습니다."));

        // 비밀번호 검증
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new BadCredentialsException("이메일 또는 비밀번호가 일치하지 않습니다.");
        }

        // 계정 상태 확인
        if (!user.isEnabled()) {
            throw new BadCredentialsException("비활성화된 계정입니다.");
        }

        return user;
    }

    /**
     * 사용자 이름 마스킹 처리
     *
     * @param user 사용자 엔티티
     * @return 마스킹된 이름
     */
    @Transactional(readOnly = true)
    public String getMaskedName(User user) {
        // 이름 복호화 및 마스킹
        String decryptedName = encryptionUtil.decrypt(user.getNameEncrypted());
        return maskName(decryptedName);
    }

    /**
     * 이름 마스킹 처리
     */
    public String maskName(String name) {
        if (name == null || name.length() <= 1) {
            return "***";
        }

        // 첫 글자만 표시하고 나머지는 *로 마스킹
        return name.substring(0, 1) + "*".repeat(name.length() - 1);
    }

    /**
     * 비밀번호 변경
     */
    @Transactional
    public void changePassword(String email, AuthDto.PasswordChangeRequest request) {
        // 이메일로 사용자 조회
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new BadCredentialsException("사용자를 찾을 수 없습니다."));

        // 현재 비밀번호 검증
        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            throw new BadCredentialsException("현재 비밀번호가 일치하지 않습니다.");
        }

        // 새 비밀번호와 확인 비밀번호 일치 확인
        if (!request.getNewPassword().equals(request.getConfirmPassword())) {
            throw new IllegalArgumentException("새 비밀번호와 확인 비밀번호가 일치하지 않습니다.");
        }

        // 새 비밀번호 암호화 및 업데이트
        String encodedNewPassword = passwordEncoder.encode(request.getNewPassword());
        user.updatePassword(encodedNewPassword);

        userRepository.save(user);
    }

    /**
     * 사용자 인증 후 토큰 발급
     *
     * @param user 인증된 사용자
     * @return 토큰 정보
     */
    @Transactional
    public TokenInfo issueTokens(User user) {
        // 토큰 생성
        TokenInfo tokenInfo = jwtTokenProvider.generateTokenPair(user);

        // 리프레시 토큰 저장
        saveRefreshToken(user.getId(), tokenInfo.getRefreshToken());

        log.info("토큰 발급 완료: userId={}, email={}", user.getId(), user.getEmail());
        return tokenInfo;
    }

    /**
     * 리프레시 토큰 저장/갱신
     *
     * @param userId 사용자 ID
     * @param refreshToken 리프레시 토큰
     */
    @Transactional
    public void saveRefreshToken(Long userId, String refreshToken) {
        long refreshTokenValidityMs = jwtTokenProvider.getRefreshTokenExpirationTimestamp() - System.currentTimeMillis();
        LocalDateTime expiresAt = LocalDateTime.now().plusSeconds(refreshTokenValidityMs / 1000);

        // 기존 토큰이 있는지 확인 후 저장 또는 갱신
        refreshTokenRepository.findByUserId(userId).ifPresentOrElse(
                // 토큰이 있으면 갱신
                token -> token.updateToken(refreshToken, expiresAt),
                // 없으면 새로 생성
                () -> refreshTokenRepository.save(RefreshToken.builder()
                        .userId(userId)
                        .token(refreshToken)
                        .expiresAt(expiresAt)
                        .build())
        );

        log.debug("리프레시 토큰 저장 완료: userId={}, 만료={}", userId, expiresAt);
    }

    /**
     * 리프레시 토큰으로 새 액세스 토큰 발급
     *
     * @param refreshToken 리프레시 토큰
     * @return 새로 발급된 토큰 정보
     */
    @Transactional
    public TokenInfo refreshAccessToken(String refreshToken) {
        // 리프레시 토큰 유효성 검증
        if (!jwtTokenProvider.validateToken(refreshToken)) {
            throw new IllegalArgumentException("유효하지 않은 리프레시 토큰입니다.");
        }

        try {
            // 토큰에서 사용자 ID 추출
            Long userId = jwtTokenProvider.getUserIdFromToken(refreshToken);

            // DB에 저장된 리프레시 토큰 조회
            RefreshToken savedToken = refreshTokenRepository.findByUserId(userId)
                    .orElseThrow(() -> new IllegalArgumentException("저장된 리프레시 토큰이 없습니다."));

            // 토큰 일치 여부 확인
            if (!savedToken.getToken().equals(refreshToken)) {
                log.warn("DB에 저장된 리프레시 토큰과 불일치: userId={}", userId);
                throw new IllegalArgumentException("유효하지 않은 리프레시 토큰입니다.");
            }

            // 토큰 만료 여부 확인
            if (savedToken.isExpired()) {
                log.warn("만료된 리프레시 토큰: userId={}", userId);
                refreshTokenRepository.delete(savedToken);
                throw new IllegalArgumentException("만료된 리프레시 토큰입니다.");
            }

            // 사용자 조회
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new EntityNotFoundException("사용자를 찾을 수 없습니다."));

            // 새 액세스 토큰 생성
            String accessToken = jwtTokenProvider.generateAccessToken(user);

            return TokenInfo.builder()
                    .grantType("Bearer")
                    .accessToken(accessToken)
                    .refreshToken(refreshToken) // 기존 리프레시 토큰 유지
                    .accessTokenExpiresIn(jwtTokenProvider.getAccessTokenExpirationTimestamp() / 1000)
                    .build();
        } catch (IllegalArgumentException e) {
            log.warn("리프레시 토큰 오류: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("토큰 갱신 중 오류: {}", e.getMessage(), e);
            throw new IllegalArgumentException("토큰 갱신 중 오류가 발생했습니다.");
        }
    }

    /**
     * 로그아웃 처리 (토큰 무효화)
     *
     * @param accessToken 액세스 토큰
     * @param userId 사용자 ID
     */
    @Transactional
    public void logout(String accessToken, Long userId) {
        try {
            // 액세스 토큰 블랙리스트에 추가
            if (accessToken != null) {
                jwtTokenProvider.invalidateToken(accessToken, "로그아웃");
            }

            // 리프레시 토큰 삭제
            refreshTokenRepository.deleteByUserId(userId);

            log.info("로그아웃 처리 완료: userId={}", userId);
        } catch (Exception e) {
            log.error("로그아웃 처리 중 오류: {}", e.getMessage(), e);
            throw new IllegalArgumentException("로그아웃 처리 중 오류가 발생했습니다.");
        }
    }

    /**
     * 만료된 토큰 정리 (스케줄링)
     * 매일 새벽 3시에 실행
     */
    @Scheduled(cron = "0 0 3 * * ?")
    @Transactional
    public void cleanupExpiredTokens() {
        LocalDateTime now = LocalDateTime.now();

        try {
            // 만료된 리프레시 토큰 삭제
            int refreshTokensDeleted = refreshTokenRepository.deleteExpiredTokens(now);

            // 만료된 블랙리스트 토큰 삭제
            int blacklistTokensDeleted = tokenBlacklistRepository.deleteExpiredTokens(now);

            log.info("만료된 토큰 정리 완료 - 리프레시 토큰: {}, 블랙리스트 토큰: {}",
                    refreshTokensDeleted, blacklistTokensDeleted);
        } catch (Exception e) {
            log.error("만료된 토큰 정리 중 오류: {}", e.getMessage(), e);
        }
    }
}
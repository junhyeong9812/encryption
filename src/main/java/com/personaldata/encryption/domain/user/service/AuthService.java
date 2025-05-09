package com.personaldata.encryption.domain.user.service;

import com.personaldata.encryption.domain.user.dto.AddressDto;
import com.personaldata.encryption.domain.user.dto.AuthDto;
import com.personaldata.encryption.domain.user.entity.Address;
import com.personaldata.encryption.domain.user.entity.User;
import com.personaldata.encryption.domain.user.repository.UserRepository;
import com.personaldata.encryption.global.utils.EncryptionUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * 사용자 인증 관련 서비스
 */
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final EncryptionUtil encryptionUtil;
    private final UserIndexService userIndexService;

    /**
     * 사용자 회원가입
     */
    @Transactional
    public AuthDto.LoginResponse signup(AuthDto.SignupRequest request) {
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

        // 로그인 응답 생성
        return AuthDto.LoginResponse.builder()
                .email(savedUser.getEmail())
                .role(savedUser.getRole())
                .maskedName(maskName(request.getName()))
                .build();
    }

    /**
     * 사용자 로그인
     */
    @Transactional(readOnly = true)
    public AuthDto.LoginResponse login(AuthDto.LoginRequest request) {
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

        // 이름 복호화 및 마스킹
        String decryptedName = encryptionUtil.decrypt(user.getNameEncrypted());
        String maskedName = maskName(decryptedName);

        // 로그인 응답 생성
        return AuthDto.LoginResponse.builder()
                .email(user.getEmail())
                .role(user.getRole())
                .maskedName(maskedName)
                .build();
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
     * 이름 마스킹 처리
     */
    private String maskName(String name) {
        if (name == null || name.length() <= 1) {
            return "***";
        }

        // 첫 글자만 표시하고 나머지는 *로 마스킹
        return name.substring(0, 1) + "*".repeat(name.length() - 1);
    }
}
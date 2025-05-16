package com.personaldata.encryption.domain.user.service;

import com.personaldata.encryption.domain.user.dto.AddressDto;
import com.personaldata.encryption.domain.user.dto.UserDto;
import com.personaldata.encryption.domain.user.entity.Address;
import com.personaldata.encryption.domain.user.entity.User;
import com.personaldata.encryption.domain.user.repository.UserRepository;
import com.personaldata.encryption.global.utils.EncryptionUtil;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

/**
 * 사용자 정보 관리 서비스
 */
@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final EncryptionUtil encryptionUtil;
    private final UserIndexService userIndexService;

    /**
     * 사용자 정보 조회
     */
    @Transactional(readOnly = true)
    public UserDto getUserById(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("ID가 " + id + "인 사용자를 찾을 수 없습니다."));

        // 민감 정보 복호화
        String decryptedName = encryptionUtil.decrypt(user.getNameEncrypted());
        String decryptedPhone = encryptionUtil.decrypt(user.getPhoneEncrypted());
        String decryptedSsn = null;

        // 주민등록번호가 있는 경우에만 복호화
        if (user.getSsnEncrypted() != null) {
            decryptedSsn = encryptionUtil.decrypt(user.getSsnEncrypted());
        }

        // 주소 정보가 있는 경우 상세 주소 복호화
        AddressDto addressDto = null;
        if (user.getAddress() != null) {
            String decryptedDetail = encryptionUtil.decrypt(user.getAddress().getDetailEncrypted());
            addressDto = AddressDto.fromEntityWithDetail(user.getAddress(), decryptedDetail);
        }

        // DTO 생성 및 주소 정보 설정
        UserDto userDto = decryptedSsn != null
                ? UserDto.fromEntity(user, decryptedName, decryptedPhone, decryptedSsn)
                : UserDto.fromEntity(user, decryptedName, decryptedPhone);
        userDto.setAddress(addressDto);

        return userDto;
    }

    /**
     * 이메일로 사용자 조회
     */
    @Transactional(readOnly = true)
    public UserDto getUserByEmail(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new EntityNotFoundException("이메일이 " + email + "인 사용자를 찾을 수 없습니다."));

        // 민감 정보 복호화
        String decryptedName = encryptionUtil.decrypt(user.getNameEncrypted());
        String decryptedPhone = encryptionUtil.decrypt(user.getPhoneEncrypted());
        String decryptedSsn = null;

        // 주민등록번호가 있는 경우에만 복호화
        if (user.getSsnEncrypted() != null) {
            decryptedSsn = encryptionUtil.decrypt(user.getSsnEncrypted());
        }

        // 주소 정보가 있는 경우 상세 주소 복호화
        AddressDto addressDto = null;
        if (user.getAddress() != null) {
            String decryptedDetail = encryptionUtil.decrypt(user.getAddress().getDetailEncrypted());
            addressDto = AddressDto.fromEntityWithDetail(user.getAddress(), decryptedDetail);
        }

        // DTO 생성 및 주소 정보 설정
        UserDto userDto = decryptedSsn != null
                ? UserDto.fromEntity(user, decryptedName, decryptedPhone, decryptedSsn)
                : UserDto.fromEntity(user, decryptedName, decryptedPhone);
        userDto.setAddress(addressDto);

        return userDto;
    }

    /**
     * 사용자 정보 업데이트
     */
    @Transactional
    public UserDto updateUser(Long id, String name, String phone, String ssn, String email, AddressDto addressDto) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("ID가 " + id + "인 사용자를 찾을 수 없습니다."));

        // 이름 암호화
        String nameEncrypted = encryptionUtil.encryptStrongly(name);
        String nameSearchable = encryptionUtil.deterministicEncrypt(name);
        String nameInitial = encryptionUtil.extractKoreanInitials(name);

        // 전화번호 암호화
        String phoneEncrypted = encryptionUtil.encryptStrongly(phone);
        String phonePrefix = "";
        String phoneSuffix = "";

        if (phone != null) {
            // 전화번호 앞 3자리를 결정적 암호화하여 검색에 활용
            if (phone.length() >= 3) {
                phonePrefix = encryptionUtil.deterministicEncrypt(phone.substring(0, 3));
            }

            // 전화번호 뒤 4자리를 결정적 암호화하여 검색에 활용
            if (phone.length() >= 4) {
                int phoneLength = phone.length();
                phoneSuffix = encryptionUtil.deterministicEncrypt(
                        phone.substring(phoneLength - 4));
            }
        }

        // 주민등록번호 암호화 (있는 경우)
        String ssnEncrypted = null;
        String ssnPrefix = null;
        String ssnGenderDigit = null;

        if (ssn != null && !ssn.isEmpty()) {
            ssnEncrypted = encryptionUtil.encryptStrongly(ssn);

            // 주민등록번호 앞 6자리(생년월일)를 결정적 암호화하여 검색에 활용
            if (ssn.length() >= 6) {
                ssnPrefix = encryptionUtil.deterministicEncrypt(ssn.substring(0, 6));
            }

            // 주민등록번호 성별자리를 결정적 암호화하여 검색에 활용
            String genderDigit = encryptionUtil.extractSsnGenderDigit(ssn);
            if (!genderDigit.isEmpty()) {
                ssnGenderDigit = encryptionUtil.deterministicEncrypt(genderDigit);
            }
        }

        // 사용자 정보 업데이트
        user.updateUserInfo(nameEncrypted, nameSearchable, nameInitial,
                phoneEncrypted, phonePrefix, phoneSuffix,
                ssnEncrypted, ssnPrefix, ssnGenderDigit, email);

        // 주소 정보 업데이트
        if (addressDto != null) {
            String detailEncrypted = encryptionUtil.encryptStrongly(addressDto.getDetail());
            String detailSearchable = encryptionUtil.deterministicEncrypt(addressDto.getDetail());

            Address address = user.getAddress();
            if (address == null) {
                // 새 주소 생성
                address = Address.builder()
                        .zipCode(addressDto.getZipCode())
                        .region(addressDto.getRegion())
                        .regionCode(addressDto.getRegionCode())
                        .city(addressDto.getCity())
                        .cityCode(addressDto.getCityCode())
                        .detailEncrypted(detailEncrypted)
                        .detailSearchable(detailSearchable)
                        .build();
                user.setAddress(address);
            } else {
                // 기존 주소 업데이트
                address.updateAddress(
                        addressDto.getZipCode(),
                        addressDto.getRegion(),
                        addressDto.getRegionCode(),
                        addressDto.getCity(),
                        addressDto.getCityCode(),
                        detailEncrypted,
                        detailSearchable
                );
            }
        }

        // save() 호출 제거 - 더티 체킹을 통해 자동으로 업데이트됨
        // User updatedUser = userRepository.save(user);

        // 검색 인덱스 업데이트 (user 객체 사용)
        userIndexService.indexUser(user);

        // DTO 반환
        return ssn != null
                ? UserDto.fromEntity(user, name, phone, ssn)
                : UserDto.fromEntity(user, name, phone);
    }

    /**
     * 사용자 삭제
     */
    @Transactional
    public void deleteUser(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("ID가 " + id + "인 사용자를 찾을 수 없습니다."));

        // 검색 인덱스 삭제
        userIndexService.deleteUserIndex(id);

        // 사용자 삭제
        userRepository.delete(user);
    }

    /**
     * 이름으로 사용자 검색 (JPA 사용)
     */
    @Transactional(readOnly = true)
    public List<UserDto> searchUsersByName(String name) {
        String nameSearchable = encryptionUtil.deterministicEncrypt(name);
        List<User> users = userRepository.findByNameSearchable(nameSearchable);

        return users.stream()
                .map(user -> {
                    String decryptedName = encryptionUtil.decrypt(user.getNameEncrypted());
                    String decryptedPhone = encryptionUtil.decrypt(user.getPhoneEncrypted());
                    String decryptedSsn = null;

                    if (user.getSsnEncrypted() != null) {
                        decryptedSsn = encryptionUtil.decrypt(user.getSsnEncrypted());
                    }

                    return decryptedSsn != null
                            ? UserDto.fromEntity(user, decryptedName, decryptedPhone, decryptedSsn)
                            : UserDto.fromEntity(user, decryptedName, decryptedPhone);
                })
                .collect(Collectors.toList());
    }

    /**
     * 전화번호 앞자리로 사용자 검색 (JPA 사용)
     */
    @Transactional(readOnly = true)
    public List<UserDto> searchUsersByPhonePrefix(String phonePrefix) {
        String phonePrefixSearchable = encryptionUtil.deterministicEncrypt(phonePrefix);
        List<User> users = userRepository.findByPhonePrefix(phonePrefixSearchable);

        return users.stream()
                .map(user -> {
                    String decryptedName = encryptionUtil.decrypt(user.getNameEncrypted());
                    String decryptedPhone = encryptionUtil.decrypt(user.getPhoneEncrypted());
                    String decryptedSsn = null;

                    if (user.getSsnEncrypted() != null) {
                        decryptedSsn = encryptionUtil.decrypt(user.getSsnEncrypted());
                    }

                    return decryptedSsn != null
                            ? UserDto.fromEntity(user, decryptedName, decryptedPhone, decryptedSsn)
                            : UserDto.fromEntity(user, decryptedName, decryptedPhone);
                })
                .collect(Collectors.toList());
    }

    /**
     * 전화번호 뒷자리로 사용자 검색 (JPA 사용)
     */
    @Transactional(readOnly = true)
    public List<UserDto> searchUsersByPhoneSuffix(String phoneSuffix) {
        String phoneSuffixSearchable = encryptionUtil.deterministicEncrypt(phoneSuffix);
        List<User> users = userRepository.findByPhoneSuffix(phoneSuffixSearchable);

        return users.stream()
                .map(user -> {
                    String decryptedName = encryptionUtil.decrypt(user.getNameEncrypted());
                    String decryptedPhone = encryptionUtil.decrypt(user.getPhoneEncrypted());
                    String decryptedSsn = null;

                    if (user.getSsnEncrypted() != null) {
                        decryptedSsn = encryptionUtil.decrypt(user.getSsnEncrypted());
                    }

                    return decryptedSsn != null
                            ? UserDto.fromEntity(user, decryptedName, decryptedPhone, decryptedSsn)
                            : UserDto.fromEntity(user, decryptedName, decryptedPhone);
                })
                .collect(Collectors.toList());
    }

    /**
     * 주민등록번호 앞자리로 사용자 검색 (JPA 사용)
     */
    @Transactional(readOnly = true)
    public List<UserDto> searchUsersBySsnPrefix(String ssnPrefix) {
        String ssnPrefixSearchable = encryptionUtil.deterministicEncrypt(ssnPrefix);
        List<User> users = userRepository.findBySsnPrefix(ssnPrefixSearchable);

        return users.stream()
                .map(user -> {
                    String decryptedName = encryptionUtil.decrypt(user.getNameEncrypted());
                    String decryptedPhone = encryptionUtil.decrypt(user.getPhoneEncrypted());
                    String decryptedSsn = null;

                    if (user.getSsnEncrypted() != null) {
                        decryptedSsn = encryptionUtil.decrypt(user.getSsnEncrypted());
                    }

                    return decryptedSsn != null
                            ? UserDto.fromEntity(user, decryptedName, decryptedPhone, decryptedSsn)
                            : UserDto.fromEntity(user, decryptedName, decryptedPhone);
                })
                .collect(Collectors.toList());
    }

    /**
     * 이름 초성으로 사용자 검색 (JPA 사용)
     */
    @Transactional(readOnly = true)
    public List<UserDto> searchUsersByNameInitial(String nameInitial) {
        List<User> users = userRepository.findByNameInitialContaining(nameInitial);

        return users.stream()
                .map(user -> {
                    String decryptedName = encryptionUtil.decrypt(user.getNameEncrypted());
                    String decryptedPhone = encryptionUtil.decrypt(user.getPhoneEncrypted());
                    String decryptedSsn = null;

                    if (user.getSsnEncrypted() != null) {
                        decryptedSsn = encryptionUtil.decrypt(user.getSsnEncrypted());
                    }

                    return decryptedSsn != null
                            ? UserDto.fromEntity(user, decryptedName, decryptedPhone, decryptedSsn)
                            : UserDto.fromEntity(user, decryptedName, decryptedPhone);
                })
                .collect(Collectors.toList());
    }

    /**
     * 지역으로 사용자 검색 (JPA 사용)
     */
    @Transactional(readOnly = true)
    public List<UserDto> searchUsersByRegion(String region) {
        List<User> users = userRepository.findByRegion(region);

        return users.stream()
                .map(user -> {
                    String decryptedName = encryptionUtil.decrypt(user.getNameEncrypted());
                    String decryptedPhone = encryptionUtil.decrypt(user.getPhoneEncrypted());
                    String decryptedSsn = null;

                    if (user.getSsnEncrypted() != null) {
                        decryptedSsn = encryptionUtil.decrypt(user.getSsnEncrypted());
                    }

                    return decryptedSsn != null
                            ? UserDto.fromEntity(user, decryptedName, decryptedPhone, decryptedSsn)
                            : UserDto.fromEntity(user, decryptedName, decryptedPhone);
                })
                .collect(Collectors.toList());
    }

    /**
     * 전화번호 뒷자리와 이름으로 사용자 검색 (JPA 사용)
     * - 고객센터에서 많이 사용하는 검색 방식
     */
    @Transactional(readOnly = true)
    public List<UserDto> searchUsersByPhoneSuffixAndName(String phoneSuffix, String name) {
        String phoneSuffixSearchable = encryptionUtil.deterministicEncrypt(phoneSuffix);
        String nameSearchable = encryptionUtil.deterministicEncrypt(name);

        List<User> users = userRepository.findByPhoneSuffixAndNameSearchable(phoneSuffixSearchable, nameSearchable);

        return users.stream()
                .map(user -> {
                    String decryptedName = encryptionUtil.decrypt(user.getNameEncrypted());
                    String decryptedPhone = encryptionUtil.decrypt(user.getPhoneEncrypted());
                    String decryptedSsn = null;

                    if (user.getSsnEncrypted() != null) {
                        decryptedSsn = encryptionUtil.decrypt(user.getSsnEncrypted());
                    }

                    return decryptedSsn != null
                            ? UserDto.fromEntity(user, decryptedName, decryptedPhone, decryptedSsn)
                            : UserDto.fromEntity(user, decryptedName, decryptedPhone);
                })
                .collect(Collectors.toList());
    }
}
package com.personaldata.encryption.domain.user.service;

import com.personaldata.encryption.domain.user.document.UserSearchDocument;
import com.personaldata.encryption.domain.user.dto.UserDto;
import com.personaldata.encryption.domain.user.entity.User;
import com.personaldata.encryption.domain.user.repository.UserRepository;
import com.personaldata.encryption.domain.user.repository.UserSearchRepository;
import com.personaldata.encryption.global.utils.EncryptionUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.elasticsearch.core.ElasticsearchOperations;
import org.springframework.data.elasticsearch.core.SearchHit;
import org.springframework.data.elasticsearch.core.SearchHits;
import org.springframework.data.elasticsearch.core.query.Criteria;
import org.springframework.data.elasticsearch.core.query.CriteriaQuery;
import org.springframework.data.elasticsearch.core.query.Query;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.stream.Collectors;

/**
 * 사용자 검색 서비스
 * ElasticSearch를 활용한 고급 검색 기능 제공
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class UserSearchService {

    private final UserRepository userRepository;
    private final UserSearchRepository userSearchRepository;
    private final ElasticsearchOperations elasticsearchOperations;
    private final EncryptionUtil encryptionUtil;

    /**
     * 이름으로 사용자 검색 (ElasticSearch 사용)
     */
    @Transactional(readOnly = true)
    public List<UserDto> searchUsersByName(String name, Pageable pageable) {
        // 이름 검색을 위해 결정적 암호화
        String nameSearchable = encryptionUtil.deterministicEncrypt(name);

        Page<UserSearchDocument> searchResults = userSearchRepository.findByNameSearchable(nameSearchable, pageable);

        return convertToUserDtos(searchResults.getContent());
    }

    /**
     * 이름 초성으로 사용자 검색 (ElasticSearch 사용)
     */
    @Transactional(readOnly = true)
    public List<UserDto> searchUsersByNameInitial(String nameInitial, Pageable pageable) {
        Page<UserSearchDocument> searchResults = userSearchRepository.findByNameInitialContaining(nameInitial, pageable);

        return convertToUserDtos(searchResults.getContent());
    }

    /**
     * 전화번호 앞자리로 사용자 검색 (ElasticSearch 사용)
     */
    @Transactional(readOnly = true)
    public List<UserDto> searchUsersByPhonePrefix(String phonePrefix, Pageable pageable) {
        // 전화번호 앞자리 결정적 암호화
        String phonePrefixSearchable = encryptionUtil.deterministicEncrypt(phonePrefix);

        Page<UserSearchDocument> searchResults = userSearchRepository.findByPhonePrefix(phonePrefixSearchable, pageable);

        return convertToUserDtos(searchResults.getContent());
    }

    /**
     * 전화번호 뒷자리로 사용자 검색 (ElasticSearch 사용)
     */
    @Transactional(readOnly = true)
    public List<UserDto> searchUsersByPhoneSuffix(String phoneSuffix, Pageable pageable) {
        // 전화번호 뒷자리 결정적 암호화
        String phoneSuffixSearchable = encryptionUtil.deterministicEncrypt(phoneSuffix);

        Page<UserSearchDocument> searchResults = userSearchRepository.findByPhoneSuffix(phoneSuffixSearchable, pageable);

        return convertToUserDtos(searchResults.getContent());
    }

    /**
     * 주민등록번호 앞자리(생년월일)로 사용자 검색 (ElasticSearch 사용)
     */
    @Transactional(readOnly = true)
    public List<UserDto> searchUsersBySsnPrefix(String ssnPrefix, Pageable pageable) {
        // 주민등록번호 앞자리 결정적 암호화
        String ssnPrefixSearchable = encryptionUtil.deterministicEncrypt(ssnPrefix);

        Page<UserSearchDocument> searchResults = userSearchRepository.findBySsnPrefix(ssnPrefixSearchable, pageable);

        return convertToUserDtos(searchResults.getContent());
    }

    /**
     * 주민등록번호 성별자리로 사용자 검색 (ElasticSearch 사용)
     */
    @Transactional(readOnly = true)
    public List<UserDto> searchUsersBySsnGenderDigit(String ssnGenderDigit, Pageable pageable) {
        // 주민등록번호 성별자리 결정적 암호화
        String ssnGenderDigitSearchable = encryptionUtil.deterministicEncrypt(ssnGenderDigit);

        Page<UserSearchDocument> searchResults = userSearchRepository.findBySsnGenderDigit(ssnGenderDigitSearchable, pageable);

        return convertToUserDtos(searchResults.getContent());
    }

    /**
     * 지역으로 사용자 검색 (ElasticSearch 사용)
     */
    @Transactional(readOnly = true)
    public List<UserDto> searchUsersByRegion(String region, Pageable pageable) {
        Page<UserSearchDocument> searchResults = userSearchRepository.findByRegion(region, pageable);

        return convertToUserDtos(searchResults.getContent());
    }

    /**
     * 이메일 도메인으로 사용자 검색 (ElasticSearch 사용)
     */
    @Transactional(readOnly = true)
    public List<UserDto> searchUsersByEmailDomain(String emailDomain, Pageable pageable) {
        Page<UserSearchDocument> searchResults = userSearchRepository.findByEmailDomain(emailDomain, pageable);

        return convertToUserDtos(searchResults.getContent());
    }

    /**
     * 복합 조건으로 사용자 검색 (ElasticSearch 사용)
     */
    @Transactional(readOnly = true)
    public List<UserDto> searchUsers(String name, String nameInitial, String phonePrefix, String phoneSuffix,
                                     String ssnPrefix, String ssnGenderDigit,
                                     String region, String city, Pageable pageable) {
        // 검색 기준 생성
        Criteria criteria = new Criteria();

        // 이름이 있으면 결정적 암호화하여 검색 조건 추가
        if (StringUtils.hasText(name)) {
            String nameSearchable = encryptionUtil.deterministicEncrypt(name);
            criteria = criteria.and(new Criteria("nameSearchable").is(nameSearchable));
        }

        // 이름 초성이 있으면 검색 조건 추가
        if (StringUtils.hasText(nameInitial)) {
            criteria = criteria.and(new Criteria("nameInitial").contains(nameInitial));
        }

        // 전화번호 앞자리가 있으면 결정적 암호화하여 검색 조건 추가
        if (StringUtils.hasText(phonePrefix)) {
            String phonePrefixSearchable = encryptionUtil.deterministicEncrypt(phonePrefix);
            criteria = criteria.and(new Criteria("phonePrefix").is(phonePrefixSearchable));
        }

        // 전화번호 뒷자리가 있으면 결정적 암호화하여 검색 조건 추가
        if (StringUtils.hasText(phoneSuffix)) {
            String phoneSuffixSearchable = encryptionUtil.deterministicEncrypt(phoneSuffix);
            criteria = criteria.and(new Criteria("phoneSuffix").is(phoneSuffixSearchable));
        }

        // 주민등록번호 앞자리가 있으면 결정적 암호화하여 검색 조건 추가
        if (StringUtils.hasText(ssnPrefix)) {
            String ssnPrefixSearchable = encryptionUtil.deterministicEncrypt(ssnPrefix);
            criteria = criteria.and(new Criteria("ssnPrefix").is(ssnPrefixSearchable));
        }

        // 주민등록번호 성별자리가 있으면 결정적 암호화하여 검색 조건 추가
        if (StringUtils.hasText(ssnGenderDigit)) {
            String ssnGenderDigitSearchable = encryptionUtil.deterministicEncrypt(ssnGenderDigit);
            criteria = criteria.and(new Criteria("ssnGenderDigit").is(ssnGenderDigitSearchable));
        }

        // 지역이 있으면 검색 조건 추가
        if (StringUtils.hasText(region)) {
            criteria = criteria.and(new Criteria("region").is(region));
        }

        // 도시가 있으면 검색 조건 추가
        if (StringUtils.hasText(city)) {
            criteria = criteria.and(new Criteria("city").is(city));
        }

        // 쿼리 생성 및 실행
        Query query = new CriteriaQuery(criteria).setPageable(pageable);
        SearchHits<UserSearchDocument> searchHits = elasticsearchOperations.search(query, UserSearchDocument.class);

        List<UserSearchDocument> searchResults = searchHits.getSearchHits().stream()
                .map(SearchHit::getContent)
                .collect(Collectors.toList());

        return convertToUserDtos(searchResults);
    }

    /**
     * 전화번호 뒷자리와 이름으로 사용자 검색 (ElasticSearch 사용)
     * - 흔히 고객센터에서 많이 사용하는 검색 방식
     */
    @Transactional(readOnly = true)
    public List<UserDto> searchUsersByPhoneSuffixAndName(String phoneSuffix, String name, Pageable pageable) {
        // 결정적 암호화하여 검색
        String phoneSuffixSearchable = encryptionUtil.deterministicEncrypt(phoneSuffix);
        String nameSearchable = encryptionUtil.deterministicEncrypt(name);

        Page<UserSearchDocument> searchResults = userSearchRepository.findByPhoneSuffixAndNameSearchable(
                phoneSuffixSearchable, nameSearchable, pageable);

        return convertToUserDtos(searchResults.getContent());
    }

    /**
     * 주민등록번호 앞자리(생년월일)와 성별자리로 사용자 검색 (ElasticSearch 사용)
     */
    @Transactional(readOnly = true)
    public List<UserDto> searchUsersBySsnPrefixAndGenderDigit(String ssnPrefix, String ssnGenderDigit, Pageable pageable) {
        // 결정적 암호화하여 검색
        String ssnPrefixSearchable = encryptionUtil.deterministicEncrypt(ssnPrefix);
        String ssnGenderDigitSearchable = encryptionUtil.deterministicEncrypt(ssnGenderDigit);

        Page<UserSearchDocument> searchResults = userSearchRepository.findBySsnPrefixAndSsnGenderDigit(
                ssnPrefixSearchable, ssnGenderDigitSearchable, pageable);

        return convertToUserDtos(searchResults.getContent());
    }

    /**
     * 검색 결과를 UserDto로 변환
     */
    private List<UserDto> convertToUserDtos(List<UserSearchDocument> searchResults) {
        return searchResults.stream()
                .map(doc -> {
                    try {
                        // ID로 사용자 조회
                        Long userId = Long.parseLong(doc.getId());
                        User user = userRepository.findById(userId).orElse(null);

                        if (user != null) {
                            // 민감 정보 복호화
                            String decryptedName = encryptionUtil.decrypt(user.getNameEncrypted());
                            String decryptedPhone = encryptionUtil.decrypt(user.getPhoneEncrypted());
                            String decryptedSsn = null;

                            // 주민등록번호가 있는 경우에만 복호화
                            if (user.getSsnEncrypted() != null) {
                                decryptedSsn = encryptionUtil.decrypt(user.getSsnEncrypted());
                                return UserDto.fromEntity(user, decryptedName, decryptedPhone, decryptedSsn);
                            } else {
                                return UserDto.fromEntity(user, decryptedName, decryptedPhone);
                            }
                        }
                    } catch (Exception e) {
                        log.error("사용자 정보 변환 실패: ID={}, 원인={}", doc.getId(), e.getMessage(), e);
                    }
                    return null;
                })
                .filter(dto -> dto != null)
                .collect(Collectors.toList());
    }
}
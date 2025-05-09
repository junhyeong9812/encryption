package com.personaldata.encryption.domain.user.repository;

import com.personaldata.encryption.domain.user.document.UserSearchDocument;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.elasticsearch.annotations.Query;
import org.springframework.data.elasticsearch.core.SearchHit;
import org.springframework.data.elasticsearch.repository.ElasticsearchRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * 사용자 검색을 위한 엘라스틱서치 리포지토리
 */
@Repository
public interface UserSearchRepository extends ElasticsearchRepository<UserSearchDocument, String> {

    /**
     * 결정적 암호화된 이름으로 사용자 검색
     */
    Page<UserSearchDocument> findByNameSearchable(String nameSearchable, Pageable pageable);

    /**
     * 이름 초성으로 사용자 검색
     */
    Page<UserSearchDocument> findByNameInitialContaining(String nameInitial, Pageable pageable);

    /**
     * 전화번호 앞자리로 사용자 검색
     */
    Page<UserSearchDocument> findByPhonePrefix(String phonePrefix, Pageable pageable);

    /**
     * 전화번호 뒷자리로 사용자 검색
     */
    Page<UserSearchDocument> findByPhoneSuffix(String phoneSuffix, Pageable pageable);

    /**
     * 주민등록번호 앞자리(생년월일)로 사용자 검색
     */
    Page<UserSearchDocument> findBySsnPrefix(String ssnPrefix, Pageable pageable);

    /**
     * 주민등록번호 성별자리로 사용자 검색
     */
    Page<UserSearchDocument> findBySsnGenderDigit(String ssnGenderDigit, Pageable pageable);

    /**
     * 이메일 도메인으로 사용자 검색
     */
    Page<UserSearchDocument> findByEmailDomain(String emailDomain, Pageable pageable);

    /**
     * 지역별 사용자 검색
     */
    Page<UserSearchDocument> findByRegion(String region, Pageable pageable);

    /**
     * 도시별 사용자 검색
     */
    Page<UserSearchDocument> findByCity(String city, Pageable pageable);

    /**
     * 지역 코드별 사용자 검색
     */
    Page<UserSearchDocument> findByRegionCode(String regionCode, Pageable pageable);

    /**
     * 도시 코드별 사용자 검색
     */
    Page<UserSearchDocument> findByCityCode(String cityCode, Pageable pageable);

    /**
     * 주소 키워드로 사용자 검색
     */
    Page<UserSearchDocument> findByAddressDetailSearchable(String addressDetailSearchable, Pageable pageable);

    /**
     * 복합 조건 검색 (이름 + 지역)
     */
    Page<UserSearchDocument> findByNameSearchableAndRegion(String nameSearchable, String region, Pageable pageable);

    /**
     * 복합 조건 검색 (전화번호 뒷자리 + 이름)
     */
    Page<UserSearchDocument> findByPhoneSuffixAndNameSearchable(String phoneSuffix, String nameSearchable, Pageable pageable);

    /**
     * 복합 조건 검색 (주민번호 앞자리 + 성별자리)
     */
    Page<UserSearchDocument> findBySsnPrefixAndSsnGenderDigit(String ssnPrefix, String ssnGenderDigit, Pageable pageable);

    /**
     * 상세 검색을 위한 쿼리 DSL 사용
     */
    @Query("{\"bool\": {\"must\": [{\"term\": {\"nameSearchable\": \"?0\"}}, {\"term\": {\"regionCode\": \"?1\"}}]}}")
    List<SearchHit<UserSearchDocument>> searchByNameAndRegion(String nameSearchable, String regionCode, Pageable pageable);

    /**
     * 페이징 없는 메서드들 (필요한 경우 사용)
     */
    List<UserSearchDocument> findByNameSearchable(String nameSearchable);
    List<UserSearchDocument> findByNameInitialContaining(String nameInitial);
    List<UserSearchDocument> findByPhonePrefix(String phonePrefix);
    List<UserSearchDocument> findByPhoneSuffix(String phoneSuffix);
    List<UserSearchDocument> findBySsnPrefix(String ssnPrefix);
    List<UserSearchDocument> findByRegion(String region);
}
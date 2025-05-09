package com.personaldata.encryption.domain.user.service;

import com.personaldata.encryption.domain.user.document.UserSearchDocument;
import com.personaldata.encryption.domain.user.entity.User;
import com.personaldata.encryption.domain.user.repository.UserRepository;
import com.personaldata.encryption.domain.user.repository.UserSearchRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.elasticsearch.core.ElasticsearchOperations;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * 사용자 검색 인덱스 관리 서비스
 * ElasticSearch 문서 인덱싱 담당
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class UserIndexService {

    private final UserRepository userRepository;
    private final UserSearchRepository userSearchRepository;
    private final ElasticsearchOperations elasticsearchOperations;

    /**
     * 사용자 정보를 ElasticSearch 인덱스에 저장
     *
     * @param user 인덱싱할 사용자 정보
     */
    @Transactional
    public void indexUser(User user) {
        try {
            // 이메일 도메인 추출 (검색용)
            String emailDomain = extractEmailDomain(user.getEmail());

            // UserSearchDocument 생성
            UserSearchDocument document = UserSearchDocument.builder()
                    .id(user.getId().toString())
                    .nameSearchable(user.getNameSearchable())
                    .nameInitial(user.getNameInitial())
                    .phonePrefix(user.getPhonePrefix())
                    .emailDomain(emailDomain)
                    .build();

            // 주소 정보가 있는 경우 추가
            if (user.getAddress() != null) {
                document.setRegion(user.getAddress().getRegion());
                document.setRegionCode(user.getAddress().getRegionCode());
                document.setCity(user.getAddress().getCity());
                document.setCityCode(user.getAddress().getCityCode());
                document.setAddressDetailSearchable(user.getAddress().getDetailSearchable());
            }

            // ElasticSearch에 저장
            userSearchRepository.save(document);

            log.info("사용자 인덱싱 완료: ID={}", user.getId());
        } catch (Exception e) {
            log.error("사용자 인덱싱 실패: ID={}, 원인={}", user.getId(), e.getMessage(), e);
            // 인덱싱 실패 시에도 트랜잭션은 커밋 (DB 저장은 유지)
            // 재시도 메커니즘 구현 필요 (운영 환경)
        }
    }

    /**
     * 모든 사용자 정보를 ElasticSearch 인덱스에 저장 (대량 인덱싱)
     */
    @Async
    @Transactional(readOnly = true)
    public void indexAllUsers() {
        log.info("모든 사용자 인덱싱 시작");

        try {
            long count = 0;
            for (User user : userRepository.findAll()) {
                indexUser(user);
                count++;

                // 로깅 진행 상황
                if (count % 100 == 0) {
                    log.info("사용자 인덱싱 진행 중: {} 건 완료", count);
                }
            }

            log.info("모든 사용자 인덱싱 완료: 총 {} 건", count);
        } catch (Exception e) {
            log.error("모든 사용자 인덱싱 실패: 원인={}", e.getMessage(), e);
        }
    }

    /**
     * 사용자 인덱스 삭제
     *
     * @param userId 삭제할 사용자 ID
     */
    @Transactional
    public void deleteUserIndex(Long userId) {
        try {
            userSearchRepository.deleteById(userId.toString());
            log.info("사용자 인덱스 삭제 완료: ID={}", userId);
        } catch (Exception e) {
            log.error("사용자 인덱스 삭제 실패: ID={}, 원인={}", userId, e.getMessage(), e);
        }
    }

    /**
     * 인덱스 재생성 (전체 인덱스 재구축)
     */
    @Async
    @Transactional(readOnly = true)
    public void rebuildIndex() {
        log.info("인덱스 재생성 시작");

        try {
            // 기존 인덱스 삭제
            userSearchRepository.deleteAll();

            // 새로 인덱스 생성
            indexAllUsers();

            log.info("인덱스 재생성 완료");
        } catch (Exception e) {
            log.error("인덱스 재생성 실패: 원인={}", e.getMessage(), e);
        }
    }

    /**
     * 이메일에서 도메인 부분 추출
     *
     * @param email 이메일 주소
     * @return 도메인 부분
     */
    private String extractEmailDomain(String email) {
        if (email == null || email.isEmpty() || !email.contains("@")) {
            return "";
        }
        return email.substring(email.indexOf('@') + 1);
    }
}
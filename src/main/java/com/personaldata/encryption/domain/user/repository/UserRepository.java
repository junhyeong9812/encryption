package com.personaldata.encryption.domain.user.repository;

import com.personaldata.encryption.domain.user.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * 사용자 정보에 접근하는 리포지토리
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    /**
     * 결정적 암호화된 이름으로 사용자 찾기
     */
    List<User> findByNameSearchable(String nameSearchable);

    /**
     * 이름 초성으로 사용자 찾기
     */
    List<User> findByNameInitialContaining(String nameInitial);

    /**
     * 결정적 암호화된 전화번호 앞자리로 사용자 찾기
     */
    List<User> findByPhonePrefix(String phonePrefix);

    /**
     * 이메일로 사용자 찾기
     */
    Optional<User> findByEmail(String email);

    /**
     * 주소 정보로 사용자 찾기 (JPQL 사용)
     */
    @Query("SELECT u FROM User u JOIN u.address a WHERE a.region = :region")
    List<User> findByRegion(@Param("region") String region);

    /**
     * 주소 정보로 사용자 찾기 (JPQL 사용)
     */
    @Query("SELECT u FROM User u JOIN u.address a WHERE a.city = :city")
    List<User> findByCity(@Param("city") String city);

    /**
     * 주소 정보로 사용자 찾기 (JPQL 사용)
     */
    @Query("SELECT u FROM User u JOIN u.address a WHERE a.regionCode = :regionCode")
    List<User> findByRegionCode(@Param("regionCode") String regionCode);

    /**
     * 주소 정보로 사용자 찾기 (JPQL 사용)
     */
    @Query("SELECT u FROM User u JOIN u.address a WHERE a.cityCode = :cityCode")
    List<User> findByCityCode(@Param("cityCode") String cityCode);
}
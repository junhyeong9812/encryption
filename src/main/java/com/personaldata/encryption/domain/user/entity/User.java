package com.personaldata.encryption.domain.user.entity;

import com.personaldata.encryption.global.entity.BaseEntity;
import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;

/**
 * 사용자 정보를 저장하는 엔티티
 * 암호화된 개인정보와 검색용 인덱스 값을 함께 관리
 * Spring Security의 UserDetails를 구현하여 인증에 활용
 */
@Entity
@Table(name = "users")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class User extends BaseEntity implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * 암호화된 이름 (복호화 가능한 암호화)
     */
    @Column(name = "name_encrypted", nullable = false)
    private String nameEncrypted;

    /**
     * 결정적 암호화된 이름 (검색용)
     */
    @Column(name = "name_searchable", nullable = false)
    private String nameSearchable;

    /**
     * 이름 초성 (한글 검색용)
     */
    @Column(name = "name_initial")
    private String nameInitial;

    /**
     * 암호화된 전화번호 (복호화 가능한 암호화)
     */
    @Column(name = "phone_encrypted", nullable = false)
    private String phoneEncrypted;

    /**
     * 결정적 암호화된 전화번호 앞자리 (검색용)
     */
    @Column(name = "phone_prefix")
    private String phonePrefix;

    /**
     * 사용자 이메일 (로그인 ID로 사용)
     */
    @Column(name = "email", unique = true, nullable = false)
    private String email;

    /**
     * 비밀번호 (BCrypt로 암호화됨)
     */
    @Column(name = "password", nullable = false)
    private String password;

    /**
     * 사용자 권한
     */
    @Column(name = "role", nullable = false)
    private String role;

    /**
     * 계정 활성화 여부
     */
    @Column(name = "enabled", nullable = false)
    private boolean enabled;

    /**
     * 계정 잠금 여부
     */
    @Column(name = "account_non_locked", nullable = false)
    private boolean accountNonLocked;

    /**
     * 자격 증명 만료 여부
     */
    @Column(name = "credentials_non_expired", nullable = false)
    private boolean credentialsNonExpired;

    /**
     * 계정 만료 여부
     */
    @Column(name = "account_non_expired", nullable = false)
    private boolean accountNonExpired;

    /**
     * 사용자 주소 참조
     */
    @OneToOne(cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @JoinColumn(name = "address_id")
    private Address address;

    /**
     * 생성자
     */
    @Builder
    public User(String nameEncrypted, String nameSearchable, String nameInitial,
                String phoneEncrypted, String phonePrefix, String email, String password,
                String role, Boolean enabled, Boolean accountNonLocked,
                Boolean credentialsNonExpired, Boolean accountNonExpired, Address address) {
        this.nameEncrypted = nameEncrypted;
        this.nameSearchable = nameSearchable;
        this.nameInitial = nameInitial;
        this.phoneEncrypted = phoneEncrypted;
        this.phonePrefix = phonePrefix;
        this.email = email;
        this.password = password;
        this.role = role != null ? role : "ROLE_USER";
        this.enabled = enabled != null ? enabled : true;
        this.accountNonLocked = accountNonLocked != null ? accountNonLocked : true;
        this.credentialsNonExpired = credentialsNonExpired != null ? credentialsNonExpired : true;
        this.accountNonExpired = accountNonExpired != null ? accountNonExpired : true;
        this.address = address;
    }

    /**
     * 사용자 정보 업데이트
     */
    public void updateUserInfo(String nameEncrypted, String nameSearchable, String nameInitial,
                               String phoneEncrypted, String phonePrefix, String email) {
        this.nameEncrypted = nameEncrypted;
        this.nameSearchable = nameSearchable;
        this.nameInitial = nameInitial;
        this.phoneEncrypted = phoneEncrypted;
        this.phonePrefix = phonePrefix;
        this.email = email;
    }

    /**
     * 비밀번호 업데이트
     */
    public void updatePassword(String password) {
        this.password = password;
    }

    /**
     * 주소 설정
     */
    public void setAddress(Address address) {
        this.address = address;
    }

    /**
     * 계정 상태 업데이트
     */
    public void updateAccountStatus(Boolean enabled, Boolean accountNonLocked,
                                    Boolean credentialsNonExpired, Boolean accountNonExpired) {
        if (enabled != null) this.enabled = enabled;
        if (accountNonLocked != null) this.accountNonLocked = accountNonLocked;
        if (credentialsNonExpired != null) this.credentialsNonExpired = credentialsNonExpired;
        if (accountNonExpired != null) this.accountNonExpired = accountNonExpired;
    }

    /**
     * 권한 업데이트
     */
    public void updateRole(String role) {
        this.role = role;
    }

    // UserDetails 인터페이스 구현

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singleton(new SimpleGrantedAuthority(this.role));
    }

    @Override
    public String getUsername() {
        return this.email; // 이메일을 로그인 ID로 사용
    }

    @Override
    public boolean isAccountNonExpired() {
        return this.accountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return this.accountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return this.credentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return this.enabled;
    }
}
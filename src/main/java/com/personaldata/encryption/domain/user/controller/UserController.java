package com.personaldata.encryption.domain.user.controller;

import com.personaldata.encryption.domain.user.dto.AddressDto;
import com.personaldata.encryption.domain.user.dto.UserDto;
import com.personaldata.encryption.domain.user.service.UserSearchService;
import com.personaldata.encryption.domain.user.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 사용자 정보 관리 컨트롤러
 */
@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
@Tag(name = "사용자 API", description = "사용자 정보 조회, 수정, 검색 API")
public class UserController {

    private final UserService userService;
    private final UserSearchService userSearchService;

    /**
     * 사용자 정보 조회
     */
    @GetMapping("/{id}")
    @Operation(summary = "사용자 정보 조회", description = "사용자 ID로 사용자 정보를 조회합니다.")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<UserDto> getUserById(
            @Parameter(description = "사용자 ID", required = true) @PathVariable Long id) {

        // 본인 정보 또는 관리자만 접근 가능하도록 검증
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String currentEmail = authentication.getName();
        boolean isAdmin = authentication.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));

        UserDto user = userService.getUserById(id);
        if (!isAdmin && !user.getEmail().equals(currentEmail)) {
            return ResponseEntity.status(403).build(); // 접근 권한 없음
        }

        return ResponseEntity.ok(user);
    }

    /**
     * 현재 로그인한 사용자 정보 조회
     */
    @GetMapping("/me")
    @Operation(summary = "내 정보 조회", description = "현재 로그인한 사용자의 정보를 조회합니다.")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<UserDto> getMyInfo() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();

        UserDto user = userService.getUserByEmail(email);
        return ResponseEntity.ok(user);
    }

    /**
     * 사용자 정보 수정
     */
    @PutMapping("/{id}")
    @Operation(summary = "사용자 정보 수정", description = "사용자 정보를 수정합니다.")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<UserDto> updateUser(
            @Parameter(description = "사용자 ID", required = true) @PathVariable Long id,
            @RequestBody @Valid UserUpdateRequest request) {

        // 본인 정보 또는 관리자만 수정 가능하도록 검증
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String currentEmail = authentication.getName();
        boolean isAdmin = authentication.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));

        UserDto existingUser = userService.getUserById(id);
        if (!isAdmin && !existingUser.getEmail().equals(currentEmail)) {
            return ResponseEntity.status(403).build(); // 접근 권한 없음
        }

        UserDto updatedUser = userService.updateUser(
                id,
                request.getName(),
                request.getPhone(),
                request.getEmail(),
                request.getAddress()
        );

        return ResponseEntity.ok(updatedUser);
    }

    /**
     * 사용자 삭제
     */
    @DeleteMapping("/{id}")
    @Operation(summary = "사용자 삭제", description = "사용자를 삭제합니다.")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deleteUser(
            @Parameter(description = "사용자 ID", required = true) @PathVariable Long id) {

        userService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }

    /**
     * 이름으로 사용자 검색
     */
    @GetMapping("/search/name")
    @Operation(summary = "이름으로 사용자 검색", description = "이름으로 사용자를 검색합니다.")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<UserDto>> searchUsersByName(
            @Parameter(description = "이름", required = true) @RequestParam String name,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {

        Pageable pageable = PageRequest.of(page, size, Sort.by("id").descending());
        List<UserDto> users = userSearchService.searchUsersByName(name, pageable);

        return ResponseEntity.ok(users);
    }

    /**
     * 이름 초성으로 사용자 검색
     */
    @GetMapping("/search/initial")
    @Operation(summary = "이름 초성으로 사용자 검색", description = "이름 초성으로 사용자를 검색합니다.")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<UserDto>> searchUsersByNameInitial(
            @Parameter(description = "이름 초성", required = true) @RequestParam String initial,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {

        Pageable pageable = PageRequest.of(page, size, Sort.by("id").descending());
        List<UserDto> users = userSearchService.searchUsersByNameInitial(initial, pageable);

        return ResponseEntity.ok(users);
    }

    /**
     * 전화번호로 사용자 검색
     */
    @GetMapping("/search/phone")
    @Operation(summary = "전화번호로 사용자 검색", description = "전화번호 앞자리로 사용자를 검색합니다.")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<UserDto>> searchUsersByPhone(
            @Parameter(description = "전화번호 앞자리", required = true) @RequestParam String prefix,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {

        Pageable pageable = PageRequest.of(page, size, Sort.by("id").descending());
        List<UserDto> users = userSearchService.searchUsersByPhonePrefix(prefix, pageable);

        return ResponseEntity.ok(users);
    }

    /**
     * 지역으로 사용자 검색
     */
    @GetMapping("/search/region")
    @Operation(summary = "지역으로 사용자 검색", description = "지역으로 사용자를 검색합니다.")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<UserDto>> searchUsersByRegion(
            @Parameter(description = "지역", required = true) @RequestParam String region,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {

        Pageable pageable = PageRequest.of(page, size, Sort.by("id").descending());
        List<UserDto> users = userSearchService.searchUsersByRegion(region, pageable);

        return ResponseEntity.ok(users);
    }

    /**
     * 복합 조건으로 사용자 검색
     */
    @GetMapping("/search")
    @Operation(summary = "복합 조건으로 사용자 검색", description = "여러 조건을 조합하여 사용자를 검색합니다.")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<UserDto>> searchUsers(
            @RequestParam(required = false) String name,
            @RequestParam(required = false) String initial,
            @RequestParam(required = false) String phonePrefix,
            @RequestParam(required = false) String region,
            @RequestParam(required = false) String city,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {

        Pageable pageable = PageRequest.of(page, size, Sort.by("id").descending());
        List<UserDto> users = userSearchService.searchUsers(name, initial, phonePrefix, region, city, pageable);

        return ResponseEntity.ok(users);
    }

    /**
     * 사용자 정보 수정 요청 DTO
     */
    public static class UserUpdateRequest {
        private String name;
        private String phone;
        private String email;
        private AddressDto address;

        // Getter/Setter 생략
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public String getPhone() { return phone; }
        public void setPhone(String phone) { this.phone = phone; }
        public String getEmail() { return email; }
        public void setEmail(String email) { this.email = email; }
        public AddressDto getAddress() { return address; }
        public void setAddress(AddressDto address) { this.address = address; }
    }
}
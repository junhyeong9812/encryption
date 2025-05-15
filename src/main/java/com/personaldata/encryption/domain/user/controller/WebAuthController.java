package com.personaldata.encryption.domain.user.controller;

import com.personaldata.encryption.domain.user.dto.AuthDto;
import com.personaldata.encryption.domain.user.entity.User;
import com.personaldata.encryption.domain.user.service.AuthService;
import com.personaldata.encryption.global.security.TokenInfo;
import com.personaldata.encryption.global.utils.CookieUtil;
import com.personaldata.encryption.global.utils.SecurityUtils;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * 웹 클라이언트용 인증 컨트롤러
 * HTTP-only 쿠키 기반의 인증 처리
 */
@Slf4j
@RestController
@RequestMapping("/auth/web")
@RequiredArgsConstructor
@Tag(name = "웹 인증 API", description = "웹 클라이언트용 인증 API (쿠키 기반)")
public class WebAuthController {

    private final AuthService authService;
    private final CookieUtil cookieUtil;

    /**
     * 인증 상태 확인
     * SecurityContext에 인증 정보가 있는지 확인합니다.
     */
    @GetMapping("/status")
    @Operation(summary = "인증 상태 확인", description = "현재 인증 상태 정보를 반환합니다.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "상태 확인 성공")
    })
    public ResponseEntity<?> checkAuthStatus() {
        try {
            Map<String, Object> response = new HashMap<>();

            if (!SecurityUtils.isAuthenticated()) {
                // 인증되지 않은 사용자
                response.put("authenticated", false);
                log.debug("인증되지 않은 사용자의 상태 확인 요청");
            } else {
                // 인증된 사용자 정보 추출
                String email = SecurityUtils.getCurrentUserEmail();
                Long userId = SecurityUtils.getCurrentUserId();
                String role = SecurityUtils.isCurrentUserAdmin() ? "ROLE_ADMIN" : "ROLE_USER";

                // 응답 생성
                response.put("authenticated", true);
                response.put("userId", userId);
                response.put("email", email);
                response.put("role", role);

                log.info("인증된 사용자 상태 확인: userId={}, email={}", userId, email);
            }

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            // 예외 발생 시 인증되지 않은 상태로 응답
            log.warn("인증 상태 확인 중 오류 발생: {}", e.getMessage());
            Map<String, Object> response = new HashMap<>();
            response.put("authenticated", false);
            response.put("error", "인증 상태 확인 중 오류가 발생했습니다.");

            return ResponseEntity.ok(response);
        }
    }

    /**
     * 웹 회원가입
     */
    @PostMapping("/signup")
    @Operation(summary = "웹 회원가입", description = "웹 클라이언트용 회원가입 (HTTP-only 쿠키 사용)")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "회원가입 성공"),
            @ApiResponse(responseCode = "400", description = "잘못된 요청"),
            @ApiResponse(responseCode = "409", description = "이미 존재하는 이메일")
    })
    public ResponseEntity<?> signup(
            @Valid @RequestBody AuthDto.SignupRequest request,
            HttpServletResponse response) {
        try {
            // 회원가입 처리
            User user = authService.signup(request);

            // JWT 토큰 생성
            TokenInfo tokenInfo = authService.issueTokens(user);

            // HTTP-only 쿠키로 토큰 설정
            cookieUtil.addAuthCookies(response, tokenInfo);

            // 응답 생성 (토큰 정보 제외)
            AuthDto.WebResponseDto responseDto = AuthDto.WebResponseDto.builder()
                    .email(user.getEmail())
                    .role(user.getRole())
                    .maskedName(authService.maskName(request.getName()))
                    .authenticated(true)
                    .build();

            return ResponseEntity.ok(responseDto);
        } catch (IllegalArgumentException e) {
            // 중복 이메일 등의 예외 처리
            ErrorResponse errorResponse = new ErrorResponse(HttpStatus.CONFLICT.value(), e.getMessage());
            return ResponseEntity.status(HttpStatus.CONFLICT).body(errorResponse);
        } catch (Exception e) {
            // 기타 예외 처리
            log.error("웹 회원가입 처리 중 오류: {}", e.getMessage(), e);
            ErrorResponse errorResponse = new ErrorResponse(HttpStatus.BAD_REQUEST.value(), "회원가입 처리 중 오류가 발생했습니다.");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
        }
    }

    /**
     * 웹 로그인
     */
    @PostMapping("/login")
    @Operation(summary = "웹 로그인", description = "웹 클라이언트용 로그인 (HTTP-only 쿠키 사용)")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "로그인 성공"),
            @ApiResponse(responseCode = "401", description = "인증 실패")
    })
    public ResponseEntity<?> login(
            @Valid @RequestBody AuthDto.LoginRequest request,
            HttpServletResponse response) {
        try {
            // 로그인 처리 및 사용자 정보 조회
            User user = authService.login(request);

            // JWT 토큰 생성
            TokenInfo tokenInfo = authService.issueTokens(user);

            // HTTP-only 쿠키로 토큰 설정
            cookieUtil.addAuthCookies(response, tokenInfo);

            // 이름 복호화 및 마스킹
            String maskedName = authService.getMaskedName(user);

            // 응답 생성 (토큰 정보 제외)
            AuthDto.WebResponseDto responseDto = AuthDto.WebResponseDto.builder()
                    .email(user.getEmail())
                    .role(user.getRole())
                    .maskedName(maskedName)
                    .authenticated(true)
                    .build();

            return ResponseEntity.ok(responseDto);
        } catch (BadCredentialsException e) {
            // 인증 실패 예외 처리
            ErrorResponse errorResponse = new ErrorResponse(HttpStatus.UNAUTHORIZED.value(), "이메일 또는 비밀번호가 일치하지 않습니다.");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
        } catch (Exception e) {
            // 기타 예외 처리
            log.error("웹 로그인 처리 중 오류: {}", e.getMessage(), e);
            ErrorResponse errorResponse = new ErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR.value(), "로그인 처리 중 오류가 발생했습니다.");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * 웹 토큰 갱신
     */
    @PostMapping("/refresh")
    @Operation(summary = "웹 토큰 갱신", description = "웹 클라이언트용 토큰 갱신 (쿠키에서 리프레시 토큰 추출)")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "토큰 갱신 성공"),
            @ApiResponse(responseCode = "401", description = "유효하지 않은 리프레시 토큰")
    })
    public ResponseEntity<?> refreshToken(
            HttpServletRequest request,
            HttpServletResponse response) {
        try {
            // 쿠키에서 리프레시 토큰 추출
            String refreshToken = extractCookieValue(request, "refresh_token");

            if (!StringUtils.hasText(refreshToken)) {
                throw new IllegalArgumentException("리프레시 토큰이 없습니다.");
            }

            // 리프레시 토큰으로 새 액세스 토큰 발급
            TokenInfo tokenInfo = authService.refreshAccessToken(refreshToken);

            // 쿠키 갱신
            cookieUtil.addAuthCookies(response, tokenInfo);

            return ResponseEntity.ok().build();
        } catch (IllegalArgumentException e) {
            // 잘못된 토큰 예외 처리
            log.warn("웹 토큰 갱신 실패: {}", e.getMessage());
            ErrorResponse errorResponse = new ErrorResponse(HttpStatus.UNAUTHORIZED.value(), e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
        } catch (Exception e) {
            // 기타 예외 처리
            log.error("웹 토큰 갱신 중 오류: {}", e.getMessage(), e);
            ErrorResponse errorResponse = new ErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR.value(), "토큰 갱신 중 오류가 발생했습니다.");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * 웹 로그아웃
     */
    @PostMapping("/logout")
    @Operation(summary = "웹 로그아웃", description = "웹 클라이언트용 로그아웃 (인증 쿠키 삭제)")
    @PreAuthorize("isAuthenticated()")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "로그아웃 성공"),
            @ApiResponse(responseCode = "401", description = "인증되지 않은 사용자")
    })
    public ResponseEntity<?> logout(
            HttpServletRequest request,
            HttpServletResponse response) {
        try {
            // 사용자 ID 추출
            Long userId = SecurityUtils.getCurrentUserId();

            // 쿠키에서 액세스 토큰 추출
            String accessToken = extractCookieValue(request, "access_token");

            // 토큰 무효화
            if (StringUtils.hasText(accessToken)) {
                authService.logout(accessToken, userId);
            }

            // 인증 쿠키 삭제
            cookieUtil.clearAuthCookies(response);

            return ResponseEntity.ok().build();
        } catch (Exception e) {
            // 예외 처리
            log.error("웹 로그아웃 처리 중 오류: {}", e.getMessage(), e);
            ErrorResponse errorResponse = new ErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR.value(), "로그아웃 처리 중 오류가 발생했습니다.");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * 비밀번호 변경
     */
    @PostMapping("/password")
    @Operation(summary = "비밀번호 변경", description = "로그인한 사용자의 비밀번호를 변경합니다.")
    @PreAuthorize("isAuthenticated()")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "비밀번호 변경 성공"),
            @ApiResponse(responseCode = "400", description = "잘못된 요청"),
            @ApiResponse(responseCode = "401", description = "인증 실패")
    })
    public ResponseEntity<?> changePassword(@Valid @RequestBody AuthDto.PasswordChangeRequest request) {
        try {
            // 현재 인증된 사용자 이메일 가져오기
            String email = SecurityUtils.getCurrentUserEmail();

            // 비밀번호 변경 처리
            authService.changePassword(email, request);

            return ResponseEntity.ok().build();
        } catch (BadCredentialsException e) {
            // 현재 비밀번호 불일치 예외 처리
            ErrorResponse errorResponse = new ErrorResponse(HttpStatus.UNAUTHORIZED.value(), e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
        } catch (IllegalArgumentException e) {
            // 새 비밀번호 형식 오류 또는 확인 불일치 예외 처리
            ErrorResponse errorResponse = new ErrorResponse(HttpStatus.BAD_REQUEST.value(), e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
        } catch (Exception e) {
            // 기타 예외 처리
            log.error("비밀번호 변경 중 오류: {}", e.getMessage(), e);
            ErrorResponse errorResponse = new ErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR.value(), "비밀번호 변경 중 오류가 발생했습니다.");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * 쿠키에서 특정 값 추출
     *
     * @param request     HTTP 요청
     * @param cookieName  쿠키 이름
     * @return 쿠키 값 (없으면 null)
     */
    private String extractCookieValue(HttpServletRequest request, String cookieName) {
        if (request.getCookies() == null) {
            return null;
        }

        Optional<Cookie> cookie = Arrays.stream(request.getCookies())
                .filter(c -> c.getName().equals(cookieName))
                .findFirst();

        return cookie.map(Cookie::getValue).orElse(null);
    }

    /**
     * 에러 응답 클래스
     */
    public static class ErrorResponse {
        private int status;
        private String message;

        public ErrorResponse(int status, String message) {
            this.status = status;
            this.message = message;
        }

        public int getStatus() {
            return status;
        }

        public String getMessage() {
            return message;
        }
    }
}
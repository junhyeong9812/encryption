package com.personaldata.encryption.domain.user.controller;

import com.personaldata.encryption.domain.user.dto.AuthDto;
import com.personaldata.encryption.domain.user.entity.User;
import com.personaldata.encryption.domain.user.service.AuthService;
import com.personaldata.encryption.global.security.TokenInfo;
import com.personaldata.encryption.global.utils.SecurityUtils;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.*;

/**
 * 모바일 클라이언트용 인증 컨트롤러
 * 토큰 응답 기반의 인증 처리
 */
@Slf4j
@RestController
@RequestMapping("/auth/mobile")
@RequiredArgsConstructor
@Tag(name = "모바일 인증 API", description = "모바일 클라이언트용 인증 API (토큰 응답 기반)")
public class MobileAuthController {

    private final AuthService authService;

    /**
     * 모바일 회원가입
     */
    @PostMapping("/signup")
    @Operation(summary = "모바일 회원가입", description = "모바일 클라이언트용 회원가입 (토큰 응답 방식)")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "회원가입 성공",
                    content = @Content(schema = @Schema(implementation = AuthDto.MobileResponseDto.class))),
            @ApiResponse(responseCode = "400", description = "잘못된 요청",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "409", description = "이미 존재하는 이메일",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    public ResponseEntity<?> signup(@Valid @RequestBody AuthDto.SignupRequest request) {
        try {
            // 회원가입 처리
            User user = authService.signup(request);

            // JWT 토큰 생성
            TokenInfo tokenInfo = authService.issueTokens(user);

            // 응답 생성 (토큰 정보 포함)
            AuthDto.MobileResponseDto response = AuthDto.MobileResponseDto.builder()
                    .email(user.getEmail())
                    .role(user.getRole())
                    .maskedName(authService.maskName(request.getName()))
                    .token(tokenInfo)
                    .build();

            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            // 중복 이메일 등의 예외 처리
            ErrorResponse errorResponse = new ErrorResponse(HttpStatus.CONFLICT.value(), e.getMessage());
            return ResponseEntity.status(HttpStatus.CONFLICT).body(errorResponse);
        } catch (Exception e) {
            // 기타 예외 처리
            log.error("모바일 회원가입 처리 중 오류: {}", e.getMessage(), e);
            ErrorResponse errorResponse = new ErrorResponse(HttpStatus.BAD_REQUEST.value(), "회원가입 처리 중 오류가 발생했습니다.");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
        }
    }

    /**
     * 모바일 로그인
     */
    @PostMapping("/login")
    @Operation(summary = "모바일 로그인", description = "모바일 클라이언트용 로그인 (토큰 응답 방식)")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "로그인 성공",
                    content = @Content(schema = @Schema(implementation = AuthDto.MobileResponseDto.class))),
            @ApiResponse(responseCode = "401", description = "인증 실패",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    public ResponseEntity<?> login(@Valid @RequestBody AuthDto.LoginRequest request) {
        try {
            // 로그인 처리 및 사용자 정보 조회
            User user = authService.login(request);

            // JWT 토큰 생성
            TokenInfo tokenInfo = authService.issueTokens(user);

            // 이름 복호화 및 마스킹
            String maskedName = authService.getMaskedName(user);

            // 응답 생성 (토큰 정보 포함)
            AuthDto.MobileResponseDto response = AuthDto.MobileResponseDto.builder()
                    .email(user.getEmail())
                    .role(user.getRole())
                    .maskedName(maskedName)
                    .token(tokenInfo)
                    .build();

            return ResponseEntity.ok(response);
        } catch (BadCredentialsException e) {
            // 인증 실패 예외 처리
            ErrorResponse errorResponse = new ErrorResponse(HttpStatus.UNAUTHORIZED.value(), "이메일 또는 비밀번호가 일치하지 않습니다.");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
        } catch (Exception e) {
            // 기타 예외 처리
            log.error("모바일 로그인 처리 중 오류: {}", e.getMessage(), e);
            ErrorResponse errorResponse = new ErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR.value(), "로그인 처리 중 오류가 발생했습니다.");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * 모바일 토큰 갱신
     */
    @PostMapping("/refresh")
    @Operation(summary = "모바일 토큰 갱신", description = "모바일 클라이언트용 토큰 갱신")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "토큰 갱신 성공",
                    content = @Content(schema = @Schema(implementation = TokenInfo.class))),
            @ApiResponse(responseCode = "401", description = "유효하지 않은 리프레시 토큰",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    public ResponseEntity<?> refreshToken(@Valid @RequestBody AuthDto.TokenRefreshRequest request) {
        try {
            // 리프레시 토큰으로 새 액세스 토큰 발급
            TokenInfo tokenInfo = authService.refreshAccessToken(request.getRefreshToken());
            return ResponseEntity.ok(tokenInfo);
        } catch (IllegalArgumentException e) {
            // 잘못된 토큰 예외 처리
            log.warn("모바일 토큰 갱신 실패: {}", e.getMessage());
            ErrorResponse errorResponse = new ErrorResponse(HttpStatus.UNAUTHORIZED.value(), e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
        } catch (Exception e) {
            // 기타 예외 처리
            log.error("모바일 토큰 갱신 중 오류: {}", e.getMessage(), e);
            ErrorResponse errorResponse = new ErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR.value(), "토큰 갱신 중 오류가 발생했습니다.");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * 모바일 로그아웃
     */
    @PostMapping("/logout")
    @Operation(summary = "모바일 로그아웃", description = "모바일 클라이언트용 로그아웃")
    @PreAuthorize("isAuthenticated()")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "로그아웃 성공"),
            @ApiResponse(responseCode = "401", description = "인증되지 않은 사용자",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    public ResponseEntity<?> logout(@RequestHeader(value = "Authorization", required = false) String authHeader) {
        try {
            // JWT 토큰 추출
            String accessToken = null;
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                accessToken = authHeader.substring(7);
            }

            // 사용자 ID 추출
            Long userId = SecurityUtils.getCurrentUserId();

            // 토큰 무효화
            authService.logout(accessToken, userId);

            return ResponseEntity.ok().build();
        } catch (Exception e) {
            // 예외 처리
            log.error("모바일 로그아웃 처리 중 오류: {}", e.getMessage(), e);
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
            @ApiResponse(responseCode = "400", description = "잘못된 요청",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "401", description = "인증 실패",
                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
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
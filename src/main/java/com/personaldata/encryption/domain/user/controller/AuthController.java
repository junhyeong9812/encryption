//package com.personaldata.encryption.domain.user.controller;
//
//import com.personaldata.encryption.domain.user.dto.AuthDto;
//import com.personaldata.encryption.domain.user.service.AuthService;
//import io.swagger.v3.oas.annotations.Operation;
//import io.swagger.v3.oas.annotations.Parameter;
//import io.swagger.v3.oas.annotations.media.Content;
//import io.swagger.v3.oas.annotations.media.Schema;
//import io.swagger.v3.oas.annotations.responses.ApiResponse;
//import io.swagger.v3.oas.annotations.responses.ApiResponses;
//import io.swagger.v3.oas.annotations.tags.Tag;
//import jakarta.validation.Valid;
//import lombok.RequiredArgsConstructor;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.ResponseEntity;
//import org.springframework.security.access.prepost.PreAuthorize;
//import org.springframework.security.authentication.BadCredentialsException;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.web.bind.annotation.*;
//
///**
// * 인증 관련 컨트롤러
// * 회원가입, 로그인, 비밀번호 변경 기능 제공
// */
//@RestController
//@RequestMapping("/api/auth")
//@RequiredArgsConstructor
//@Tag(name = "인증 API", description = "회원가입, 로그인, 비밀번호 변경 API")
//public class AuthController {
//
//    private final AuthService authService;
//
//    /**
//     * 회원가입
//     */
//    @PostMapping("/signup")
//    @Operation(summary = "회원가입", description = "새로운 사용자를 등록합니다.")
//    @ApiResponses(value = {
//            @ApiResponse(responseCode = "200", description = "회원가입 성공",
//                    content = @Content(schema = @Schema(implementation = AuthDto.LoginResponse.class))),
//            @ApiResponse(responseCode = "400", description = "잘못된 요청",
//                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
//            @ApiResponse(responseCode = "409", description = "이미 존재하는 이메일",
//                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
//    })
//    public ResponseEntity<?> signup(@Valid @RequestBody AuthDto.SignupRequest request) {
//        try {
//            // 회원가입 처리
//            AuthDto.LoginResponse response = authService.signup(request);
//            return ResponseEntity.ok(response);
//        } catch (IllegalArgumentException e) {
//            // 중복 이메일 등의 예외 처리
//            ErrorResponse errorResponse = new ErrorResponse(HttpStatus.CONFLICT.value(), e.getMessage());
//            return ResponseEntity.status(HttpStatus.CONFLICT).body(errorResponse);
//        } catch (Exception e) {
//            // 기타 예외 처리
//            ErrorResponse errorResponse = new ErrorResponse(HttpStatus.BAD_REQUEST.value(), "회원가입 처리 중 오류가 발생했습니다.");
//            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
//        }
//    }
//
//    /**
//     * 로그인
//     */
//    @PostMapping("/login")
//    @Operation(summary = "로그인", description = "사용자 로그인을 처리합니다.")
//    @ApiResponses(value = {
//            @ApiResponse(responseCode = "200", description = "로그인 성공",
//                    content = @Content(schema = @Schema(implementation = AuthDto.LoginResponse.class))),
//            @ApiResponse(responseCode = "401", description = "인증 실패",
//                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
//    })
//    public ResponseEntity<?> login(@Valid @RequestBody AuthDto.LoginRequest request) {
//        try {
//            // 로그인 처리
//            AuthDto.LoginResponse response = authService.login(request);
//            return ResponseEntity.ok(response);
//        } catch (BadCredentialsException e) {
//            // 인증 실패 예외 처리
//            ErrorResponse errorResponse = new ErrorResponse(HttpStatus.UNAUTHORIZED.value(), "이메일 또는 비밀번호가 일치하지 않습니다.");
//            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
//        } catch (Exception e) {
//            // 기타 예외 처리
//            ErrorResponse errorResponse = new ErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR.value(), "로그인 처리 중 오류가 발생했습니다.");
//            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
//        }
//    }
//
//    /**
//     * 비밀번호 변경
//     */
//    @PostMapping("/password")
//    @Operation(summary = "비밀번호 변경", description = "로그인한 사용자의 비밀번호를 변경합니다.")
//    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
//    @ApiResponses(value = {
//            @ApiResponse(responseCode = "200", description = "비밀번호 변경 성공"),
//            @ApiResponse(responseCode = "400", description = "잘못된 요청",
//                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
//            @ApiResponse(responseCode = "401", description = "인증 실패",
//                    content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
//            @ApiResponse(responseCode = "403", description = "접근 권한 없음",
//                    content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
//    })
//    public ResponseEntity<?> changePassword(@Valid @RequestBody AuthDto.PasswordChangeRequest request) {
//        try {
//            // 현재 인증된 사용자 이메일 가져오기
//            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//            String email = authentication.getName();
//
//            // 비밀번호 변경 처리
//            authService.changePassword(email, request);
//
//            return ResponseEntity.ok().build();
//        } catch (BadCredentialsException e) {
//            // 현재 비밀번호 불일치 예외 처리
//            ErrorResponse errorResponse = new ErrorResponse(HttpStatus.UNAUTHORIZED.value(), e.getMessage());
//            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
//        } catch (IllegalArgumentException e) {
//            // 새 비밀번호 형식 오류 또는 확인 불일치 예외 처리
//            ErrorResponse errorResponse = new ErrorResponse(HttpStatus.BAD_REQUEST.value(), e.getMessage());
//            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
//        } catch (Exception e) {
//            // 기타 예외 처리
//            ErrorResponse errorResponse = new ErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR.value(), "비밀번호 변경 중 오류가 발생했습니다.");
//            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
//        }
//    }
//
//    /**
//     * 에러 응답 클래스
//     */
//    public static class ErrorResponse {
//        private int status;
//        private String message;
//
//        public ErrorResponse(int status, String message) {
//            this.status = status;
//            this.message = message;
//        }
//
//        public int getStatus() {
//            return status;
//        }
//
//        public String getMessage() {
//            return message;
//        }
//    }
//}
//

package com.personaldata.encryption.global.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.BindException;
import org.springframework.dao.DataIntegrityViolationException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidAlgorithmParameterException;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * 애플리케이션 전역에서 발생하는 예외를 처리하는 글로벌 예외 핸들러
 * 모든 컨트롤러에서 발생하는 예외를 일관된 형식으로 처리합니다.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    /**
     * 기본 에러 응답 포맷 생성
     * 일관된 오류 응답 형식을 제공합니다.
     */
    private ResponseEntity<ErrorResponse> createErrorResponse(String message, HttpStatus status, WebRequest request) {
        ErrorResponse errorResponse = ErrorResponse.builder()
                .timestamp(LocalDateTime.now())
                .status(status.value())
                .error(status.getReasonPhrase())
                .message(message)
                .path(request.getDescription(false).substring(4))
                .build();

        return new ResponseEntity<>(errorResponse, status);
    }

    /**
     * 암호화 관련 예외 처리 (500 Internal Server Error)
     * 암호화/복호화 과정에서 발생하는 예외들을 처리합니다.
     */
    @ExceptionHandler({
            BadPaddingException.class,
            IllegalBlockSizeException.class,
            InvalidKeyException.class,
            NoSuchAlgorithmException.class,
            InvalidAlgorithmParameterException.class,
            EncryptionException.class
    })
    public ResponseEntity<ErrorResponse> handleEncryptionException(Exception ex, WebRequest request) {
        HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;
        if (ex instanceof EncryptionException) {
            status = ((EncryptionException) ex).getStatus();
        }

        return createErrorResponse("암호화 처리 중 오류가 발생했습니다: " + ex.getMessage(),
                status, request);
    }

    /**
     * 검색 암호화 관련 예외 처리
     * 암호화된 데이터 검색 과정에서 발생하는 예외를 처리합니다.
     */
    @ExceptionHandler({SearchEncryptionException.class})
    public ResponseEntity<ErrorResponse> handleSearchEncryptionException(SearchEncryptionException ex, WebRequest request) {
        return createErrorResponse("암호화된 데이터 검색 중 오류가 발생했습니다: " + ex.getMessage(),
                ex.getStatus(), request);
    }

    /**
     * 키 관리 관련 예외 처리
     * 암호화 키 생성, 저장, 로딩 등에서 발생하는 예외를 처리합니다.
     */
    @ExceptionHandler({KeyManagementException.class})
    public ResponseEntity<ErrorResponse> handleKeyManagementException(KeyManagementException ex, WebRequest request) {
        return createErrorResponse("암호화 키 관리 중 오류가 발생했습니다: " + ex.getMessage(),
                ex.getStatus(), request);
    }

    /**
     * 익명화/가명화 관련 예외 처리
     * 개인정보 처리 과정에서 발생하는 예외를 처리합니다.
     */
    @ExceptionHandler({PseudonymizationException.class})
    public ResponseEntity<ErrorResponse> handlePseudonymizationException(PseudonymizationException ex, WebRequest request) {
        return createErrorResponse("데이터 익명화/가명화 중 오류가 발생했습니다: " + ex.getMessage(),
                ex.getStatus(), request);
    }

    /**
     * 인증 관련 예외 처리 (401 Unauthorized)
     * 사용자 인증 실패 시 발생하는 예외를 처리합니다.
     */
    @ExceptionHandler({AuthenticationException.class})
    public ResponseEntity<ErrorResponse> handleAuthenticationException(Exception ex, WebRequest request) {
        return createErrorResponse("인증에 실패했습니다: " + ex.getMessage(),
                HttpStatus.UNAUTHORIZED, request);
    }

    /**
     * 접근 권한 관련 예외 처리 (403 Forbidden)
     * 접근 권한 부족으로 인한 예외를 처리합니다.
     */
    @ExceptionHandler({AccessDeniedException.class})
    public ResponseEntity<ErrorResponse> handleAccessDeniedException(Exception ex, WebRequest request) {
        return createErrorResponse("접근 권한이 없습니다: " + ex.getMessage(),
                HttpStatus.FORBIDDEN, request);
    }

    /**
     * 입력값 유효성 검사 예외 처리 (400 Bad Request)
     * 폼 데이터나 요청 본문의 유효성 검사 실패 시 발생하는 예외를 처리합니다.
     */
    @ExceptionHandler({BindException.class})
    public ResponseEntity<Map<String, Object>> handleBindException(BindException ex, WebRequest request) {
        Map<String, Object> errorMap = new HashMap<>();
        errorMap.put("timestamp", LocalDateTime.now());
        errorMap.put("status", HttpStatus.BAD_REQUEST.value());

        // 각 필드별 오류 메시지를 수집하여 상세 정보 제공
        Map<String, String> validationErrors = new HashMap<>();
        ex.getBindingResult().getFieldErrors().forEach(
                error -> validationErrors.put(error.getField(), error.getDefaultMessage())
        );

        errorMap.put("errors", validationErrors);
        errorMap.put("path", request.getDescription(false).substring(4));

        return new ResponseEntity<>(errorMap, HttpStatus.BAD_REQUEST);
    }

    /**
     * 데이터 무결성 예외 처리 (409 Conflict)
     * 데이터 저장/수정 시 무결성 제약 조건 위반으로 인한 예외를 처리합니다.
     */
    @ExceptionHandler({DataIntegrityViolationException.class})
    public ResponseEntity<ErrorResponse> handleDataIntegrityException(DataIntegrityViolationException ex, WebRequest request) {
        return createErrorResponse("데이터 무결성 오류가 발생했습니다: " + ex.getMessage(),
                HttpStatus.CONFLICT, request);
    }

    /**
     * IllegalArgumentException 예외 처리 (400 Bad Request)
     * 잘못된 인수가 전달되었을 때 발생하는 예외를 처리합니다.
     */
    @ExceptionHandler({IllegalArgumentException.class})
    public ResponseEntity<ErrorResponse> handleIllegalArgumentException(IllegalArgumentException ex, WebRequest request) {
        return createErrorResponse("잘못된 인수가 전달되었습니다: " + ex.getMessage(),
                HttpStatus.BAD_REQUEST, request);
    }

    /**
     * IllegalStateException 예외 처리 (500 Internal Server Error)
     * 메서드 호출이 잘못된 상태에서 실행되었을 때 발생하는 예외를 처리합니다.
     */
    @ExceptionHandler({IllegalStateException.class})
    public ResponseEntity<ErrorResponse> handleIllegalStateException(IllegalStateException ex, WebRequest request) {
        return createErrorResponse("잘못된 상태에서 메서드가 호출되었습니다: " + ex.getMessage(),
                HttpStatus.INTERNAL_SERVER_ERROR, request);
    }

    /**
     * NullPointerException 예외 처리 (500 Internal Server Error)
     * null 참조를 역참조할 때 발생하는 예외를 처리합니다.
     */
    @ExceptionHandler({NullPointerException.class})
    public ResponseEntity<ErrorResponse> handleNullPointerException(NullPointerException ex, WebRequest request) {
        return createErrorResponse("null 참조가 발생했습니다: " + ex.getMessage(),
                HttpStatus.INTERNAL_SERVER_ERROR, request);
    }

    /**
     * 기타 모든 예외 처리 (500 Internal Server Error)
     * 위에서 처리되지 않은 모든 예외를 캐치하는 최종 처리기입니다.
     */
    @ExceptionHandler({Exception.class})
    public ResponseEntity<ErrorResponse> handleAllExceptions(Exception ex, WebRequest request) {
        return createErrorResponse("서버 내부 오류가 발생했습니다: " + ex.getMessage(),
                HttpStatus.INTERNAL_SERVER_ERROR, request);
    }
}
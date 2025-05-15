package com.personaldata.encryption.global.exception;

import lombok.Builder;
import lombok.Getter;

import java.time.LocalDateTime;

/**
 * 예외 발생 시 클라이언트에게 반환할 표준화된 오류 응답 객체
 */
@Getter
@Builder
public class ErrorResponse {
    /**
     * 오류 발생 시간
     */
    private LocalDateTime timestamp;

    /**
     * HTTP 상태 코드
     */
    private int status;

    /**
     * HTTP 상태 메시지
     */
    private String error;

    /**
     * 상세 오류 메시지
     */
    private String message;

    /**
     * 오류가 발생한 요청 경로
     */
    private String path;
}
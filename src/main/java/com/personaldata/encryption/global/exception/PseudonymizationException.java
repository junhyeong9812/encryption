package com.personaldata.encryption.global.exception;

import org.springframework.http.HttpStatus;
import lombok.Getter;

/**
 * 데이터 익명화/가명화 관련 예외를 처리하기 위한 클래스
 * 개인정보 처리 과정에서 발생하는 오류를 처리합니다.
 */
@Getter
public class PseudonymizationException extends RuntimeException {

    private static final long serialVersionUID = 1L;
    private final HttpStatus status;

    /**
     * 메시지와 HTTP 상태를 포함하는 생성자
     *
     * @param message 예외 메시지
     * @param status HTTP 상태 코드
     */
    public PseudonymizationException(String message, HttpStatus status) {
        super(message);
        this.status = status;
    }

    /**
     * 메시지와 원인, HTTP 상태를 포함하는 생성자
     *
     * @param message 예외 메시지
     * @param cause 원인 예외
     * @param status HTTP 상태 코드
     */
    public PseudonymizationException(String message, Throwable cause, HttpStatus status) {
        super(message, cause);
        this.status = status;
    }

    /**
     * 메시지만 포함하는 생성자
     *
     * @param message 예외 메시지
     */
    public PseudonymizationException(String message) {
        super(message);
        this.status = HttpStatus.INTERNAL_SERVER_ERROR;
    }

    /**
     * 메시지와 원인을 포함하는 생성자
     *
     * @param message 예외 메시지
     * @param cause 원인 예외
     */
    public PseudonymizationException(String message, Throwable cause) {
        super(message, cause);
        this.status = HttpStatus.INTERNAL_SERVER_ERROR;
    }
}
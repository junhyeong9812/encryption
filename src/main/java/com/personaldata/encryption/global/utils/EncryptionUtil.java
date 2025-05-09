package com.personaldata.encryption.global.utils;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

import jakarta.annotation.PostConstruct;

/**
 * 암호화 및 복호화 기능을 제공하는 유틸리티 클래스
 * - AES-GCM 방식의 강력한 암호화 제공
 * - 결정적 암호화(Deterministic Encryption) 제공
 */
@Slf4j
@Component
public class EncryptionUtil {

    @Value("${encryption.key}")
    private String masterKeyBase64;

    @Value("${encryption.algorithm:AES/GCM/NoPadding}")
    private String algorithm;

    private SecretKey masterKey;

    /**
     * 서비스 초기화 시 마스터 키 설정
     */
    @PostConstruct
    public void init() {
        try {
            // Base64 디코딩하여 마스터 키 생성
            byte[] keyBytes = Base64.getDecoder().decode(masterKeyBase64);
            masterKey = new SecretKeySpec(keyBytes, "AES");
            log.info("암호화 유틸리티가 초기화되었습니다. 알고리즘: {}", algorithm);
        } catch (Exception e) {
            log.error("마스터 키 초기화 실패", e);
            throw new RuntimeException("암호화 유틸리티 초기화 실패", e);
        }
    }

    /**
     * 강력한 암호화 (AES-GCM)
     * - 매번 다른 IV 사용으로 동일 평문도 다른 암호문 생성
     * - 복호화 가능한 방식
     *
     * @param plaintext 암호화할 평문
     * @return Base64로 인코딩된 암호문
     */
    public String encryptStrongly(String plaintext) {
        if (plaintext == null) {
            return null;
        }

        try {
            // AES-GCM 모드 암호화 준비
            Cipher cipher = Cipher.getInstance(algorithm);
            byte[] iv = generateRandomIv();
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);

            cipher.init(Cipher.ENCRYPT_MODE, masterKey, parameterSpec);
            byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            // IV와 암호화된 데이터 결합 (IV를 함께 저장해야 복호화 가능)
            ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + encrypted.length);
            byteBuffer.put(iv);
            byteBuffer.put(encrypted);

            return Base64.getEncoder().encodeToString(byteBuffer.array());
        } catch (Exception e) {
            log.error("암호화 실패: {}", e.getMessage());
            throw new RuntimeException("암호화 실패", e);
        }
    }

    /**
     * 결정적 암호화 (Deterministic Encryption)
     * - 동일 평문은 항상 동일 암호문 생성
     * - 검색 용도로 사용 가능
     *
     * @param plaintext 암호화할 평문
     * @return Base64로 인코딩된 결정적 암호문
     */
    public String deterministicEncrypt(String plaintext) {
        if (plaintext == null) {
            return null;
        }

        try {
            // HMAC-SHA256 기반 결정적 암호화 (키는 동일하게 사용)
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(masterKey);
            byte[] result = mac.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(result);
        } catch (Exception e) {
            log.error("결정적 암호화 실패: {}", e.getMessage());
            throw new RuntimeException("결정적 암호화 실패", e);
        }
    }

    /**
     * 복호화
     *
     * @param encryptedBase64 Base64로 인코딩된 암호문
     * @return 복호화된 평문
     */
    public String decrypt(String encryptedBase64) {
        if (encryptedBase64 == null) {
            return null;
        }

        try {
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedBase64);
            ByteBuffer byteBuffer = ByteBuffer.wrap(encryptedBytes);

            // IV 추출 (AES-GCM의 경우 일반적으로 12바이트)
            byte[] iv = new byte[12];
            byteBuffer.get(iv);

            // 암호문 추출
            byte[] cipherText = new byte[byteBuffer.remaining()];
            byteBuffer.get(cipherText);

            // 복호화
            Cipher cipher = Cipher.getInstance(algorithm);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, masterKey, parameterSpec);

            byte[] decrypted = cipher.doFinal(cipherText);
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            log.error("복호화 실패: {}", e.getMessage());
            throw new RuntimeException("복호화 실패", e);
        }
    }

    /**
     * 무작위 IV(초기화 벡터) 생성
     *
     * @return 12바이트 IV
     */
    private byte[] generateRandomIv() {
        byte[] iv = new byte[12]; // GCM 모드에 권장되는 IV 크기
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    /**
     * 한글 초성 추출 (검색용)
     *
     * @param text 한글 텍스트
     * @return 초성으로 변환된 텍스트
     */
    public String extractKoreanInitials(String text) {
        if (text == null || text.isEmpty()) {
            return "";
        }

        StringBuilder result = new StringBuilder();

        for (char c : text.toCharArray()) {
            // 한글 범위 확인 (가 ~ 힣)
            if (c >= '가' && c <= '힣') {
                // 초성 추출 공식: ((문자코드 - 가) / 588)
                char initialIndex = (char) ((c - '가') / 588);

                // 초성 매핑 (ㄱ, ㄲ, ㄴ, ㄷ, ...)
                char[] initials = {'ㄱ', 'ㄲ', 'ㄴ', 'ㄷ', 'ㄸ', 'ㄹ', 'ㅁ', 'ㅂ', 'ㅃ',
                        'ㅅ', 'ㅆ', 'ㅇ', 'ㅈ', 'ㅉ', 'ㅊ', 'ㅋ', 'ㅌ', 'ㅍ', 'ㅎ'};

                if (initialIndex >= 0 && initialIndex < initials.length) {
                    result.append(initials[initialIndex]);
                }
            } else {
                // 한글이 아닌 경우 그대로 추가
                result.append(c);
            }
        }

        return result.toString();
    }

    /**
     * 전화번호 마스킹 처리
     *
     * @param phoneNumber 전화번호
     * @return 마스킹된 전화번호 (예: 010-****-5678)
     */
    public String maskPhoneNumber(String phoneNumber) {
        if (phoneNumber == null || phoneNumber.length() < 7) {
            return phoneNumber;
        }

        // 전화번호 형식에 따라 마스킹 처리
        String[] parts = phoneNumber.split("-");
        if (parts.length == 3) {
            // xxx-xxxx-xxxx 형식
            return parts[0] + "-****-" + parts[2];
        } else {
            // 그 외 형식
            int length = phoneNumber.length();
            String prefix = phoneNumber.substring(0, 3);
            String suffix = phoneNumber.substring(length - 4);
            return prefix + "****" + suffix;
        }
    }
}
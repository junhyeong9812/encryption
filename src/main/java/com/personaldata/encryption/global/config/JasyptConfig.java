package com.personaldata.encryption.global.config;

import org.jasypt.encryption.StringEncryptor;
import org.jasypt.encryption.pbe.PooledPBEStringEncryptor;
import org.jasypt.encryption.pbe.config.SimpleStringPBEConfig;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Jasypt 설정 클래스
 * application.yml과 같은 설정 파일 내 민감한 정보를 암호화하기 위한 설정
 */
@Configuration
public class JasyptConfig {

    @Value("${jasypt.encryptor.password:defaultpassword}")
    private String password;

    @Value("${jasypt.encryptor.algorithm:PBEWithMD5AndDES}")
    private String algorithm;

    @Value("${jasypt.encryptor.pool-size:1}")
    private int poolSize;

    @Value("${jasypt.encryptor.key-obtention-iterations:1000}")
    private int keyObtentionIterations;

    @Value("${jasypt.encryptor.string-output-type:base64}")
    private String stringOutputType;

    /**
     * Jasypt 암호화 빈 설정
     * 프로퍼티 파일에서 ENC(암호화된_값) 형태로 사용 가능
     *
     * @return StringEncryptor 인스턴스
     */
    @Bean("jasyptStringEncryptor")
    public StringEncryptor stringEncryptor() {
        PooledPBEStringEncryptor encryptor = new PooledPBEStringEncryptor();
        SimpleStringPBEConfig config = new SimpleStringPBEConfig();

        config.setPassword(password);  // 암호화 키
        config.setAlgorithm(algorithm);  // 암호화 알고리즘
        config.setKeyObtentionIterations(keyObtentionIterations);  // 키 생성 반복 횟수
        config.setPoolSize(poolSize);  // 암호화 인스턴스 풀 크기
        config.setProviderName("SunJCE");  // 프로바이더
        config.setSaltGeneratorClassName("org.jasypt.salt.RandomSaltGenerator");  // 솔트 생성기
        config.setIvGeneratorClassName("org.jasypt.iv.RandomIvGenerator");  // IV 생성기
        config.setStringOutputType(stringOutputType);  // 출력 인코딩

        encryptor.setConfig(config);

        return encryptor;
    }
}
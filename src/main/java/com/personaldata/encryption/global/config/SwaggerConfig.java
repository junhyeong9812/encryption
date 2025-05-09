package com.personaldata.encryption.global.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * Swagger/OpenAPI 문서 설정 클래스
 */
@Configuration
public class SwaggerConfig {

    /**
     * OpenAPI 메타데이터 및 서버 정보 설정
     *
     * @return OpenAPI 설정 객체
     */
    @Bean
    public OpenAPI openAPI() {
        return new OpenAPI()
                // API 기본 정보
                .info(new Info()
                        .title("암호화 기반 검색 최적화 API")
                        .description("개인정보를 안전하게 암호화하면서도 검색 기능을 제공하는 API")
                        .version("v1.0")
                        .contact(new Contact()
                                .name("Development Team")
                                .email("dev@example.com")
                                .url("https://github.com/your-repository"))
                        .license(new License()
                                .name("MIT License")
                                .url("https://opensource.org/licenses/MIT")))
                // 서버 정보
                .servers(List.of(
                        new Server()
                                .url("/")
                                .description("Local Development Server"),
                        new Server()
                                .url("http://localhost:8080")
                                .description("로컬 개발 서버")));
    }
}
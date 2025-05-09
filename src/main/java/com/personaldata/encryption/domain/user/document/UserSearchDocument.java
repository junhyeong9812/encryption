package com.personaldata.encryption.domain.user.document;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.elasticsearch.annotations.Document;
import org.springframework.data.elasticsearch.annotations.Field;
import org.springframework.data.elasticsearch.annotations.FieldType;
import org.springframework.data.elasticsearch.annotations.Setting;

/**
 * 사용자 검색을 위한 엘라스틱서치 문서
 * 검색에 필요한 필드만 정의하여 사용
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Document(indexName = "user_search_index")
@Setting(settingPath = "elasticsearch/user-search-settings.json")
public class UserSearchDocument {

    /**
     * 문서 ID (사용자 ID와 매핑)
     */
    @Id
    private String id;

    /**
     * 결정적 암호화된 이름 (동등 검색용)
     */
    @Field(type = FieldType.Keyword)
    private String nameSearchable;

    /**
     * 이름 초성 (한글 검색용)
     */
    @Field(type = FieldType.Text, analyzer = "korean")
    private String nameInitial;

    /**
     * 결정적 암호화된 전화번호 앞자리 (검색용)
     */
    @Field(type = FieldType.Keyword)
    private String phonePrefix;

    /**
     * 이메일 도메인 (검색용)
     */
    @Field(type = FieldType.Keyword)
    private String emailDomain;

    /**
     * 지역 정보 (검색용)
     */
    @Field(type = FieldType.Keyword)
    private String region;

    /**
     * 지역 코드 (검색용)
     */
    @Field(type = FieldType.Keyword)
    private String regionCode;

    /**
     * 도시 정보 (검색용)
     */
    @Field(type = FieldType.Keyword)
    private String city;

    /**
     * 도시 코드 (검색용)
     */
    @Field(type = FieldType.Keyword)
    private String cityCode;

    /**
     * 결정적 암호화된 상세 주소 키워드 (검색용)
     */
    @Field(type = FieldType.Keyword)
    private String addressDetailSearchable;
}
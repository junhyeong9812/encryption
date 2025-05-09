# 데이터 암호화 기반 검색 최적화 연구 프로젝트

## 도입 배경

최근 SKT, 알바몬 등 국내 대기업 및 주요 서비스 기업들이 연이어 **DB 유출 사고**를 겪고 있습니다. 이처럼 데이터베이스에 저장된 민감한 개인정보가 외부 공격으로 인해 유출될 경우 기업의 신뢰도 및 사용자 보안에 막대한 영향을 미치게 됩니다.

이러한 현실을 반영하여, **DB 내 민감 정보 암호화는 선택이 아닌 필수**가 되었습니다.

하지만 데이터를 암호화하여 저장하는 것은 간단해 보여도, 실무에서는 심각한 문제를 유발합니다. 그 중 대표적인 것이 바로 **"검색 불가능 문제"**입니다. 모든 데이터를 암호화하면, 일반적인 WHERE 조건이나 LIKE 검색이 제대로 동작하지 않기 때문에 암호화가 오히려 서비스 기능을 제한하게 됩니다.

본 프로젝트는 **개인정보를 암호화하여 안전하게 저장하면서도**, **실시간 검색이 가능한 구조를 어떻게 구현할 수 있을지를 연구하는 프로젝트**입니다.

## 1. DB 데이터 암호화 방식 정리

| 분류 | 방식 | 특징 | 검색 가능성 | 실무 활용 |
|------|------|------|------------|----------|
| ✅ 대칭키 암호화 | AES-256 등 | 복호화 가능, 강력한 보안 | ❌ 직접 검색 불가 | ✅ 개인정보 저장용 |
| ✅ 해시함수 | SHA-256 등 | 비가역적, 일치 비교만 가능 | ✅ 완전 일치만 가능 | ✅ 전화번호/주민번호 등 |
| ⛔ 비대칭키 암호화 | RSA 등 | 느리고 키 관리 복잡 | ❌ 검색 불가 | ❌ 검색엔진에는 부적합 |
| ⚠ 동형암호 | Paillier 등 | 암호화 상태로 연산 가능 | ⚠ 가능하나 매우 느림 | ❌ 실무 적용 어려움 |
| ⚠ 검색 가능한 암호화 | Order-Preserving Encryption 등 | 부분 검색 가능 | ⚠ 가능하나 보안 취약 가능성 있음 | ❌ 매우 제한적 적용 |
| ✅ 결정적 암호화 | HMAC, AES-ECB 등 | 동일 입력 시 동일 출력 | ✅ 동등 검색(equality) 가능 | ✅ 이름, 이메일 등 검색 필요 필드 |

## 2. 결정적 암호화(Deterministic Encryption)의 활용

결정적 암호화는 동일한 평문이 항상 동일한 암호문으로 변환되는 특성을 가지고 있어, 검색에 활용할 수 있습니다:

- **장점**: 암호화된 상태에서도 동등 검색(equality search)이 가능
- **단점**: 빈도 분석 공격에 취약할 수 있음
- **적용 사례**: 이름, 이메일 주소 등 동등 검색이 필요한 필드에 활용
- **구현 방식**:
    - AES-ECB 모드 (보안에 취약할 수 있음)
    - AES-CBC 모드 + 고정 IV (더 안전한 방식)
    - HMAC 기반 구현 (SHA-256 등 해시 함수 활용)

## 3. 실무 환경에서 많이 쓰는 구조

1. **필드별 차등 보호 전략**
    - 개인정보 필드마다 민감도와 검색 필요성에 따라 다른 암호화 방식 적용
        * **이름**: 결정적 암호화 또는 포네틱 검색 인덱스 병행
        * **전화번호**: 마스킹 + 부분 암호화 (뒷자리만 강한 암호화)
        * **주소**: 계층별 보호 (시/도는 평문, 상세주소는 암호화)

2. **토큰화(Tokenization) 방식**
    - 민감한 데이터를 의미 없는 토큰으로 대체
    - 원본 데이터와 토큰 간의 매핑은 별도 보안 시스템에서 관리
    - 검색은 토큰으로 수행, 표시할 때만 원본 복원

3. **검색 최적화 구조**
    - AES-256 등으로 개인정보 암호화 저장 (복호화 가능)
    - 검색용으로는 마스킹 필드/토큰화된 필드를 별도로 저장하여 사용
    - Elasticsearch 등 외부 검색엔진에 가명화된 정보만 색인
    - 검색 결과에서 ID를 기준으로 DB에서 복호화하여 응답

4. **데이터 유형별 실제 구현 예시**

   ```
   이름 처리:
   - 원본 이름 "홍길동" → 암호화하여 저장 (AES-256 등으로)
   - 검색용 인덱스: 결정적 암호화된 값 (HMAC-SHA256 등)
   - 또는 초성 인덱스 "ㅎㄱㄷ"을 별도 컬럼에 저장
   
   전화번호 처리:
   - 전체 번호는 강한 암호화 (AES-GCM 등)
   - 국번(앞 자리)은 결정적 암호화하여 지역별 검색 가능
   - 검색 시: 입력된 전화번호에 동일한 처리를 적용하여 검색
   
   주소 처리:
   - 주소를 구성요소별로 분리: 시/도, 구/군, 상세주소
   - 시/도, 구/군은 평문 또는 결정적 암호화
   - 상세주소는 강한 암호화
   - 검색용 지역 코드 필드 추가
   ```

## 4. DB 선택 시 고려 사항

| 기준 | 설명 |
|------|------|
| ✅ 저장 암호화 지원 | 컬럼 수준 암호화 또는 암호화된 필드 저장 구조 지원 |
| ✅ 인덱스 설정 유연성 | 검색용 필드를 따로 관리할 수 있도록 인덱스 구조 유연해야 함 |
| ✅ 외부 검색 연동성 | Elasticsearch 등 검색 시스템과 연동이 수월해야 함 |
| ✅ 성능 | 복호화나 전체 스캔이 많기 때문에 IO 성능 중요 |
| ✅ 키 관리 구조 | 암호화 키를 안전하게 관리할 수 있는 시스템이 필요 (예: AWS KMS, Hashicorp Vault 등) |

### 🔎 **추천 DB 예시**:
* **RDB**: PostgreSQL (암호화 기능, JSON 구조 저장 등 활용 가능)
* **NoSQL**: MongoDB (필드 암호화 + 유연한 인덱싱)
* **검색엔진**: Elasticsearch (가명화된 데이터 색인 용도)

## 5. 이중 저장 방식에 대한 보안 고려사항

이중 저장 방식은 많이 사용되지만 다음과 같은 보안 위험이 있습니다:

1. **위험성**: 원본 데이터와 검색용 데이터가 모두 유출될 경우 보안 효과가 감소
2. **대안 접근법**:
    - 물리적 분리: 검색용 인덱스와 원본 데이터를 다른 서버/DB에 저장
    - 접근 제어 강화: 검색용 데이터에 대한 접근 권한 제한
    - 가명화 수준 향상: 검색용 데이터를 최대한 가명화하여 원본 식별 어렵게 함

## 6. 암호화 키 관리 전략

1. **키 관리 시스템 (KMS)**
    - AWS KMS, HashiCorp Vault, Google Cloud KMS 등 활용
    - 키는 DB와 반드시 분리하여 관리

2. **키 순환 (Key Rotation)**
    - 정기적인 키 변경으로 키 유출 시 피해 최소화
    - 순환 주기: 분기, 반기, 1년 등 정책에 따라 설정

3. **마스터 키와 데이터 키 분리**
    - 마스터 키: 데이터 키를 암호화하는 용도
    - 데이터 키: 실제 데이터 암호화에 사용

## 7. 테스트 및 벤치마킹 계획

1. **성능 테스트**
    - 다양한 암호화 방식별 암/복호화 속도 비교
    - 검색 성능 측정 (TPS, 응답시간)
    - 대용량 데이터셋(100만 건 이상)에서의 성능 검증

2. **보안성 테스트**
    - 암호화된 데이터에 대한 빈도 분석 공격 시뮬레이션
    - 키 유출 시나리오에 따른 위험 평가
    - 데이터 복구 가능성 검증

## 8. 기술 검토 과정 기록

본 프로젝트를 진행하면서 다양한 암호화 및 검색 기술에 대한 검토가 이루어졌습니다. 아래는 핵심 논의 사항을 요약한 것입니다.

### 결정적 암호화(Deterministic Encryption) 분석

결정적 암호화는 동일한 입력 값(평문)에 대해 항상 동일한 암호화 결과(암호문)를 생성하는 방식으로, 검색 기능 구현에 매우 유용합니다.

#### 결정적 암호화의 주요 특징:

- **일관성**: 동일한 평문은 항상 동일한 암호문으로 변환
- **동등성 검색 가능**: 암호화된 상태에서도 값의 동등성(equality) 비교가 가능
- **보안 수준**: 확률적 암호화보다는 보안 수준이 낮음 (빈도 분석 공격에 취약)

#### 결정적 암호화의 구현 방식:

- **블록 암호화 모드**: ECB 모드(보안 취약) 또는 CBC 모드 + 고정 IV
- **키 파생**: HMAC, PBKDF2와 같은 키 파생 함수 사용
- **암호화 함수 조합**: AES와 같은 블록 암호화 알고리즘 + 적절한 패딩

#### 보안 강화 방법:

- **솔팅(Salting)**: 고유 식별자를 추가하여 동일 값도 다른 암호문이 되도록 함
- **액세스 제어**: 암호화된 데이터에 대한 접근 권한 엄격히 제한
- **추가 암호화 계층**: 전체 데이터베이스 또는 테이블 수준에서 추가 암호화 적용

### 현업에서 사용되는 암호화 및 검색 방식 분석

다양한 서비스 환경에서 실제로 사용되는 암호화 및 검색 방식을 분석한 결과, 다음과 같은 접근법이 많이 사용되고 있습니다:

1. **필드별 차등 보호 전략**:
    - 이름: 결정적 암호화 또는 포네틱 검색 인덱스 병행
    - 전화번호: 마스킹 + 부분 암호화 (뒷자리만 강한 암호화)
    - 주소: 계층별 보호 (시/도는 평문, 상세주소는 암호화)

2. **데이터 유형별 실제 처리 방식**:
    - 이름 검색: 결정적 암호화 또는 초성 인덱스 활용
    - 전화번호 검색: 국번 기반 검색 + 마스킹된 뒷자리
    - 주소 검색: 구성요소별 분리 처리 + 지역 코드 인덱싱

3. **업계별 주요 사용 기술**:
    - 금융권/대기업: 상용 컬럼 암호화 솔루션, 자체 EKMS, Oracle TDE
    - 중견/중소기업: 애플리케이션 레벨 암호화 + 검색용 인덱스, 클라우드 KMS
    - 스타트업: Firebase 보안 기능, 애플리케이션 레벨 암호화 + 검색용 필드

### 이중 저장 방식의 한계 분석

이중 저장 방식(원본 데이터는 강하게 암호화하고 검색용 데이터는 별도 저장)의 보안 위험성을 검토한 결과:

- 양쪽 데이터 모두 유출 시 보안 효과가 크게 감소하는 문제 확인
- 물리적 분리, 접근 제어 강화, 더 높은 수준의 가명화 등 대안 접근법 필요성 도출
- 모든 데이터에 대해 이중 저장을 적용하기보다 민감도에 따른 선별적 적용 권장

### 향후 연구 방향 도출

1. 실시간 검색이 가능하면서도 보안성을 유지할 수 있는 하이브리드 접근법 개발
2. 블룸 필터와 같은 확률적 데이터 구조를 활용한 암호화 검색 최적화 방안 연구
3. 모바일/분산 환경에서의 암호화 키 관리 전략 수립
4. 다양한 암호화 방식의 성능 영향 정량 측정 및 비교 분석

## 9. 실제 구현 코드 예시

### Spring Boot에서의 암호화 처리 예시

```java
// 사용자 정보 저장 시
@Service
public class UserService {
    @Autowired
    private EncryptionService encryptionService;
    @Autowired
    private UserRepository userRepository;
    
    public void saveUser(UserDto userDto) {
        User user = new User();
        
        // 1. 이름 처리
        user.setNameEncrypted(encryptionService.encryptStrongly(userDto.getName()));
        user.setNameSearchable(encryptionService.deterministicEncrypt(userDto.getName()));
        
        // 2. 전화번호 처리
        user.setPhoneEncrypted(encryptionService.encryptStrongly(userDto.getPhone()));
        user.setPhonePrefix(encryptionService.deterministicEncrypt(
            userDto.getPhone().substring(0, 6))); // 지역번호 검색용
        
        // 3. 주소 처리
        Address address = userDto.getAddress();
        user.setRegion(address.getRegion());  // 시/도 (평문 유지)
        user.setCity(address.getCity());      // 구/군 (평문 유지)
        user.setAddressDetailEncrypted(encryptionService.encryptStrongly(address.getDetail()));
        
        userRepository.save(user);
    }
    
    // 이름으로 검색 시
    public List<UserDto> searchByName(String nameQuery) {
        String searchableNameQuery = encryptionService.deterministicEncrypt(nameQuery);
        List<User> users = userRepository.findByNameSearchable(searchableNameQuery);
        
        return users.stream()
            .map(user -> {
                UserDto dto = new UserDto();
                dto.setName(encryptionService.decrypt(user.getNameEncrypted()));
                dto.setPhone(encryptionService.decrypt(user.getPhoneEncrypted()));
                // 다른 필드 설정...
                return dto;
            })
            .collect(Collectors.toList());
    }
}
```

### 암호화 서비스 구현 예시

```java
@Service
public class EncryptionService {
    @Value("${encryption.key}")
    private String masterKeyBase64;
    private SecretKey masterKey;
    
    @PostConstruct
    public void init() {
        // 마스터 키 초기화
        byte[] keyBytes = Base64.getDecoder().decode(masterKeyBase64);
        masterKey = new SecretKeySpec(keyBytes, "AES");
    }
    
    // 강력한 암호화 (AES-GCM)
    public String encryptStrongly(String plaintext) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            byte[] iv = generateRandomIv();
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
            
            cipher.init(Cipher.ENCRYPT_MODE, masterKey, parameterSpec);
            byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            
            // IV와 암호화된 데이터 결합
            ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + encrypted.length);
            byteBuffer.put(iv);
            byteBuffer.put(encrypted);
            
            return Base64.getEncoder().encodeToString(byteBuffer.array());
        } catch (Exception e) {
            throw new RuntimeException("암호화 실패", e);
        }
    }
    
    // 결정적 암호화 (검색용)
    public String deterministicEncrypt(String plaintext) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(masterKey);
            byte[] result = mac.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(result);
        } catch (Exception e) {
            throw new RuntimeException("결정적 암호화 실패", e);
        }
    }
    
    // 복호화
    public String decrypt(String encryptedBase64) {
        try {
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedBase64);
            ByteBuffer byteBuffer = ByteBuffer.wrap(encryptedBytes);
            
            byte[] iv = new byte[12]; // GCM 모드의 IV 크기
            byteBuffer.get(iv);
            
            byte[] cipherText = new byte[byteBuffer.remaining()];
            byteBuffer.get(cipherText);
            
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, masterKey, parameterSpec);
            
            byte[] decrypted = cipher.doFinal(cipherText);
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("복호화 실패", e);
        }
    }
    
    private byte[] generateRandomIv() {
        byte[] iv = new byte[12]; // GCM 모드에 권장되는 IV 크기
        new SecureRandom().nextBytes(iv);
        return iv;
    }
}
```

## 10. 보안과 검색성능 사이의 균형 전략

본 프로젝트는 암호화로 인한 보안 강화와 검색 기능 유지 사이에서 최적의 균형을 찾는 것을 목표로 합니다. 이를 위해 다음과 같은 전략을 고려하고 있습니다:

1. **계층적 보안 모델** - 데이터 민감도에 따른 차등 보호
2. **검색 기능별 최적 암호화 방식 선정** - 동등 검색, 범위 검색, 부분 검색 등
3. **성능과 보안의 균형점 측정** - 다양한 시나리오에서의 벤치마킹

## ✅ 다음 단계

* Spring + JPA 기반 AES256 암복호화 자동화 구조 설계
* Elasticsearch 연동을 고려한 검색 필드 마스킹/가명화 구조 설계
* 다양한 암호화 방식에 따른 성능 및 검색 가능성 비교 실험 진행 예정
* 암호화된 상태에서의 부분 검색(LIKE 검색) 구현 방안 연구
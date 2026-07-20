-- V1__sas_baseline.sql
-- Spring Authorization Server 1.x 표준 스키마 verbatim(컬럼 타입·제약 무변경) + refresh 재사용 탐지 레지스트리.
-- Source: spring-security-oauth2-authorization-server jar
--   org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql
--   org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql
--   org/springframework/security/oauth2/server/authorization/oauth2-authorization-consent-schema.sql
-- Dialect: MariaDB.
-- Flyway history: 이 프로젝트 전용 테이블(flyway_schema_history_auth — application.yml 설정)에 기록된다.
--   api 서비스와 단일 DB를 공유하므로 기본 history 테이블명을 그대로 쓰면 버전 충돌이 난다.
--
-- ⚠️ COMMENT 추가 정책: 컬럼 타입·제약은 SAS 원본과 byte-identical 보존. 각 컬럼에 COMMENT만 추가해
--    OIDC/OAuth2 의미를 문서화한다(운영 DB 직접 조회 + 도메인 학습용). 타입/NULL/DEFAULT/PK는 절대 변경하지 않는다.
--
-- ⚠️ oauth2_authorization 대용량 컬럼은 처음부터 longtext로 생성한다(blob 아님). MariaDB Connector/J는
--    `blob` 컬럼을 LONGVARBINARY로 보고해 SAS의 문자열 bind(JSON 직렬화)와 타입이 어긋나 저장이 실패한다.
--    longtext는 String bind/read와 정합돼 문제가 없다 — 이 스키마는 신규 생성이라 blob으로 만들었다가
--    나중에 ALTER하는 2단계를 거칠 필요가 없다.

-- ============================================================
-- Table 1: oauth2_registered_client
-- OAuth2/OIDC 등록 클라이언트 — RP(Relying Party) 메타데이터 1행 = 1 클라이언트.
-- ============================================================
CREATE TABLE oauth2_registered_client (
    id varchar(100) NOT NULL COMMENT 'PK — 등록 클라이언트 내부 식별자(SAS 생성 UUID 등). client_id와 별개의 행 PK',
    client_id varchar(100) NOT NULL COMMENT 'OAuth2 client_id — RP가 토큰/인가 요청 시 제출하는 공개 식별자(OIDC client_id)',
    client_id_issued_at timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL COMMENT 'client_id 발급 시각',
    client_secret varchar(200) DEFAULT NULL COMMENT 'client_secret — confidential 클라이언트 인증 비밀값(public 클라이언트는 NULL). 해시/암호화 저장',
    client_secret_expires_at timestamp DEFAULT NULL COMMENT 'client_secret 만료 시각 — NULL이면 무기한',
    client_name varchar(200) NOT NULL COMMENT '클라이언트 표시명 — 동의 화면/관리 UI 노출용',
    client_authentication_methods varchar(1000) NOT NULL COMMENT '클라이언트 인증 방식 목록(콤마 구분) — client_secret_basic / client_secret_post / none / private_key_jwt 등',
    authorization_grant_types varchar(1000) NOT NULL COMMENT '허용 grant type 목록(콤마 구분) — authorization_code / refresh_token / client_credentials 등',
    redirect_uris varchar(1000) DEFAULT NULL COMMENT '허용 redirect_uri 화이트리스트(콤마 구분) — authorization_code 콜백 검증용',
    post_logout_redirect_uris varchar(1000) DEFAULT NULL COMMENT 'OIDC RP-Initiated Logout 후 리다이렉트 허용 URI 목록(콤마 구분)',
    scopes varchar(1000) NOT NULL COMMENT '허용 scope 목록(콤마 구분) — openid / email 등 발급 가능 범위',
    client_settings varchar(2000) NOT NULL COMMENT '클라이언트 설정(SAS 직렬화 문자열) — require PKCE / require consent 등',
    token_settings varchar(2000) NOT NULL COMMENT '토큰 설정(SAS 직렬화 문자열) — access/refresh TTL, ID token 서명 알고리즘 등',
    PRIMARY KEY (id)
);

-- ============================================================
-- Table 2: oauth2_authorization
-- OAuth2 인가 상태 — 인가코드/액세스/리프레시/ID 토큰 등 1 인가 흐름의 durable 저장.
-- ============================================================
CREATE TABLE oauth2_authorization (
    id varchar(100) NOT NULL COMMENT 'PK — 인가(authorization) 레코드 식별자',
    registered_client_id varchar(100) NOT NULL COMMENT 'FK(논리) → oauth2_registered_client.id. 이 인가를 발급받은 클라이언트',
    principal_name varchar(200) NOT NULL COMMENT '리소스 소유자 식별자 — 토큰 sub 클레임 기반(morymaker는 account.id UUID)',
    authorization_grant_type varchar(100) NOT NULL COMMENT '이 인가에 사용된 grant type — authorization_code / refresh_token 등',
    authorized_scopes varchar(1000) DEFAULT NULL COMMENT '리소스 소유자가 동의한 scope 목록(콤마 구분)',
    attributes longtext DEFAULT NULL COMMENT 'SAS 직렬화 인가 속성(OAuth2AuthorizationRequest 등 컨텍스트)',
    state varchar(500) DEFAULT NULL COMMENT 'authorization_code 흐름 CSRF 방지 state 값',
    authorization_code_value longtext DEFAULT NULL COMMENT '발급된 authorization_code 값(직렬화)',
    authorization_code_issued_at timestamp DEFAULT NULL COMMENT 'authorization_code 발급 시각',
    authorization_code_expires_at timestamp DEFAULT NULL COMMENT 'authorization_code 만료 시각(단기)',
    authorization_code_metadata longtext DEFAULT NULL COMMENT 'authorization_code 메타데이터(사용 여부 등, 직렬화)',
    access_token_value longtext DEFAULT NULL COMMENT '발급된 access token 값(직렬화)',
    access_token_issued_at timestamp DEFAULT NULL COMMENT 'access token 발급 시각',
    access_token_expires_at timestamp DEFAULT NULL COMMENT 'access token 만료 시각',
    access_token_metadata longtext DEFAULT NULL COMMENT 'access token 메타데이터(클레임 등, 직렬화)',
    access_token_type varchar(100) DEFAULT NULL COMMENT 'access token 유형 — 통상 Bearer',
    access_token_scopes varchar(1000) DEFAULT NULL COMMENT 'access token에 부여된 scope 목록(콤마 구분)',
    oidc_id_token_value longtext DEFAULT NULL COMMENT 'OIDC ID token(JWT) 값(직렬화) — 인증 사실 증명 클레임 토큰',
    oidc_id_token_issued_at timestamp DEFAULT NULL COMMENT 'ID token 발급 시각',
    oidc_id_token_expires_at timestamp DEFAULT NULL COMMENT 'ID token 만료 시각',
    oidc_id_token_metadata longtext DEFAULT NULL COMMENT 'ID token 메타데이터(클레임 등, 직렬화)',
    refresh_token_value longtext DEFAULT NULL COMMENT '발급된 refresh token 값 — at-rest SHA-256 hex 64자 저장(평문 금지)',
    refresh_token_issued_at timestamp DEFAULT NULL COMMENT 'refresh token 발급 시각',
    refresh_token_expires_at timestamp DEFAULT NULL COMMENT 'refresh token 만료 시각(장기)',
    refresh_token_metadata longtext DEFAULT NULL COMMENT 'refresh token 메타데이터(직렬화)',
    user_code_value longtext DEFAULT NULL COMMENT 'Device Authorization Grant user_code 값(직렬화) — morymaker 미사용 grant, 벤더 스키마 보존 목적',
    user_code_issued_at timestamp DEFAULT NULL COMMENT 'user_code 발급 시각',
    user_code_expires_at timestamp DEFAULT NULL COMMENT 'user_code 만료 시각',
    user_code_metadata longtext DEFAULT NULL COMMENT 'user_code 메타데이터(직렬화)',
    device_code_value longtext DEFAULT NULL COMMENT 'Device Authorization Grant device_code 값(직렬화) — morymaker 미사용 grant, 벤더 스키마 보존 목적',
    device_code_issued_at timestamp DEFAULT NULL COMMENT 'device_code 발급 시각',
    device_code_expires_at timestamp DEFAULT NULL COMMENT 'device_code 만료 시각',
    device_code_metadata longtext DEFAULT NULL COMMENT 'device_code 메타데이터(직렬화)',
    PRIMARY KEY (id)
);

-- ============================================================
-- Table 3: oauth2_authorization_consent
-- 리소스 소유자 동의 기록 — (client, principal)별 부여 authority 집합. 재동의 생략 판단에 사용.
-- ============================================================
CREATE TABLE oauth2_authorization_consent (
    registered_client_id varchar(100) NOT NULL COMMENT 'PK(복합) — 동의 대상 클라이언트(oauth2_registered_client.id 참조)',
    principal_name varchar(200) NOT NULL COMMENT 'PK(복합) — 동의한 리소스 소유자 식별자(account.id UUID 기반)',
    authorities varchar(1000) NOT NULL COMMENT '소유자가 이 클라이언트에 부여한 authority/scope 집합(콤마 구분) — 동의 화면 재노출 여부 판단',
    PRIMARY KEY (registered_client_id, principal_name)
);

-- ============================================================
-- Table 4: consumed_refresh_tokens
-- rotation으로 소비된(교체된) refresh token 해시를 일시 보존 — 재제시(replay) 시 패밀리 무효화 탐지에 사용.
-- raw 토큰은 저장하지 않는다. token_hash 컬럼에는 SHA-256 lowercase hex 64자만 저장한다.
--
-- fail-CLOSED 불변식: record-before-overwrite + 단일 트랜잭션. HashedRefreshTokenAuthorizationService(Decorator)가
--   rotation overwrite 전에 구 토큰 해시를 이 테이블에 INSERT한다. INSERT가 실패하면 전체 트랜잭션이 롤백되어
--   rotation 자체가 실패한다 — 새 refresh token이 발급되지 않는다.
--
-- lazy-evict 정책: bulk cleanup 스케줄러 없음. 조회 시 `expires_at > #{now}` JDBC 파라미터 바인딩으로 만료 항목을
--   자연 제외한다(DB 서버 NOW() 비사용 — timezone 안전). 만료 행은 조회에 영향 없어 무해하게 잔류한다.
--
-- FK 없음(설계): authorization_id는 oauth2_authorization.id 참조이나, 패밀리 무효화 시 oauth2_authorization
--   행이 먼저 삭제될 수 있어 FK를 두지 않는다. 소비 후 authorization 행이 삭제되어도 이 레코드는 TTL까지 보존된다
--   (레코드 존재 자체가 "이 hash는 재사용됐음"의 신호).
CREATE TABLE consumed_refresh_tokens
(
    id               CHAR(36)     NOT NULL COMMENT 'PK — UUID. 어댑터가 record() 호출 시 생성.',
    authorization_id VARCHAR(100) NOT NULL COMMENT 'oauth2_authorization.id — 패밀리 무효화 대상 authorization 식별자. FK 미선언(패밀리 무효화 시 authorization 행이 먼저 삭제될 수 있음). 로그에는 이 값(id)만 허용, token_hash는 출력 금지.',
    token_hash       VARCHAR(64)  NOT NULL COMMENT 'SHA-256 lowercase hex 64자. rotation으로 소비된 구 refresh token의 at-rest 해시값. raw 토큰은 저장하지 않는다. UNIQUE — 같은 해시가 두 행에 존재할 수 없어야 함.',
    consumed_at      DATETIME     NOT NULL COMMENT '소비일시. rotation save() 시 기록. grace 창 판정: NOW() - consumed_at <= graceWindow 이면 패밀리 kill 억제.',
    expires_at       DATETIME     NOT NULL COMMENT '이 기록의 만료일시. 구 토큰의 실 만료(oauth2_authorization.refresh_token_value의 만료시각) + 5분 margin. expires_at > #{now} JDBC 바인딩으로 만료 항목 자연 제외(lazy-evict — timezone 안전).',
    created_at       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '행 생성일시.',

    PRIMARY KEY (id),
    CONSTRAINT uq_consumed_refresh_tokens_hash UNIQUE (token_hash),
    INDEX idx_consumed_refresh_authorization_id (authorization_id),
    INDEX idx_consumed_refresh_expires_at       (expires_at)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_unicode_ci
  COMMENT = 'rotation으로 소비된 refresh token 해시 레지스트리. 재사용(replay) 탐지 + 패밀리 무효화에 사용. raw 토큰 저장 금지 — token_hash(SHA-256 hex 64자)만 저장. expires_at > #{now} JDBC 바인딩으로 lazy-evict.';

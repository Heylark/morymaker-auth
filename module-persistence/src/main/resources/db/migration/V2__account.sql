-- V2__account.sql
-- 로그인 계정 테이블 (RBAC B — account.role 단일 컬럼, 스키마 SSOT).
-- password_hash/failed_attempts/locked_at/locked_until을 account 테이블에 직접 통합한다
-- (별도 물리 테이블 없음 — 단일 물리 테이블 통합 결정).
--
-- role/permission 4테이블(roles/permissions/user_roles/role_permissions)은 미도입.
-- 3역할(SYSTEM_ADMIN/EVENT_ADMIN/EVENT_STAFF) 고정 + `hasAnyRole` 게이트만 사용한다
-- (MoryRoles 상수 참조) — MyBatis JOIN·nested <collection> dedup 패턴 자체가 불필요해진다.
--
-- status는 한글 "활성"/"비활성"(스키마 SSOT 값 — yulse 원본의 영문 ACTIVE/INACTIVE와 다름).
-- email 콜레이션(utf8mb4_unicode_ci)이 대소문자 무시 비교를 DB 레벨에서 보장한다.
CREATE TABLE account (
    id             CHAR(36)     NOT NULL COMMENT '계정 PK — JWT sub, 앱이 UUID 생성',
    email          VARCHAR(190) NOT NULL COMMENT '로그인 아이디(utf8mb4 인덱스 안전 길이)',
    name           VARCHAR(60)  NULL     COMMENT '표시 이름',
    role           VARCHAR(20)  NOT NULL COMMENT 'SYSTEM_ADMIN / EVENT_ADMIN / EVENT_STAFF (영문 코드)',
    password_hash  VARCHAR(255) NOT NULL COMMENT 'BCrypt 해시',
    failed_attempts INT         NOT NULL DEFAULT 0 COMMENT '연속 로그인 실패 횟수 — 잠금 정책 판정 기준',
    locked_at      DATETIME     NULL     COMMENT '잠금 시작 시각(null=미잠금)',
    locked_until   DATETIME     NULL     COMMENT '잠금 해제 예정 시각 — 경과 시 애플리케이션이 자동 해제(시간 기반, 수동 해제 UI 없음)',
    status         VARCHAR(10)  NOT NULL DEFAULT '활성' COMMENT '활성/비활성 — 삭제가 아닌 토글',
    note           VARCHAR(120) NULL     COMMENT '실행자 담당 위치 메모',
    created_at     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    CONSTRAINT uk_account_email UNIQUE (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='로그인 계정';

-- V3__account_event.sql
-- 계정-행사 담당 M:N 매핑(EventScopePort 조회 대상).
--
-- event_id는 api 소유 event 테이블(후속 api 구축에서 생성, 이 시점엔 아직 존재하지 않음)을 가리키지만
-- 물리 FK는 걸지 않는다 — auth·api가 각자 Flyway를 돌리는 공유 DB에서 교차 소유 FK는 auth
-- Flyway 독립 실행을 깨뜨린다. 참조 무결성은 api EventScopeGuard·쿼리 계층이 담보한다.
--
-- 순수 매핑 테이블(비즈니스 속성 없음) — 복합 PK가 곧 유니크 제약 + 기본 키 역할을 겸한다.
CREATE TABLE account_event (
    account_id CHAR(36) NOT NULL COMMENT 'FK → account.id',
    event_id   CHAR(36) NOT NULL COMMENT 'event.id(UUID) — api 소유 event 테이블 참조, 물리 FK 없음',
    PRIMARY KEY (account_id, event_id),
    CONSTRAINT fk_ae_account FOREIGN KEY (account_id) REFERENCES account(id) ON DELETE CASCADE,
    INDEX idx_ae_event (event_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='계정-행사 담당 M:N';

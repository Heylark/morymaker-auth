-- V4__account_updated_at.sql
-- account.updated_at 감사 컬럼 — 이번 REQ가 도입하는 관리자 update/toggle이 account 최초 mutation
-- 표면이라 db-design 표준(전 테이블 updated_at)을 여기서 회수한다.
--
-- DB가 ON UPDATE로 자동 갱신하는 관리 컬럼이다 — Account 도메인 생성자·BaseResultMap에는 유입하지
-- 않는다(응답에도 노출하지 않으므로 도메인 threading 불요, 동결 코드 0접촉으로 안전).
--
-- 로그인 실패/성공 기록(동결 AccountMapper.update, 잠금 상태 전이)도 이 컬럼을 자동 bump한다 —
-- "행이 변경됨"은 사실이므로 정확한 동작이며, 동결 코드 자체는 SQL 변경 없이 그대로 유지된다.
ALTER TABLE account
    ADD COLUMN updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    COMMENT '수정일시 — 관리자 변경·상태 전이 추적' AFTER created_at;

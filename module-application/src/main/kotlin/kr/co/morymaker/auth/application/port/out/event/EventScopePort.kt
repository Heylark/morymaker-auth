package kr.co.morymaker.auth.application.port.out.event

/**
 * 토큰 발급 시점의 event 스코프(담당 행사 목록) 조회 port-out — `TokenCustomizerConfig`가 의존하는 SPI.
 *
 * 헥사고날 레이어: application port-out(SPI 인터페이스 — 구현체는 module-persistence 내부).
 *
 * yulse `OrgContextPort.resolveOrgContext`(단일 org_id 스칼라)를 그대로 옮기지 않는다 — morymaker
 * 계정은 여러 행사를 동시에 담당할 수 있어 이 인터페이스는 배열을 반환한다(단일 org 스칼라 → 복수 event 배열).
 *
 * 조회 흐름(구현체 책임):
 * 1. accountId로 role을 조회한다. role을 찾지 못하면(계정 미상) null을 반환한다 — 클레임을 생략하는
 *    안전 측 판단이다.
 * 2. role이 SYSTEM_ADMIN이면 null을 반환한다(전체 허용 — claim 자체를 생략한다). 단 이 "전체 허용"은
 *    auth가 토큰에 event_ids를 싣지 않는다는 뜻일 뿐이고, 실제 접근 강제(요청한 event_id가 허용
 *    범위인지 검증)는 이 서버의 책임이 아니라 api의 EventScopeGuard가 담당한다 — auth는 발급까지만
 *    책임진다.
 * 3. 그 외(EVENT_ADMIN/EVENT_STAFF)는 account_event에서 담당 event_id 목록을 조회해 반환한다(아직
 *    배정된 행사가 없는 신규 계정도 빈 리스트로 정상 발급된다 — null과 의미가 다르다).
 *
 * @see kr.co.morymaker.auth.persistence.adapter.persistence.event.EventScopePersistenceAdapter
 */
interface EventScopePort {

    /**
     * @param accountId 계정 PK(account.id UUID) — JWT `principal.name`과 동일 값
     * @return null(SYSTEM_ADMIN 또는 계정 미상 — 클레임 생략) 또는 event_id 목록(빈 리스트 허용)
     */
    fun resolveEventIds(accountId: String): List<String>?
}

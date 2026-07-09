package kr.co.morymaker.auth.application.port.out.event

/**
 * 계정-행사 담당 M:N(account_event) 어드민 read+write port-out — §3-1(목록 eventIds 조립)·
 * §3-2/§3-3(행사할당 delete-insert 재작성) 소비.
 *
 * [EventScopePort](토큰 발급 시점 mint-time 조회, SYSTEM_ADMIN→null 특수 의미)와 의도적으로
 * 분리한다 — 이 포트는 어드민 CRUD 전용이라 "빈 리스트"와 "미상"을 구분할 필요가 없고, 쓰기
 * 오퍼레이션(replaceEventIds)을 포함한다.
 */
interface AccountEventPort {

    /**
     * accountId가 담당하는 행사 목록을 delete-insert 전량 재작성한다(원자성은 호출자의
     * `@Transactional` 경계 — AccountAdminService).
     */
    fun replaceEventIds(accountId: String, eventIds: List<String>)

    /** 단건 응답 조립(§3-3/§3-4 갱신 후 재조회). */
    fun findEventIds(accountId: String): List<String>

    /** 목록 응답 조립용 배치 조회(§3-1) — N+1 회피. 배정 0건인 계정은 결과 맵에 키 자체가 없다. */
    fun findEventIdsByAccountIds(accountIds: List<String>): Map<String, List<String>>
}

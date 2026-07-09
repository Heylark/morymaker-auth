package kr.co.morymaker.auth.persistence.adapter.persistence.event

import kr.co.morymaker.auth.application.port.out.event.AccountEventPort
import kr.co.morymaker.auth.persistence.adapter.persistence.event.mapper.AccountEventMapper
import org.springframework.stereotype.Component

/**
 * [AccountEventPort] 구현체 — 어드민 CRUD 전용(mint-time 조회 [EventScopePersistenceAdapter]와 분리,
 * 같은 [AccountEventMapper]를 공유하되 신설된 쓰기 메서드만 사용한다).
 *
 * 헥사고날 레이어: Persistence(adapter). `internal`: application 계층은 [AccountEventPort] 인터페이스만
 * 의존한다 — module-persistence 외부에서 직접 참조 금지(레이어 의존 방향 위반).
 */
@Component
internal class AccountEventPersistenceAdapter(
    private val accountEventMapper: AccountEventMapper,
) : AccountEventPort {

    /**
     * 전량 delete 후 전량 insert(원자성은 호출자의 `@Transactional` 경계 — AccountAdminService).
     * eventIds가 빈 리스트면 delete만 실행되고 잔존 행이 0건이 된다(SYSTEM_ADMIN 전환 경로).
     */
    override fun replaceEventIds(accountId: String, eventIds: List<String>) {
        accountEventMapper.deleteByAccountId(accountId)
        eventIds.forEach { eventId -> accountEventMapper.insert(accountId, eventId) }
    }

    override fun findEventIds(accountId: String): List<String> = accountEventMapper.findEventIds(accountId)

    /** accountIds가 비어있으면 쿼리를 아예 호출하지 않는다(빈 IN절 방지). */
    override fun findEventIdsByAccountIds(accountIds: List<String>): Map<String, List<String>> {
        if (accountIds.isEmpty()) return emptyMap()
        return accountEventMapper.findEventIdsByAccountIds(accountIds)
            .groupBy(keySelector = { it.accountId }, valueTransform = { it.eventId })
    }
}

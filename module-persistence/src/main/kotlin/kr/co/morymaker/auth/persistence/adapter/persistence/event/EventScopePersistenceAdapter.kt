package kr.co.morymaker.auth.persistence.adapter.persistence.event

import kr.co.morymaker.auth.application.port.out.event.EventScopePort
import kr.co.morymaker.auth.domain.account.MoryRoles
import kr.co.morymaker.auth.persistence.adapter.persistence.account.mapper.AccountMapper
import kr.co.morymaker.auth.persistence.adapter.persistence.event.mapper.AccountEventMapper
import org.springframework.stereotype.Component

/**
 * [EventScopePort] 구현체 — 1-hop 조회(yulse의 client_org 2-hop 불요, 단일 web 클라이언트).
 *
 * 헥사고날 레이어: Persistence(adapter). `internal`: application 계층은 [EventScopePort] 인터페이스만
 * 의존한다 — 이 클래스를 module-persistence 외부에서 직접 참조하는 것은 금지된다(레이어 의존 방향 위반).
 *
 * 판정 순서:
 * 1. [AccountMapper.selectRoleById]로 role을 조회한다. 계정이 존재하지 않으면(role==null) 미상 계정이라
 *    클레임을 생략한다(null 반환 — 안전 측 판단).
 * 2. role이 [MoryRoles.SYSTEM_ADMIN]이면 null을 반환한다(전체 허용 — claim 자체 생략). 이 판정은
 *    역할로만 이뤄진다 — event_ids 부재만으로 전체 허용을 단정하는 강제는 여기서 하지 않는다(그 강제는
 *    api의 EventScopeGuard 몫).
 * 3. 그 외(EVENT_ADMIN/EVENT_STAFF)는 [AccountEventMapper.findEventIds]로 담당 event_id 목록을
 *    반환한다(빈 리스트 허용 — 아직 배정된 행사가 없는 계정도 정상 발급된다).
 */
@Component
internal class EventScopePersistenceAdapter(
    private val accountMapper: AccountMapper,
    private val accountEventMapper: AccountEventMapper,
) : EventScopePort {

    override fun resolveEventIds(accountId: String): List<String>? {
        val role = accountMapper.selectRoleById(accountId) ?: return null
        if (role == MoryRoles.SYSTEM_ADMIN) return null
        return accountEventMapper.findEventIds(accountId)
    }
}

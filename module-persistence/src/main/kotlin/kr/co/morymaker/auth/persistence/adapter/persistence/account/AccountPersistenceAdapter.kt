package kr.co.morymaker.auth.persistence.adapter.persistence.account

import kr.co.morymaker.auth.application.port.out.account.AccountPort
import kr.co.morymaker.auth.application.port.out.account.AccountSearch
import kr.co.morymaker.auth.domain.account.Account
import kr.co.morymaker.auth.persistence.adapter.persistence.account.mapper.AccountMapper
import org.springframework.stereotype.Component

/**
 * [AccountPort] 구현체 — MyBatis 매퍼 위임.
 *
 * 헥사고날 레이어: Persistence (adapter). `internal`: application 계층은 [AccountPort] 인터페이스만
 * 의존한다 — 이 클래스를 module-persistence 외부에서 직접 참조하는 것은 금지된다(레이어 의존 방향 위반).
 *
 * RBAC B — 단일 테이블 조회, JOIN·nested collection dedup 패턴 없음.
 */
@Component
internal class AccountPersistenceAdapter(
    private val accountMapper: AccountMapper,
) : AccountPort {

    override fun findByEmail(email: String): Account? = accountMapper.selectByEmail(email)

    override fun findById(id: String): Account? = accountMapper.selectById(id)

    override fun findRoleById(id: String): String? = accountMapper.selectRoleById(id)

    /** 로그인 시도 결과([Account] 잠금 상태 전이)만 반영하는 좁은 UPDATE(AccountPort.save KDoc 참조). */
    override fun save(account: Account) {
        accountMapper.update(
            id = account.id,
            failedAttempts = account.failedAttempts,
            lockedAt = account.lockedAt,
            lockedUntil = account.lockedUntil,
        )
    }

    /** 계정 신규 생성(§3-2) — email UNIQUE 위반 시 durable 저장소가 DuplicateKeyException을 던진다. */
    override fun insert(account: Account) {
        accountMapper.insert(account)
    }

    /** 프로필 갱신(§3-3) — 이름·역할·메모만. email·password·잠금 필드는 건드리지 않는다. */
    override fun updateProfile(id: String, name: String?, role: String, note: String?) {
        accountMapper.updateProfile(id = id, name = name, role = role, note = note)
    }

    /** 상태 토글(§3-4). */
    override fun updateStatus(id: String, status: String) {
        accountMapper.updateStatus(id = id, status = status)
    }

    /** 목록 조회(§3-1) — role/status/q 필터 + 페이징. */
    override fun search(search: AccountSearch): List<Account> = accountMapper.search(search)

    /** 전체 건수(§3-1) — 호출자가 `search.paging=false`로 넘겨야 정확한 전체 건수가 나온다. */
    override fun count(search: AccountSearch): Int = accountMapper.searchTotalCnt(search)
}

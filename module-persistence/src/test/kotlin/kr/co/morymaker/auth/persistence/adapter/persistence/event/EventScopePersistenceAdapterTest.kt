package kr.co.morymaker.auth.persistence.adapter.persistence.event

import io.mockk.every
import io.mockk.mockk
import kr.co.morymaker.auth.persistence.adapter.persistence.account.mapper.AccountMapper
import kr.co.morymaker.auth.persistence.adapter.persistence.event.mapper.AccountEventMapper
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * [EventScopePersistenceAdapter] 단위 테스트 — 역할→event_ids 판정 분기(SYSTEM_ADMIN→null / 미상 계정→null / 그 외→목록).
 */
class EventScopePersistenceAdapterTest {

    private val accountMapper: AccountMapper = mockk()
    private val accountEventMapper: AccountEventMapper = mockk()
    private val sut = EventScopePersistenceAdapter(accountMapper, accountEventMapper)

    @Test
    fun `role이 SYSTEM_ADMIN이면 null을 반환한다 (전체 허용 — claim 생략)`() {
        every { accountMapper.selectRoleById("sysadmin-1") } returns "SYSTEM_ADMIN"

        assertNull(sut.resolveEventIds("sysadmin-1"))
    }

    @Test
    fun `role 조회 결과가 없으면(미상 계정) null을 반환한다`() {
        every { accountMapper.selectRoleById("unknown-1") } returns null

        assertNull(sut.resolveEventIds("unknown-1"))
    }

    @Test
    fun `EVENT_ADMIN은 account_event 조회 결과를 그대로 반환한다`() {
        every { accountMapper.selectRoleById("admin-1") } returns "EVENT_ADMIN"
        every { accountEventMapper.findEventIds("admin-1") } returns listOf("event-a", "event-b")

        assertEquals(listOf("event-a", "event-b"), sut.resolveEventIds("admin-1"))
    }

    @Test
    fun `배정된 행사가 없는 EVENT_STAFF는 빈 리스트를 반환한다 (null과 구분)`() {
        every { accountMapper.selectRoleById("staff-1") } returns "EVENT_STAFF"
        every { accountEventMapper.findEventIds("staff-1") } returns emptyList()

        val result = sut.resolveEventIds("staff-1")

        assertTrue(result != null && result.isEmpty(), "null이 아닌 빈 리스트여야 함(SYSTEM_ADMIN의 null과 구분)")
    }
}

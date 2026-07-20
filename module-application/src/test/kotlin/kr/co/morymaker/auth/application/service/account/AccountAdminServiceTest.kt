package kr.co.morymaker.auth.application.service.account

import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import kr.co.morymaker.auth.application.port.out.account.AccountPort
import kr.co.morymaker.auth.application.port.out.account.AccountSearch
import kr.co.morymaker.auth.application.port.out.event.AccountEventPort
import kr.co.morymaker.auth.application.port.out.security.PasswordEncoderPort
import kr.co.morymaker.auth.application.service.dto.AccountCreateCommand
import kr.co.morymaker.auth.application.service.dto.AccountUpdateCommand
import kr.co.morymaker.auth.domain.account.Account
import kr.co.morymaker.auth.domain.account.MoryRoles
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset

/**
 * [AccountAdminService] 단위 테스트 — §3 어드민 CRUD 핵심 규칙(이메일 중복·역할별 eventIds
 * 필수·SYSTEM_ADMIN eventIds 무시·delete-insert 위임)을 검증한다.
 */
class AccountAdminServiceTest {

    private val accountPort: AccountPort = mockk()
    private val accountEventPort: AccountEventPort = mockk()
    private val passwordEncoderPort: PasswordEncoderPort = mockk()
    private val fixedNow = Instant.parse("2026-01-01T00:00:00Z")
    private val clock = Clock.fixed(fixedNow, ZoneOffset.UTC)

    private lateinit var sut: AccountAdminService

    @BeforeEach
    fun setUp() {
        sut = AccountAdminService(
            accountPort = accountPort,
            accountEventPort = accountEventPort,
            passwordEncoderPort = passwordEncoderPort,
            clock = clock,
        )
    }

    private fun accountOf(
        id: String = "acc-1",
        email: String = "staff@morymaker.co.kr",
        role: String = MoryRoles.EVENT_STAFF,
        status: String = Account.STATUS_ACTIVE,
    ) = Account(
        id = id,
        email = email,
        name = "실행자",
        role = role,
        status = status,
        passwordHash = "{bcrypt-hash}",
        failedAttempts = 0,
        lockedAt = null,
        lockedUntil = null,
        note = null,
        createdAt = fixedNow,
    )

    // ── create ──

    @Test
    fun `create 는 이메일 중복이면 EmailDuplicateException 을 던진다`() {
        every { accountPort.findByEmail("dup@morymaker.co.kr") } returns accountOf(email = "dup@morymaker.co.kr")

        val command = AccountCreateCommand(
            email = "dup@morymaker.co.kr",
            name = "테스트",
            role = MoryRoles.EVENT_STAFF,
            eventIds = listOf("event-1"),
            note = null,
            password = "password123",
        )

        assertThrows(EmailDuplicateException::class.java) { sut.create(command) }
        verify(exactly = 0) { accountPort.insert(any()) }
    }

    @Test
    fun `create 는 EVENT_STAFF 인데 eventIds 가 비어있으면 EventAssignmentRequiredException 을 던진다`() {
        every { accountPort.findByEmail(any()) } returns null

        val command = AccountCreateCommand(
            email = "new@morymaker.co.kr",
            name = "테스트",
            role = MoryRoles.EVENT_STAFF,
            eventIds = emptyList(),
            note = null,
            password = "password123",
        )

        assertThrows(EventAssignmentRequiredException::class.java) { sut.create(command) }
        verify(exactly = 0) { accountPort.insert(any()) }
    }

    @Test
    fun `create 는 유효하지 않은 role 이면 IllegalArgumentException 을 던진다`() {
        every { accountPort.findByEmail(any()) } returns null

        val command = AccountCreateCommand(
            email = "new@morymaker.co.kr",
            name = "테스트",
            role = "UNKNOWN_ROLE",
            eventIds = emptyList(),
            note = null,
            password = "password123",
        )

        assertThrows(IllegalArgumentException::class.java) { sut.create(command) }
        verify(exactly = 0) { accountPort.insert(any()) }
    }

    @Test
    fun `create 는 성공 시 비밀번호를 인코딩해 insert 하고 eventIds 를 재작성한다`() {
        every { accountPort.findByEmail("new@morymaker.co.kr") } returns null
        every { passwordEncoderPort.encode("password123") } returns "{bcrypt}encoded"
        val insertedSlot = slot<Account>()
        every { accountPort.insert(capture(insertedSlot)) } returns Unit
        // id는 서비스 내부에서 UUID.randomUUID()로 생성되므로 인자 매처는 any() — 실제 값은 아래 verify에서
        // insertedSlot으로 캡처된 실 id와 대조한다.
        every { accountEventPort.replaceEventIds(any(), listOf("event-1")) } returns Unit

        val command = AccountCreateCommand(
            email = "new@morymaker.co.kr",
            name = "테스트",
            role = MoryRoles.EVENT_STAFF,
            eventIds = listOf("event-1"),
            note = "메모",
            password = "password123",
        )

        val result = sut.create(command)

        assertEquals("{bcrypt}encoded", insertedSlot.captured.passwordHash)
        assertEquals("new@morymaker.co.kr", insertedSlot.captured.email)
        assertEquals(Account.STATUS_ACTIVE, insertedSlot.captured.status)
        assertEquals(listOf("event-1"), result.eventIds)
        verify(exactly = 1) { accountEventPort.replaceEventIds(insertedSlot.captured.id, listOf("event-1")) }
    }

    @Test
    fun `create 는 SYSTEM_ADMIN 이면 eventIds 검증을 건너뛰고 배정을 비운다`() {
        every { accountPort.findByEmail(any()) } returns null
        every { passwordEncoderPort.encode(any()) } returns "{bcrypt}encoded"
        every { accountPort.insert(any()) } returns Unit
        val replacedSlot = slot<List<String>>()
        every { accountEventPort.replaceEventIds(any(), capture(replacedSlot)) } returns Unit

        val command = AccountCreateCommand(
            email = "admin@morymaker.co.kr",
            name = "관리자",
            role = MoryRoles.SYSTEM_ADMIN,
            eventIds = listOf("event-1", "event-2"), // SYSTEM_ADMIN은 무시돼야 함
            note = null,
            password = "password123",
        )

        val result = sut.create(command)

        assertTrue(replacedSlot.captured.isEmpty())
        assertTrue(result.eventIds.isEmpty())
    }

    // ── update ──

    @Test
    fun `update 는 존재하지 않는 id 면 AccountNotFoundException 을 던진다`() {
        every { accountPort.findById("missing") } returns null

        val command = AccountUpdateCommand(name = "이름", role = MoryRoles.EVENT_ADMIN, eventIds = listOf("event-1"), note = null)

        assertThrows(AccountNotFoundException::class.java) { sut.update("missing", command) }
    }

    @Test
    fun `update 는 역할 변경 시 account_event 를 전량 재작성한다`() {
        val existing = accountOf(role = MoryRoles.EVENT_STAFF)
        every { accountPort.findById("acc-1") } returns existing
        every { accountPort.updateProfile(id = "acc-1", name = "새 이름", role = MoryRoles.EVENT_ADMIN, note = "메모") } returns Unit
        every { accountEventPort.replaceEventIds("acc-1", listOf("event-2")) } returns Unit

        val command = AccountUpdateCommand(name = "새 이름", role = MoryRoles.EVENT_ADMIN, eventIds = listOf("event-2"), note = "메모")

        val result = sut.update("acc-1", command)

        verify(exactly = 1) { accountPort.updateProfile(id = "acc-1", name = "새 이름", role = MoryRoles.EVENT_ADMIN, note = "메모") }
        verify(exactly = 1) { accountEventPort.replaceEventIds("acc-1", listOf("event-2")) }
        assertEquals(listOf("event-2"), result.eventIds)
    }

    // ── toggleStatus ──

    @Test
    fun `toggleStatus 는 존재하지 않는 id 면 AccountNotFoundException 을 던진다`() {
        every { accountPort.findById("missing") } returns null

        assertThrows(AccountNotFoundException::class.java) { sut.toggleStatus("missing", Account.STATUS_INACTIVE) }
    }

    @Test
    fun `toggleStatus 는 활성 비활성이 아니면 IllegalArgumentException 을 던진다`() {
        every { accountPort.findById("acc-1") } returns accountOf()

        assertThrows(IllegalArgumentException::class.java) { sut.toggleStatus("acc-1", "UNKNOWN") }
        verify(exactly = 0) { accountPort.updateStatus(any(), any()) }
    }

    @Test
    fun `toggleStatus 는 성공 시 상태를 갱신하고 재조회한 계정을 반환한다`() {
        val existing = accountOf(status = Account.STATUS_ACTIVE)
        val updated = accountOf(status = Account.STATUS_INACTIVE)
        every { accountPort.findById("acc-1") } returnsMany listOf(existing, updated)
        every { accountPort.updateStatus("acc-1", Account.STATUS_INACTIVE) } returns Unit
        every { accountEventPort.findEventIds("acc-1") } returns listOf("event-1")

        val result = sut.toggleStatus("acc-1", Account.STATUS_INACTIVE)

        assertEquals(Account.STATUS_INACTIVE, result.account.status)
        assertEquals(listOf("event-1"), result.eventIds)
    }

    // ── list ──

    @Test
    fun `list 는 검색 결과와 배치 조회한 eventIds 를 조립한다`() {
        val search = AccountSearch(role = MoryRoles.EVENT_STAFF, page = 1, size = 50)
        val accounts = listOf(accountOf(id = "acc-1"), accountOf(id = "acc-2"))
        every { accountPort.search(search) } returns accounts
        every { accountPort.count(search.copy(paging = false)) } returns 2
        every { accountEventPort.findEventIdsByAccountIds(listOf("acc-1", "acc-2")) } returns
            mapOf("acc-1" to listOf("event-1"))

        val page = sut.list(search)

        assertEquals(2, page.total)
        assertEquals(listOf("event-1"), page.items.first { it.account.id == "acc-1" }.eventIds)
        assertTrue(page.items.first { it.account.id == "acc-2" }.eventIds.isEmpty())
    }
}

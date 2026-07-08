package kr.co.morymaker.auth.application.service.account

import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import kr.co.morymaker.auth.application.port.out.account.AccountPort
import kr.co.morymaker.auth.domain.account.Account
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset

/**
 * [AccountService] 단위 테스트 — 잠금 정책(시간 경과 자동 해제 최소안) 기록 + 사용자 열거 방지 확인.
 */
class AccountServiceTest {

    private val accountPort: AccountPort = mockk()
    private val fixedNow = Instant.parse("2026-01-01T00:00:00Z")
    private val clock = Clock.fixed(fixedNow, ZoneOffset.UTC)

    private lateinit var sut: AccountService

    @BeforeEach
    fun setUp() {
        sut = AccountService(
            accountPort = accountPort,
            maxFailedAttempts = 5,
            lockDuration = Duration.ofMinutes(15),
            clock = clock,
        )
    }

    private fun accountOf(id: String = "acc-1", email: String = "admin@morymaker.co.kr", failedAttempts: Int = 0) = Account(
        id = id,
        email = email,
        name = "관리자",
        role = "SYSTEM_ADMIN",
        status = Account.STATUS_ACTIVE,
        passwordHash = "{bcrypt-hash}",
        failedAttempts = failedAttempts,
        lockedAt = null,
        lockedUntil = null,
        note = null,
        createdAt = fixedNow,
    )

    @Test
    fun `findByEmail 은 port 결과를 그대로 반환한다`() {
        val account = accountOf()
        every { accountPort.findByEmail("admin@morymaker.co.kr") } returns account

        assertEquals(account, sut.findByEmail("admin@morymaker.co.kr"))
    }

    @Test
    fun `recordLoginFailure 는 존재하는 계정의 실패 횟수를 증가시켜 저장한다`() {
        val account = accountOf(failedAttempts = 2)
        every { accountPort.findByEmail("admin@morymaker.co.kr") } returns account
        val savedSlot = slot<Account>()
        every { accountPort.save(capture(savedSlot)) } returns Unit

        sut.recordLoginFailure("admin@morymaker.co.kr")

        assertEquals(3, savedSlot.captured.failedAttempts)
        assertNull(savedSlot.captured.lockedUntil, "임계(5) 미만이면 잠그지 않음")
    }

    @Test
    fun `recordLoginFailure 는 임계 도달 시 잠금 상태로 저장한다`() {
        val account = accountOf(failedAttempts = 4)
        every { accountPort.findByEmail("admin@morymaker.co.kr") } returns account
        val savedSlot = slot<Account>()
        every { accountPort.save(capture(savedSlot)) } returns Unit

        sut.recordLoginFailure("admin@morymaker.co.kr")

        assertEquals(5, savedSlot.captured.failedAttempts)
        assertEquals(fixedNow.plus(Duration.ofMinutes(15)), savedSlot.captured.lockedUntil)
    }

    @Test
    fun `recordLoginFailure 는 존재하지 않는 email 이면 아무 것도 하지 않는다 (사용자 열거 방지)`() {
        every { accountPort.findByEmail("unknown@morymaker.co.kr") } returns null

        sut.recordLoginFailure("unknown@morymaker.co.kr")

        verify(exactly = 0) { accountPort.save(any()) }
    }

    @Test
    fun `recordLoginSuccess 는 실패 횟수와 잠금 상태를 초기화해 저장한다`() {
        val account = accountOf(failedAttempts = 4)
        every { accountPort.findById("acc-1") } returns account
        val savedSlot = slot<Account>()
        every { accountPort.save(capture(savedSlot)) } returns Unit

        sut.recordLoginSuccess("acc-1")

        assertEquals(0, savedSlot.captured.failedAttempts)
        assertNull(savedSlot.captured.lockedUntil)
    }

    @Test
    fun `recordLoginSuccess 는 존재하지 않는 id 면 아무 것도 하지 않는다`() {
        every { accountPort.findById("missing") } returns null

        sut.recordLoginSuccess("missing")

        verify(exactly = 0) { accountPort.save(any()) }
    }
}

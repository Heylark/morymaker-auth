package kr.co.morymaker.auth.domain.account

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.time.Duration
import java.time.Instant

/**
 * [Account] 상태 계산·전이 단위 테스트 — 활성/잠금 판정과 잠금 정책(시간 경과 자동 해제 최소안) 전이 로직.
 */
class AccountTest {

    private fun accountOf(
        status: String = Account.STATUS_ACTIVE,
        failedAttempts: Int = 0,
        lockedAt: Instant? = null,
        lockedUntil: Instant? = null,
    ) = Account(
        id = "acc-1",
        email = "admin@morymaker.co.kr",
        name = "관리자",
        role = "SYSTEM_ADMIN",
        status = status,
        passwordHash = "{bcrypt-hash}",
        failedAttempts = failedAttempts,
        lockedAt = lockedAt,
        lockedUntil = lockedUntil,
        note = null,
        createdAt = Instant.parse("2026-01-01T00:00:00Z"),
    )

    @Test
    fun `isActive 는 status 활성일 때만 true`() {
        assertTrue(accountOf(status = Account.STATUS_ACTIVE).isActive)
        assertFalse(accountOf(status = Account.STATUS_INACTIVE).isActive)
    }

    @Test
    fun `isLocked 는 lockedUntil 이 미래일 때만 true`() {
        assertFalse(accountOf(lockedUntil = null).isLocked, "잠금 이력 없으면 false")
        assertTrue(accountOf(lockedUntil = Instant.now().plusSeconds(60)).isLocked, "미래 시각이면 잠금 중")
        assertFalse(accountOf(lockedUntil = Instant.now().minusSeconds(60)).isLocked, "과거 시각이면 자동 해제")
    }

    @Test
    fun `recordFailedAttempt 는 임계 미만이면 잠그지 않는다`() {
        val now = Instant.parse("2026-01-01T10:00:00Z")
        val result = accountOf(failedAttempts = 2).recordFailedAttempt(now, maxAttempts = 5, lockDuration = Duration.ofMinutes(15))

        assertEquals(3, result.failedAttempts)
        assertNull(result.lockedAt, "임계 미만이면 잠금 걸지 않음")
        assertNull(result.lockedUntil)
    }

    @Test
    fun `recordFailedAttempt 는 임계 도달 시 now 부터 lockDuration 만큼 잠근다`() {
        val now = Instant.parse("2026-01-01T10:00:00Z")
        val lockDuration = Duration.ofMinutes(15)
        val result = accountOf(failedAttempts = 4).recordFailedAttempt(now, maxAttempts = 5, lockDuration = lockDuration)

        assertEquals(5, result.failedAttempts)
        assertEquals(now, result.lockedAt)
        assertEquals(now.plus(lockDuration), result.lockedUntil)
    }

    @Test
    fun `recordFailedAttempt 는 이미 잠금 중이어도 잠금 기간을 연장한다`() {
        val originalLockedAt = Instant.parse("2026-01-01T09:00:00Z")
        val now = Instant.parse("2026-01-01T10:00:00Z")
        val lockDuration = Duration.ofMinutes(15)
        val account = accountOf(
            failedAttempts = 6,
            lockedAt = originalLockedAt,
            lockedUntil = originalLockedAt.plus(lockDuration),
        )

        val result = account.recordFailedAttempt(now, maxAttempts = 5, lockDuration = lockDuration)

        assertEquals(7, result.failedAttempts)
        assertEquals(now, result.lockedAt, "잠금 중 반복 실패는 잠금 시작 시각을 갱신")
        assertEquals(now.plus(lockDuration), result.lockedUntil, "잠금 기간을 연장")
    }

    @Test
    fun `recordSuccessfulLogin 은 실패 횟수와 잠금 상태를 모두 초기화한다`() {
        val account = accountOf(
            failedAttempts = 4,
            lockedAt = Instant.now().minusSeconds(3600),
            lockedUntil = Instant.now().minusSeconds(1800),
        )

        val result = account.recordSuccessfulLogin()

        assertEquals(0, result.failedAttempts)
        assertNull(result.lockedAt)
        assertNull(result.lockedUntil)
    }

    @Test
    fun `equals 는 id 만으로 동등성을 판정한다`() {
        val a = accountOf(failedAttempts = 0)
        val b = accountOf(failedAttempts = 3) // 다른 상태값, 같은 id("acc-1")

        assertEquals(a, b, "필드값이 달라도 id가 같으면 같은 계정")
    }

    @Test
    fun `toString 은 passwordHash 를 노출하지 않는다`() {
        val text = accountOf().toString()
        assertFalse(text.contains("bcrypt-hash"), "BCrypt 해시가 로그에 노출되면 안 됨(CWE-532)")
    }
}

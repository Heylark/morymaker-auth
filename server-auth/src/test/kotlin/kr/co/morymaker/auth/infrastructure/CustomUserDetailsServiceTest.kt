package kr.co.morymaker.auth.infrastructure

import io.mockk.every
import io.mockk.mockk
import kr.co.morymaker.auth.application.port.`in`.account.AccountUseCase
import kr.co.morymaker.auth.domain.account.Account
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.springframework.security.core.userdetails.UsernameNotFoundException
import java.time.Instant

/**
 * [CustomUserDetailsService] 단위 테스트 — stock SpringSecurityUser 보존 계약·잠금·비활성·
 * 사용자 열거 방지 엣지케이스.
 */
class CustomUserDetailsServiceTest {

    private val accountUseCase: AccountUseCase = mockk()
    private val authorityMapper = AccountAuthorityMapper()
    private val sut = CustomUserDetailsService(accountUseCase, authorityMapper)

    private fun accountOf(
        status: String = Account.STATUS_ACTIVE,
        passwordHash: String? = "{bcrypt-hash}",
        lockedUntil: Instant? = null,
        role: String = "EVENT_ADMIN",
    ) = Account(
        id = "acc-uuid-1",
        email = "admin@morymaker.co.kr",
        name = "관리자",
        role = role,
        status = status,
        passwordHash = passwordHash,
        failedAttempts = 0,
        lockedAt = null,
        lockedUntil = lockedUntil,
        note = null,
        createdAt = Instant.parse("2026-01-01T00:00:00Z"),
    )

    @Test
    fun `정상 계정은 UUID principal 과 ROLE_ 권한을 담은 UserDetails 를 반환한다`() {
        every { accountUseCase.findByEmail("admin@morymaker.co.kr") } returns accountOf()

        val result = sut.loadUserByUsername("admin@morymaker.co.kr")

        assertEquals("acc-uuid-1", result.username, "principal = account.id(UUID) — JWT sub 안정성")
        assertEquals("{bcrypt-hash}", result.password)
        assertTrue(result.isEnabled)
        assertTrue(result.isAccountNonLocked)
        assertEquals(listOf("ROLE_EVENT_ADMIN"), result.authorities.map { it.authority })
    }

    @Test
    fun `존재하지 않는 이메일은 UsernameNotFoundException (사용자 열거 방지 — 401 균일 처리)`() {
        every { accountUseCase.findByEmail("unknown@morymaker.co.kr") } returns null

        assertThrows<UsernameNotFoundException> {
            sut.loadUserByUsername("unknown@morymaker.co.kr")
        }
    }

    @Test
    fun `비활성 계정은 enabled=false 를 반환한다`() {
        every { accountUseCase.findByEmail("admin@morymaker.co.kr") } returns accountOf(status = Account.STATUS_INACTIVE)

        val result = sut.loadUserByUsername("admin@morymaker.co.kr")

        assertFalse(result.isEnabled)
    }

    @Test
    fun `잠긴 계정은 accountNonLocked=false 를 반환한다`() {
        every { accountUseCase.findByEmail("admin@morymaker.co.kr") } returns
            accountOf(lockedUntil = Instant.now().plusSeconds(600))

        val result = sut.loadUserByUsername("admin@morymaker.co.kr")

        assertFalse(result.isAccountNonLocked)
    }

    @Test
    fun `잠금 기간이 경과한 계정은 accountNonLocked=true (시간 기반 자동 해제)`() {
        every { accountUseCase.findByEmail("admin@morymaker.co.kr") } returns
            accountOf(lockedUntil = Instant.now().minusSeconds(600))

        val result = sut.loadUserByUsername("admin@morymaker.co.kr")

        assertTrue(result.isAccountNonLocked)
    }

    @Test
    fun `passwordHash 가 null 이면 빈 문자열로 대체돼 BCrypt 매칭이 되지 않는다`() {
        every { accountUseCase.findByEmail("admin@morymaker.co.kr") } returns accountOf(passwordHash = null)

        val result = sut.loadUserByUsername("admin@morymaker.co.kr")

        assertEquals("", result.password)
    }
}

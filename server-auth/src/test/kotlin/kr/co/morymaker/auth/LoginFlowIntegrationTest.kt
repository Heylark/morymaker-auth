package kr.co.morymaker.auth

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.DisabledException
import org.springframework.security.authentication.LockedException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.transaction.annotation.Transactional
import java.sql.Timestamp
import java.time.Instant
import java.util.UUID

/**
 * account 도메인 실 DB 통합 테스트 — Flyway V2 스키마 + MyBatis 매퍼 + BCrypt +
 * `DaoAuthenticationProvider` 표준 체크(잠금/비활성/자격증명) 전체 경로를 실제 MariaDB로 검증한다.
 *
 * mockk 단위 테스트([kr.co.morymaker.auth.infrastructure.CustomUserDetailsServiceTest])는 각 계층을
 * 개별 검증하지만, 실제 콜레이션(대소문자 무시) 동작과 `CustomUserDetailsService` bean이 Spring
 * Security 표준 `AuthenticationManager`에 자동 배선되는지는 실 컨텍스트로만 검증 가능하다.
 *
 * `@Transactional`: 각 테스트가 삽입한 계정 행은 테스트 종료 시 자동 롤백된다(Spring TestContext
 * 기본 동작) — 테스트 간 email UNIQUE 충돌·잔여 데이터를 걱정할 필요가 없다.
 *
 * 로컬 MariaDB(infra/docker-compose.yml) 기동이 선행돼야 한다(AuthApplicationTests와 동일 전제).
 */
@SpringBootTest
@Transactional
class LoginFlowIntegrationTest {

    /**
     * Spring Security는 `AuthenticationManager`를 기본 빈으로 노출하지 않는다 — [AuthenticationConfiguration]을
     * 통해 지연 생성된 매니저를 얻는다(공식 권장 패턴). 이 방식은 테스트 전용이며 프로덕션 SecurityConfig에
     * 새 빈을 추가하지 않는다.
     */
    @Autowired
    private lateinit var authenticationConfiguration: AuthenticationConfiguration

    @Autowired
    private lateinit var jdbcTemplate: JdbcTemplate

    @Autowired
    private lateinit var passwordEncoder: PasswordEncoder

    private val authenticationManager: AuthenticationManager
        get() = authenticationConfiguration.authenticationManager

    private fun seedAccount(
        email: String,
        rawPassword: String = "correct-horse-battery-staple",
        role: String = "EVENT_ADMIN",
        status: String = "활성",
        failedAttempts: Int = 0,
        lockedUntil: Instant? = null,
    ): String {
        val id = UUID.randomUUID().toString()
        jdbcTemplate.update(
            """
            INSERT INTO account
                (id, email, name, role, password_hash, failed_attempts, locked_at, locked_until, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """.trimIndent(),
            id,
            email,
            "테스트 계정",
            role,
            passwordEncoder.encode(rawPassword),
            failedAttempts,
            if (lockedUntil != null) Timestamp.from(Instant.now()) else null,
            if (lockedUntil != null) Timestamp.from(lockedUntil) else null,
            status,
            Timestamp.from(Instant.now()),
        )
        return id
    }

    @Test
    fun `올바른 비밀번호로 인증 성공 시 principal name 이 account id(UUID)`() {
        val id = seedAccount(email = "success@morymaker.co.kr")

        val result = authenticationManager.authenticate(
            UsernamePasswordAuthenticationToken("success@morymaker.co.kr", "correct-horse-battery-staple"),
        )

        assertEquals(id, result.name, "principal = account.id(UUID) — JWT sub 안정성(stock principal 계약)")
    }

    @Test
    fun `대소문자를 다르게 입력해도 로그인된다 (콜레이션 대소문자 무시 — 엣지케이스 8)`() {
        seedAccount(email = "MixedCase@Morymaker.co.kr")

        val result = authenticationManager.authenticate(
            UsernamePasswordAuthenticationToken("mixedcase@morymaker.co.kr", "correct-horse-battery-staple"),
        )

        assertEquals(true, result.isAuthenticated)
    }

    @Test
    fun `비밀번호가 틀리면 BadCredentialsException`() {
        seedAccount(email = "wrongpw@morymaker.co.kr")

        assertThrows<BadCredentialsException> {
            authenticationManager.authenticate(
                UsernamePasswordAuthenticationToken("wrongpw@morymaker.co.kr", "not-the-right-password"),
            )
        }
    }

    @Test
    fun `존재하지 않는 이메일도 BadCredentialsException (사용자 열거 방지)`() {
        assertThrows<BadCredentialsException> {
            authenticationManager.authenticate(
                UsernamePasswordAuthenticationToken("no-such-account@morymaker.co.kr", "whatever"),
            )
        }
    }

    @Test
    fun `잠긴 계정은 LockedException`() {
        seedAccount(email = "locked@morymaker.co.kr", lockedUntil = Instant.now().plusSeconds(600))

        assertThrows<LockedException> {
            authenticationManager.authenticate(
                UsernamePasswordAuthenticationToken("locked@morymaker.co.kr", "correct-horse-battery-staple"),
            )
        }
    }

    @Test
    fun `비활성 계정은 DisabledException`() {
        seedAccount(email = "inactive@morymaker.co.kr", status = "비활성")

        assertThrows<DisabledException> {
            authenticationManager.authenticate(
                UsernamePasswordAuthenticationToken("inactive@morymaker.co.kr", "correct-horse-battery-staple"),
            )
        }
    }

    @Test
    fun `잠금 기간이 경과한 계정은 다시 로그인 가능 (시간 기반 자동 해제)`() {
        seedAccount(email = "unlocked@morymaker.co.kr", lockedUntil = Instant.now().minusSeconds(600))

        val result = authenticationManager.authenticate(
            UsernamePasswordAuthenticationToken("unlocked@morymaker.co.kr", "correct-horse-battery-staple"),
        )

        assertEquals(true, result.isAuthenticated)
    }
}

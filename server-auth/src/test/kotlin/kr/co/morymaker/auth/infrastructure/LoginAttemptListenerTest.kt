package kr.co.morymaker.auth.infrastructure

import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kr.co.morymaker.auth.application.port.`in`.account.AccountUseCase
import org.junit.jupiter.api.Test
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent

/**
 * [LoginAttemptListener] 단위 테스트 — 인증 이벤트 → 잠금 정책 기록 위임 확인.
 *
 * 실제 `DaoAuthenticationProvider`/`ProviderManager`가 이벤트를 발행하는 경로 자체는 Spring
 * Security 표준 동작(yulse `AuditEventListener`가 동일 이벤트 타입에 의존하는 선례)이라
 * 이 테스트의 범위가 아니다 — 이벤트가 주어졌을 때 이 리스너가 올바른 식별자로 올바른
 * port-in 메서드를 호출하는지만 검증한다.
 */
class LoginAttemptListenerTest {

    private val accountUseCase: AccountUseCase = mockk(relaxed = true)
    private val sut = LoginAttemptListener(accountUseCase)

    @Test
    fun `onLoginSuccess 는 principal name(account id)으로 recordLoginSuccess 를 호출한다`() {
        val authentication = UsernamePasswordAuthenticationToken.authenticated("acc-uuid-1", null, emptyList())
        val event = InteractiveAuthenticationSuccessEvent(authentication, this::class.java)

        sut.onLoginSuccess(event)

        verify(exactly = 1) { accountUseCase.recordLoginSuccess("acc-uuid-1") }
    }

    @Test
    fun `onLoginFailure 는 제출된 identifier(email)로 recordLoginFailure 를 호출한다`() {
        val authentication = UsernamePasswordAuthenticationToken("admin@morymaker.co.kr", "wrong-password")
        val event = AuthenticationFailureBadCredentialsEvent(authentication, BadCredentialsException("bad credentials"))

        sut.onLoginFailure(event)

        verify(exactly = 1) { accountUseCase.recordLoginFailure("admin@morymaker.co.kr") }
    }
}

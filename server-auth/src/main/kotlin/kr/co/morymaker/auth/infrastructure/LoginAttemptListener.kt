package kr.co.morymaker.auth.infrastructure

import kr.co.morymaker.auth.application.port.`in`.account.AccountUseCase
import org.slf4j.LoggerFactory
import org.springframework.context.event.EventListener
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent
import org.springframework.stereotype.Component

/**
 * 폼 로그인 실패/성공 이벤트에 반응해 계정 잠금 정책(시간 경과 자동 해제 최소안)을 기록하는 리스너.
 *
 * 설계 클래스 목록에는 명시되지 않은 신규 컴포넌트다 — 설계가 정의한 AccountPort는 읽기
 * 전용(findByEmail/findById/findRoleById)이지만, 같은 설계가 승인한 잠금 정책은 실패 횟수·잠금
 * 시각의 durable 저장 없이는 성립하지 않는다. RBAC·EventScope·SecurityConfig 등 기존 설계 결정을
 * 건드리지 않는 좁은 추가라 재설계 없이 구현했다.
 *
 * ## WHY — CustomUserDetailsService가 아니라 별도 이벤트 리스너로 구현
 * `loadUserByUsername`은 비밀번호 검증 **이전**(`DaoAuthenticationProvider.retrieveUser`) 단계에
 * 호출되므로, 그 시점에는 이번 시도가 성공할지 실패할지 알 수 없다. 매 호출마다 실패로 집계하면
 * 정상 로그인 시도까지 잠기게 된다 — 반드시 인증 **결과** 이벤트에 반응해야 한다.
 *
 * ## 실패 이벤트를 [AuthenticationFailureBadCredentialsEvent]로 한정하는 이유
 * `DaoAuthenticationProvider`는 이미 잠긴/비활성 계정을 비밀번호 검증 **이전**(preAuthenticationChecks)에
 * 걸러 `LockedException`/`DisabledException`을 던진다 — 이 경로는 이 리스너가 구독하는
 * `AuthenticationFailureBadCredentialsEvent`와 다른 이벤트 타입이다. 따라서 "이미 잠긴 계정에 대한
 * 반복 시도"는 매번 잠금 기간을 연장시키지 않는다 — 잠금 중에는 비밀번호 정오 자체가 확인되지
 * 않기 때문이다. 오직 "비밀번호가 실제로 틀렸을 때"만 실패로 집계한다.
 *
 * ## 계정 미존재(사용자 열거 방지)
 * `hideUserNotFoundExceptions`(Spring Security 기본값 true) 정책상 존재하지 않는 email도 동일하게
 * `AuthenticationFailureBadCredentialsEvent`를 발행한다. [AccountUseCase.recordLoginFailure]는
 * 존재하지 않는 email이면 조용히 아무 것도 하지 않으므로, 이 리스너는 계정 존재 여부에 따라
 * 동작을 분기하지 않는다(타이밍·부작용으로 계정 존재를 노출하지 않기 위함).
 *
 * ## 로그 주의 (CWE-532)
 * 이메일·principal 값을 로그에 출력하지 않는다. 이벤트 종류만 debug 로깅한다.
 *
 * @param accountUseCase 계정 조회 + 로그인 결과 기록 port-in
 */
@Component
class LoginAttemptListener(
    private val accountUseCase: AccountUseCase,
) {

    private val log = LoggerFactory.getLogger(LoginAttemptListener::class.java)

    /** 폼 로그인 성공 — 실패 횟수·잠금 상태 초기화. `principal.name` = account.id(UUID). */
    @EventListener
    fun onLoginSuccess(event: InteractiveAuthenticationSuccessEvent) {
        val accountId = event.authentication.name
        accountUseCase.recordLoginSuccess(accountId)
        log.debug("로그인 성공 — 잠금 상태 초기화 완료")
    }

    /**
     * 폼 로그인 실패(비밀번호 불일치 — 계정 미존재 포함, hideUserNotFoundExceptions 기본값).
     * `event.authentication.name` = 사용자가 로그인 폼에 제출한 원본 식별자(email) — 인증이
     * 아직 실패했으므로 UUID(principal)로 치환되지 않은 원본 입력값이다.
     */
    @EventListener
    fun onLoginFailure(event: AuthenticationFailureBadCredentialsEvent) {
        val identifier = event.authentication.name
        accountUseCase.recordLoginFailure(identifier)
        log.debug("로그인 실패 — 실패 횟수 반영 완료")
    }
}

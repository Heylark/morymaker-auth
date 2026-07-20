package kr.co.morymaker.auth.application.service.account

import kr.co.morymaker.auth.application.port.`in`.account.AccountUseCase
import kr.co.morymaker.auth.application.port.out.account.AccountPort
import kr.co.morymaker.auth.domain.account.Account
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.Clock
import java.time.Duration
import java.time.Instant

/**
 * [AccountUseCase] 구현체 (internal — server-auth는 인터페이스만 의존).
 *
 * ## 잠금 정책 설정값을 `@Value`로 직접 주입하는 이유(레이어 방향)
 * 잠금 임계·기간을 server-auth의 `AuthProperties`(설정 바인딩 클래스)로 묶지 않고 `@Value`로
 * 개별 주입한다 — module-application은 server-auth를 의존할 수 없다(domain←application←
 * persistence←server-auth 단방향 레이어 규칙). `@Value`는 프로퍼티 키(`morymaker.auth.lock-policy.*`)만
 * 참조하므로 실제 값이 어느 모듈의 리소스(application.yml)에 있든 레이어 위반 없이 동작한다.
 *
 * @param accountPort 영속화 port-out
 * @param maxFailedAttempts 잠금 임계 연속 실패 횟수 (설정값 — 하드코딩 금지)
 * @param lockDuration 잠금 지속 기간 (설정값 — 하드코딩 금지)
 * @param clock 시각 공급(테스트 결정성 확보 — 프로덕션 기본 [Clock.systemUTC])
 */
@Service
@Transactional(rollbackFor = [Exception::class])
internal class AccountService(
    private val accountPort: AccountPort,
    @Value("\${morymaker.auth.lock-policy.max-failed-attempts}") private val maxFailedAttempts: Int,
    @Value("\${morymaker.auth.lock-policy.lock-duration}") private val lockDuration: Duration,
    private val clock: Clock = Clock.systemUTC(),
) : AccountUseCase {

    @Transactional(readOnly = true)
    override fun findByEmail(email: String): Account? = accountPort.findByEmail(email)

    @Transactional(readOnly = true)
    override fun findById(id: String): Account? = accountPort.findById(id)

    /** 존재하지 않는 email은 조용히 무시한다 — 사용자 열거 방지(계정 존재 여부를 노출하지 않음). */
    override fun recordLoginFailure(email: String) {
        val account = accountPort.findByEmail(email) ?: return
        accountPort.save(account.recordFailedAttempt(Instant.now(clock), maxFailedAttempts, lockDuration))
    }

    override fun recordLoginSuccess(accountId: String) {
        val account = accountPort.findById(accountId) ?: return
        accountPort.save(account.recordSuccessfulLogin())
    }
}

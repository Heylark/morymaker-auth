package kr.co.morymaker.auth.application.service.account

import kr.co.morymaker.auth.application.port.`in`.account.AccountAdminUseCase
import kr.co.morymaker.auth.application.port.out.account.AccountPort
import kr.co.morymaker.auth.application.port.out.account.AccountSearch
import kr.co.morymaker.auth.application.port.out.event.AccountEventPort
import kr.co.morymaker.auth.application.port.out.security.PasswordEncoderPort
import kr.co.morymaker.auth.application.service.dto.AccountAdminResult
import kr.co.morymaker.auth.application.service.dto.AccountCreateCommand
import kr.co.morymaker.auth.application.service.dto.AccountUpdateCommand
import kr.co.morymaker.auth.domain.account.Account
import kr.co.morymaker.auth.domain.account.MoryRoles
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.Clock
import java.time.Instant
import java.util.UUID

/**
 * [AccountAdminUseCase] 구현체(internal — server-auth는 인터페이스만 의존).
 *
 * 클래스 레벨 `@Transactional`로 delete-insert(account_event 재작성, [AccountEventPort.replaceEventIds])
 * 원자성을 보장한다 — 단일 메서드 안에서 account 쓰기와 account_event 재작성이 함께 커밋/롤백된다.
 *
 * @param clock 시각 공급(테스트 결정성 확보 — 프로덕션 기본 [Clock.systemUTC], [AccountService] 패턴 재사용)
 */
@Service
@Transactional(rollbackFor = [Exception::class])
internal class AccountAdminService(
    private val accountPort: AccountPort,
    private val accountEventPort: AccountEventPort,
    private val passwordEncoderPort: PasswordEncoderPort,
    private val clock: Clock = Clock.systemUTC(),
) : AccountAdminUseCase {

    @Transactional(readOnly = true)
    override fun list(search: AccountSearch): AccountAdminResult.Page {
        val accounts = accountPort.search(search)
        val total = accountPort.count(search.copy(paging = false))
        val eventIdsByAccount = accountEventPort.findEventIdsByAccountIds(accounts.map { it.id })
        val items = accounts.map { account ->
            AccountAdminResult(account, eventIdsByAccount[account.id] ?: emptyList())
        }
        return AccountAdminResult.Page(items = items, total = total, page = search.page, size = search.size)
    }

    override fun create(command: AccountCreateCommand): AccountAdminResult {
        validateRoleAndEvents(command.role, command.eventIds)
        if (accountPort.findByEmail(command.email) != null) {
            throw EmailDuplicateException(command.email)
        }

        val account = Account(
            id = UUID.randomUUID().toString(),
            email = command.email,
            name = command.name,
            role = command.role,
            status = Account.STATUS_ACTIVE,
            passwordHash = passwordEncoderPort.encode(command.password),
            failedAttempts = 0,
            lockedAt = null,
            lockedUntil = null,
            note = command.note,
            createdAt = Instant.now(clock),
        )
        // 동시성 최종 방어(pre-check race 보완) — email UNIQUE 위반 시 durable 저장소가 던지는
        // DuplicateKeyException을 여기서 감싸지 않고 그대로 전파한다. server-auth
        // GlobalExceptionHandler가 EmailDuplicateException과 함께 같은 409 EMAIL_DUPLICATE로 매핑한다.
        accountPort.insert(account)

        val effectiveEventIds = effectiveEventIds(command.role, command.eventIds)
        accountEventPort.replaceEventIds(account.id, effectiveEventIds)
        return AccountAdminResult(account, effectiveEventIds)
    }

    override fun update(id: String, command: AccountUpdateCommand): AccountAdminResult {
        accountPort.findById(id) ?: throw AccountNotFoundException(id)
        validateRoleAndEvents(command.role, command.eventIds)

        accountPort.updateProfile(id = id, name = command.name, role = command.role, note = command.note)
        val effectiveEventIds = effectiveEventIds(command.role, command.eventIds)
        accountEventPort.replaceEventIds(id, effectiveEventIds)

        val updated = accountPort.findById(id) ?: throw AccountNotFoundException(id)
        return AccountAdminResult(updated, effectiveEventIds)
    }

    override fun toggleStatus(id: String, status: String): AccountAdminResult {
        accountPort.findById(id) ?: throw AccountNotFoundException(id)
        require(status == Account.STATUS_ACTIVE || status == Account.STATUS_INACTIVE) {
            "status는 활성 또는 비활성이어야 합니다: $status"
        }

        accountPort.updateStatus(id, status)

        val updated = accountPort.findById(id) ?: throw AccountNotFoundException(id)
        return AccountAdminResult(updated, accountEventPort.findEventIds(id))
    }

    /** role∈3역할 검증(else VALIDATION_FAILED) + EVENT_ADMIN/EVENT_STAFF는 eventIds 최소 1개 필수(422). */
    private fun validateRoleAndEvents(role: String, eventIds: List<String>) {
        require(role in VALID_ROLES) {
            "role은 ${VALID_ROLES.joinToString("/")} 중 하나여야 합니다: $role"
        }
        if (role != MoryRoles.SYSTEM_ADMIN && eventIds.isEmpty()) {
            throw EventAssignmentRequiredException(role)
        }
    }

    /** SYSTEM_ADMIN은 행사할당이 무의미(row 0건) — 그 외 역할은 요청받은 eventIds 그대로 재작성한다. */
    private fun effectiveEventIds(role: String, eventIds: List<String>): List<String> =
        if (role == MoryRoles.SYSTEM_ADMIN) emptyList() else eventIds

    companion object {
        private val VALID_ROLES = setOf(MoryRoles.SYSTEM_ADMIN, MoryRoles.EVENT_ADMIN, MoryRoles.EVENT_STAFF)
    }
}

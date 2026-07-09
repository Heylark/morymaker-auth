package kr.co.morymaker.auth.dto

import kr.co.morymaker.auth.application.service.dto.AccountAdminResult

/**
 * 계정 어드민 응답(§3 공통) — [kr.co.morymaker.auth.domain.account.Account.passwordHash]는 절대
 * 포함하지 않는다.
 */
data class AccountAdminResponse(
    val id: String,
    val email: String,
    val name: String?,
    val role: String,
    val status: String,
    val eventIds: List<String>,
    val note: String?,
)

fun AccountAdminResult.toResponse(): AccountAdminResponse = AccountAdminResponse(
    id = account.id,
    email = account.email,
    name = account.name,
    role = account.role,
    status = account.status,
    eventIds = eventIds,
    note = account.note,
)

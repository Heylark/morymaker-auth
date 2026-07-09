package kr.co.morymaker.auth.web

import jakarta.validation.Valid
import kr.co.morymaker.auth.application.port.`in`.account.AccountAdminUseCase
import kr.co.morymaker.auth.application.port.out.account.AccountSearch
import kr.co.morymaker.auth.application.service.dto.AccountCreateCommand
import kr.co.morymaker.auth.application.service.dto.AccountUpdateCommand
import kr.co.morymaker.auth.dto.AccountAdminResponse
import kr.co.morymaker.auth.dto.AccountCreateRequest
import kr.co.morymaker.auth.dto.AccountStatusRequest
import kr.co.morymaker.auth.dto.AccountUpdateRequest
import kr.co.morymaker.auth.dto.ApiResponse
import kr.co.morymaker.auth.dto.Meta
import kr.co.morymaker.auth.dto.toResponse
import org.springframework.http.HttpStatus
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.PutMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController

/**
 * 계정 어드민 CRUD API(§3) — auth 최초의 `@RestController`. 인가는 이 클래스가 아니라
 * [kr.co.morymaker.auth.config.AdminApiSecurityConfig]의 요청 레벨 `hasRole(SYSTEM_ADMIN)` 게이트가
 * 담당한다(E3 — 4개 엔드포인트가 균일 SYSTEM_ADMIN이라 메서드 시큐리티 2중 강제는 배제).
 */
@RestController
@RequestMapping("/api/accounts")
class AccountAdminController(
    private val accountAdminUseCase: AccountAdminUseCase,
) {

    @GetMapping(value = ["", "/"])
    fun list(
        @RequestParam(required = false) role: String?,
        @RequestParam(required = false) status: String?,
        @RequestParam(required = false) q: String?,
        @RequestParam(defaultValue = "1") page: Int,
        @RequestParam(defaultValue = "50") size: Int,
    ): ApiResponse<List<AccountAdminResponse>> {
        val result = accountAdminUseCase.list(
            AccountSearch(role = role, status = status, q = q, page = page, size = size),
        )
        return ApiResponse(
            data = result.items.map { it.toResponse() },
            meta = Meta(total = result.total, page = result.page, size = result.size),
        )
    }

    @PostMapping(value = ["", "/"])
    @ResponseStatus(HttpStatus.CREATED)
    fun create(@Valid @RequestBody request: AccountCreateRequest): ApiResponse<AccountAdminResponse> {
        val command = AccountCreateCommand(
            email = request.email,
            name = request.name,
            role = request.role,
            eventIds = request.eventIds,
            note = request.note,
            password = request.password,
        )
        return ApiResponse(accountAdminUseCase.create(command).toResponse())
    }

    @PutMapping("/{id}")
    fun update(
        @PathVariable id: String,
        @Valid @RequestBody request: AccountUpdateRequest,
    ): ApiResponse<AccountAdminResponse> {
        val command = AccountUpdateCommand(
            name = request.name,
            role = request.role,
            eventIds = request.eventIds,
            note = request.note,
        )
        return ApiResponse(accountAdminUseCase.update(id, command).toResponse())
    }

    @PutMapping("/{id}/status")
    fun toggleStatus(
        @PathVariable id: String,
        @Valid @RequestBody request: AccountStatusRequest,
    ): ApiResponse<AccountAdminResponse> =
        ApiResponse(accountAdminUseCase.toggleStatus(id, request.status).toResponse())
}

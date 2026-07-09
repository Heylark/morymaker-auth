package kr.co.morymaker.auth.dto

import jakarta.validation.constraints.Email
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Size

/**
 * 계정 생성 요청(§3-2) — [password]는 E2(관리자 지정 + 서버 강도검증) 결정에 따른 필드다. 서버가
 * 값을 자동 생성하지 않으므로 관리자가 지정한 값을 그대로 받는다(로그·응답 어디에도 남기지 않는다).
 *
 * [role] 값 자체(3역할 중 하나인지)와 역할별 [eventIds] 최소 1개 필수 규칙은 서비스가 검증한다
 * (요청 DTO는 형식 검증만 — 비어있지 않은지).
 */
data class AccountCreateRequest(
    @field:NotBlank @field:Email val email: String,
    val name: String? = null,
    @field:NotBlank val role: String,
    val eventIds: List<String> = emptyList(),
    val note: String? = null,
    @field:NotBlank
    @field:Size(min = 8, message = "비밀번호는 8자 이상이어야 합니다")
    val password: String,
)

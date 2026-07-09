package kr.co.morymaker.auth.dto

import jakarta.validation.constraints.NotBlank

/** 계정 수정 요청(§3-3) — email·password 불변이라 포함하지 않는다(이메일 변경·비밀번호 재설정은 범위 밖). */
data class AccountUpdateRequest(
    val name: String? = null,
    @field:NotBlank val role: String,
    val eventIds: List<String> = emptyList(),
    val note: String? = null,
)

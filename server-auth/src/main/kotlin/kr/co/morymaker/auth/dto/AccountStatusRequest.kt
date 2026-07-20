package kr.co.morymaker.auth.dto

import jakarta.validation.constraints.NotBlank

/** 상태 토글 요청(§3-4) — "활성"/"비활성"([kr.co.morymaker.auth.domain.account.Account] STATUS_* 참조). */
data class AccountStatusRequest(
    @field:NotBlank val status: String,
)

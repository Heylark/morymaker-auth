package kr.co.morymaker.auth.dto

/** [field]는 필드 형식 오류(400 VALIDATION_FAILED)에서만 채워진다 — 그 외 에러코드는 null. */
data class ErrorDetail(
    val code: String,
    val message: String,
    val field: String? = null,
)

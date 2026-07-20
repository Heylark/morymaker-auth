package kr.co.morymaker.auth.dto

/** §0-5 실패 응답 envelope — [GlobalExceptionHandler][kr.co.morymaker.auth.web.GlobalExceptionHandler]와
 * [AdminApiSecurityConfig][kr.co.morymaker.auth.config.AdminApiSecurityConfig] 401/403 핸들러가 공용한다. */
data class ErrorBody(val error: ErrorDetail)

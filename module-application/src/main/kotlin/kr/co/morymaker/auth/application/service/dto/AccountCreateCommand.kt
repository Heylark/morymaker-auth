package kr.co.morymaker.auth.application.service.dto

/**
 * 계정 생성 커맨드(§3-2, port-in 입력 — HTTP Request 미유입, ACL).
 *
 * [password]는 관리자 지정 + 서버 강도검증 방식에 따른 필드다 — 서버가 값을 자동 생성하지
 * 않으므로 이 커맨드가 평문을 그대로 받아 서비스가 인코딩한다(로그·응답에는 절대 남기지 않음).
 */
data class AccountCreateCommand(
    val email: String,
    val name: String?,
    val role: String,
    val eventIds: List<String>,
    val note: String?,
    val password: String,
)

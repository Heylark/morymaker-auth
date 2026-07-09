package kr.co.morymaker.auth.application.service.dto

/** 계정 수정 커맨드(§3-3, port-in 입력) — email·password 불변이라 포함하지 않는다. */
data class AccountUpdateCommand(
    val name: String?,
    val role: String,
    val eventIds: List<String>,
    val note: String?,
)

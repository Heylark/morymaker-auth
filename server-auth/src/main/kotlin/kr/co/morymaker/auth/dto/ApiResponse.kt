package kr.co.morymaker.auth.dto

import com.fasterxml.jackson.annotation.JsonInclude

/**
 * §0-4 성공 응답 envelope — api Event/Guest 어드민 패턴의 auth 자체 사본(별도 repo라 공유 불가,
 * byte 동형 유지).
 *
 * [meta]는 목록형 응답에만 존재한다 — 단건 응답은 `null`이라 직렬화에서 생략된다.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
data class ApiResponse<T>(
    val data: T,
    val meta: Meta? = null,
)

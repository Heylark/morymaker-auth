package kr.co.morymaker.auth.dto

import com.fasterxml.jackson.annotation.JsonInclude

/** 목록 응답 페이징 메타(§3-1) — 단건 응답에서는 사용하지 않는다. */
@JsonInclude(JsonInclude.Include.NON_NULL)
data class Meta(
    val total: Int? = null,
    val page: Int? = null,
    val size: Int? = null,
)

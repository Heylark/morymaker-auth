package kr.co.morymaker.auth.application.port.out.account

/**
 * 계정 목록 조회 검색 조건(port-out) — 3-1 `GET /api/accounts` 필터(role/status/q) + 페이징.
 *
 * account는 단일 테이블 조회라 mybatis.md의 searchPaging 서브쿼리 패턴(cartesian product 방지용
 * id 선추출)은 불필요하다 — LIMIT/OFFSET을 search 쿼리에 직접 적용한다. [count] 호출 시에는
 * `paging=false`로 복사해서 넘겨야 한다 — paging=true인 채로 호출하면 COUNT가 LIMIT 이후 건수만
 * 세는 버그가 생긴다(mybatis.md "searchTotalCnt 호출 시 반드시 paging=false" 경고 정합).
 */
data class AccountSearch(
    val role: String? = null,
    val status: String? = null,
    val q: String? = null,
    val page: Int = 1,
    val size: Int = 50,
    val paging: Boolean = true,
) {
    val offset: Int get() = (page - 1) * size
}

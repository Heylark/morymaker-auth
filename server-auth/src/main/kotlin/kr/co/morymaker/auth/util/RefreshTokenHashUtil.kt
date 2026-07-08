package kr.co.morymaker.auth.util

import kr.co.morymaker.auth.domain.common.Sha256HashUtil

/**
 * Refresh token at-rest SHA-256 해시 유틸 (단일 진실 소스).
 *
 * ## WHY — 왜 refresh token을 저장 시점에 해시하는가
 * refresh token은 access token 재발급 권한을 가진 **장기 자격증명**이다. 평문으로 DB에 저장하면
 * DB 덤프(SQL injection·백업 유출·내부자 접근)만으로 모든 사용자의 토큰을 탈취당한다.
 * 비밀번호처럼 **단방향 해시**로 저장하면 — 저장값(해시)으로는 원본 토큰을 복원할 수 없으므로 —
 * DB가 유출돼도 토큰 평문은 노출되지 않는다.
 *
 * ## WHY — salt가 없는 이유
 * 비밀번호는 사람이 고른 저엔트로피 값이라 rainbow table 공격에 salt가 필요하다.
 * 그러나 refresh token은 SAS가 생성하는 **고엔트로피 랜덤 값**(추측 불가)이라 사전 공격 대상이 아니다.
 * → salt 불필요. 단순 SHA-256으로 충분하며, 조회 시 입력 토큰을 같은 함수로 해시해 컬럼과 비교할 수 있다
 *   (salt가 있으면 컬럼별 salt 보관·조회가 필요해져 lookup이 깨진다).
 *
 * ## 인코딩 계약
 * - lowercase hex 64자 (= SHA-256 32 bytes × 2). UTF-8 bytes 입력.
 * - MariaDB `SHA2(token, 256)` 결과와 byte-identical.
 *
 * ## 위임 구조
 * `hash()`의 실제 구현은 [Sha256HashUtil]에 위치한다(범용 해시 로직 단일 소스, domain 레이어).
 * `isHashed()`는 refresh token 멱등 가드 전용으로 이곳에 잔류한다
 * (generic util에 refresh 개념이 누출되는 것을 방지하기 위해 domain 레이어로 추출하지 않고 여기 유지).
 */
object RefreshTokenHashUtil {

    /**
     * 이미 SHA-256 hex 형태(소문자 0-9a-f 정확히 64자)인지 판별하는 정규식.
     *
     * ## WHY — 멱등 가드에 쓰는 패턴
     * SAS가 발급하는 raw refresh token은 ~128자 Base64URL(대소문자·`-`·`_` 혼합)이라
     * 이 패턴(소문자 hex 64자)과 절대 매칭되지 않는다. 따라서 "입력이 이 패턴에 매칭됨" ==
     * "DB에서 복원된 우리 해시값" 으로 안전하게 구별할 수 있다.
     *
     * 이 가정이 깨지면(예: 미래에 tokenGenerator가 hex 토큰을 발급하도록 바뀌면) 가드가 raw 토큰을
     * "이미 해시됨"으로 오판하여 **평문 저장**하는 보안 회귀가 발생한다. → 단위 테스트로 이 음성 케이스를 못박는다.
     *
     * ⚠️ refresh token 멱등 가드 전용 — domain Sha256HashUtil에는 두지 않는다.
     */
    private val HEX_64 = Regex("^[0-9a-f]{64}$")

    /**
     * raw 토큰을 SHA-256 lowercase hex 64자로 해시한다.
     *
     * 실제 구현은 [Sha256HashUtil.hash]에 위임한다 (hash 로직 단일 소스).
     *
     * @param rawToken 평문 refresh token 값 (SAS 발급 Base64URL)
     * @return lowercase hex 64자 (예: `"3a7b...c9"`). 같은 입력 → 항상 같은 출력(결정적).
     */
    fun hash(rawToken: String): String = Sha256HashUtil.hash(rawToken)

    /**
     * 주어진 값이 이미 우리 해시 형식(SHA-256 lowercase hex 64자)인지 판별한다 — 멱등 가드.
     *
     * ## WHY — 이중 해시(hash(hash)) 차단
     * SAS `save()`는 항상 raw 토큰을 받는 게 아니다. refresh grant(reuseRefreshTokens=true)·revoke 경로는
     * **DB에서 복원된 해시값**을 그대로 담아 다시 `save()`를 호출한다.
     * 이때 무조건 다시 해시하면 `hash(hash(raw))`가 저장돼 컬럼이 깨지고, 토큰이 1회 사용 후 조회 불가가 된다.
     * → 입력이 이미 해시면 재해시를 건너뛴다.
     *
     * ⚠️ refresh token 멱등 가드 전용 — domain Sha256HashUtil에는 두지 않는다.
     *
     * @return true면 재해시하지 않고 그대로 위임해야 함 (이미 저장 형식)
     */
    fun isHashed(value: String): Boolean = HEX_64.matches(value)
}

package kr.co.morymaker.auth.domain.common

import java.security.MessageDigest

/**
 * 범용 SHA-256 lowercase hex 해시 유틸.
 *
 * ## 위치 근거
 * module-application·server-auth 양쪽에서 SHA-256 해시가 필요할 수 있다. 서비스 레이어는 server-auth에
 * 의존할 수 없으므로(레이어는 domain ← application ← persistence ← server-auth 단방향 의존만 허용),
 * 공통 함수를 domain 레이어에 둔다.
 *
 * ## 책임 범위 (단일 책임)
 * - 이 파일: `hash(rawValue)` 하나만. 범용 SHA-256 hex 변환.
 * - refresh token 멱등 가드(`isHashed()`)는 refresh 전용 컨텍스트라 server-auth의 `RefreshTokenHashUtil`에 둔다
 *   (refresh 토큰 재해시 판별 전용 로직이라 범용 유틸에 섞이면 책임이 흐려짐).
 *
 * ## 인코딩 계약
 * lowercase hex 64자 (SHA-256 32 bytes × 2). UTF-8 bytes 입력.
 * MariaDB `SHA2(value, 256)` 결과와 byte-identical.
 *
 * ## thread-safety
 * `MessageDigest`는 thread-unsafe이므로 매 호출마다 새 인스턴스를 생성한다.
 * 공유 인스턴스를 캐시하지 않는다 (동시 호출 시 digest 오염 방지).
 *
 * ## salt-free 전제
 * 고엔트로피 랜덤값(예: SecureRandom ≥256bit)만 hash() 입력으로 허용한다.
 * 저엔트로피 값(OTP, PIN, 사람이 고른 비밀번호 등)에 salt-free SHA-256을 적용하면
 * rainbow table 공격에 취약하다. 그 경우는 BCrypt/Argon2를 사용할 것.
 */
object Sha256HashUtil {

    /**
     * 고엔트로피 rawValue를 SHA-256 lowercase hex 64자로 해시한다.
     *
     * ⚠️ 저엔트로피 입력(OTP·PIN·비밀번호) 사용 금지 — salt 없는 SHA-256은 rainbow table 공격 위험.
     * 이 함수는 SecureRandom ≥256bit 생성 토큰 전용이다.
     *
     * @param rawValue 고엔트로피 평문값 (예: SAS refresh token)
     * @return lowercase hex 64자 (결정적: 같은 입력 → 항상 같은 출력)
     */
    fun hash(rawValue: String): String {
        val bytes = MessageDigest.getInstance("SHA-256")
            .digest(rawValue.toByteArray(Charsets.UTF_8))
        // 각 byte를 2자리 소문자 hex로 — 음수 byte도 %02x가 0xFF 마스킹 처리
        return bytes.joinToString("") { "%02x".format(it) }
    }
}

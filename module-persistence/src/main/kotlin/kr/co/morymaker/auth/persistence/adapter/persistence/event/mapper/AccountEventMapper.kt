package kr.co.morymaker.auth.persistence.adapter.persistence.event.mapper

import org.apache.ibatis.annotations.Mapper
import org.apache.ibatis.annotations.Param

/**
 * account_event 테이블 MyBatis 매퍼 — 계정-행사 담당 M:N 조회+쓰기(토큰 발급 시점 event 스코프 조회 +
 * 어드민 delete-insert 재작성).
 *
 * 헥사고날 레이어: persistence(mapper) — DB 관심사만 담당. XML 정의: resources/mapper/event/AccountEventMapper.xml.
 *
 * 순수 매핑 테이블(비즈니스 속성 없음). 등록·해제 쓰기는 이 REQ(관리자 콘솔 API)에서 신설한다 —
 * [findEventIds]는 기존 mint-time 조회([kr.co.morymaker.auth.persistence.adapter.persistence.event.EventScopePersistenceAdapter]
 * 가 사용, 시그니처 불변) 그대로 재사용한다.
 */
@Mapper
interface AccountEventMapper {

    /** accountId가 담당하는 event_id 목록(빈 리스트 허용 — 배정 0건). */
    fun findEventIds(@Param("accountId") accountId: String): List<String>

    /** accountId의 행사할당을 전량 삭제한다(delete-insert 재작성의 delete 절반, §3-2/§3-3). */
    fun deleteByAccountId(@Param("accountId") accountId: String): Int

    /** accountId에 eventId 담당을 1건 등록한다(delete-insert 재작성의 insert 절반). */
    fun insert(@Param("accountId") accountId: String, @Param("eventId") eventId: String): Int

    /** 목록 응답 조립용 배치 조회(§3-1) — N+1 회피. accountIds가 비어있으면 호출하지 않는다(어댑터 책임). */
    fun findEventIdsByAccountIds(@Param("accountIds") accountIds: List<String>): List<AccountEventRow>
}

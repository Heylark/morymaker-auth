package kr.co.morymaker.auth.persistence.adapter.persistence.event.mapper

import org.apache.ibatis.annotations.Mapper
import org.apache.ibatis.annotations.Param

/**
 * account_event 테이블 MyBatis 매퍼 — 계정-행사 담당 M:N 조회 전용(토큰 발급 시점 event 스코프 조회).
 *
 * 헥사고날 레이어: persistence(mapper) — DB 관심사만 담당. XML 정의: resources/mapper/event/AccountEventMapper.xml.
 *
 * 순수 매핑 테이블(비즈니스 속성 없음) — 표준 6개 메서드(fetch/search/insert/update/delete) 대신
 * 이 조회 하나만 필요하다(등록·해제는 이 REQ 범위 밖, 후속 REQ의 관리자 콘솔 API 몫).
 */
@Mapper
interface AccountEventMapper {

    /** accountId가 담당하는 event_id 목록(빈 리스트 허용 — 배정 0건). */
    fun findEventIds(@Param("accountId") accountId: String): List<String>
}

package kr.co.morymaker.auth.persistence.adapter.persistence.event.mapper

/**
 * [AccountEventMapper.findEventIdsByAccountIds] 배치 조회 결과 행.
 *
 * account_id 1개당 event_id가 여러 행으로 펼쳐져 반환된다 — 어댑터([kr.co.morymaker.auth.persistence.adapter.persistence.event.AccountEventPersistenceAdapter])가
 * accountId 기준으로 그룹핑해 `Map<String, List<String>>`으로 조립한다(목록 응답 N+1 회피용 배치 조회).
 */
data class AccountEventRow(val accountId: String, val eventId: String)

-- One row for each registrant carrying the requested reference, and on each of
-- those rows the number of licences that registrant currently holds.
--
-- The join and the grouping are what keep records inside the extract. A count
-- crosses the source boundary; a licence record never does, so there is no row
-- for a later mistake to disclose.
--
-- The left join is load-bearing. A registrant holding no current licence must
-- still produce a row, or a registrant nobody has licensed would be
-- indistinguishable from a reference this register has never heard of. Grouping
-- by the registrant's own identifier rather than by the reference is what makes
-- two registrants filed under one reference two rows, which is the ambiguity
-- the extraction script reads.
--
-- :evidence_now is the runtime's evaluation instant, bound as fixed-width
-- RFC 3339 UTC. The stored validity bounds are published in the same form, so
-- these comparisons order lexically the way they order in time and the
-- statement reads no clock of its own. The window is half-open: a licence is
-- current from the instant it starts until the instant it ends.
SELECT COUNT(l.licence_id) AS active_licence_count
FROM registrants AS r
LEFT JOIN licences AS l
    ON l.registrant_id = r.registrant_id
   AND l.status_code = 'ACTIVE'
   AND l.valid_from <= :evidence_now
   AND l.valid_until > :evidence_now
WHERE r.reference = :record_reference
GROUP BY r.registrant_id
ORDER BY r.registrant_id;

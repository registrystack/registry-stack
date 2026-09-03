SELECT
  h.id AS id,
  count(*) FILTER (
    WHERE gm.relationship = 'head'
      AND gm.valid_from <= registry_context.evaluation_date()
      AND (gm.valid_to IS NULL OR registry_context.evaluation_date() < gm.valid_to)
  )::bigint AS head_count,
  count(*) FILTER (
    WHERE gm.relationship = 'child'
      AND gm.valid_from <= registry_context.evaluation_date()
      AND (gm.valid_to IS NULL OR registry_context.evaluation_date() < gm.valid_to)
  )::bigint AS child_count,
  count(*) FILTER (
    WHERE gm.relationship = 'child'
      AND p.date_of_birth > (registry_context.evaluation_date() - 5 * INTERVAL '1 year')::date
      AND gm.valid_from <= registry_context.evaluation_date()
      AND (gm.valid_to IS NULL OR registry_context.evaluation_date() < gm.valid_to)
  )::bigint AS child_under_5_count,
  count(*) FILTER (
    WHERE p.date_of_birth <= (registry_context.evaluation_date() - 65 * INTERVAL '1 year')::date
      AND gm.valid_from <= registry_context.evaluation_date()
      AND (gm.valid_to IS NULL OR registry_context.evaluation_date() < gm.valid_to)
  )::bigint AS elderly_count,
  (
    count(*) FILTER (
      WHERE gm.relationship = 'head'
        AND gm.valid_from <= registry_context.evaluation_date()
        AND (gm.valid_to IS NULL OR registry_context.evaluation_date() < gm.valid_to)
    ) = 1
    AND count(*) FILTER (
      WHERE gm.relationship = 'spouse'
        AND gm.valid_from <= registry_context.evaluation_date()
        AND (gm.valid_to IS NULL OR registry_context.evaluation_date() < gm.valid_to)
    ) = 0
  ) AS single_headed,
  (
    count(*) FILTER (
      WHERE gm.relationship = 'head'
        AND p.person_sex = 'female'
        AND gm.valid_from <= registry_context.evaluation_date()
        AND (gm.valid_to IS NULL OR registry_context.evaluation_date() < gm.valid_to)
    ) > 0
  ) AS woman_headed
FROM registry_source.household h
LEFT JOIN registry_source.group_membership gm
  ON gm.household = h.id
LEFT JOIN registry_source.person p
  ON p.id = gm.person
GROUP BY h.id

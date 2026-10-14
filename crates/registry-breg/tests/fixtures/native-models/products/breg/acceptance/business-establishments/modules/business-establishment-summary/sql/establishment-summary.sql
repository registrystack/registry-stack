SELECT
  b.id AS id,
  count(e.id) FILTER (WHERE a.relationship = 'head-office')::bigint AS head_office_count,
  count(e.id) FILTER (WHERE a.relationship = 'branch')::bigint AS branch_count,
  count(e.id) FILTER (WHERE e.establishment_kind = 'production')::bigint AS production_site_count,
  count(e.id) FILTER (WHERE e.operating_status = 'suspended')::bigint AS suspended_site_count,
  (count(e.id) FILTER (WHERE a.relationship = 'head-office') > 0) AS has_head_office,
  (count(e.id) FILTER (WHERE e.establishment_kind = 'production') > 0) AS has_production_site
FROM registry_source.business b
LEFT JOIN registry_source.operator_assignment a
  ON a.business = b.id
  AND a.valid_from <= registry_context.evaluation_date()
  AND (a.valid_to IS NULL OR registry_context.evaluation_date() < a.valid_to)
LEFT JOIN registry_source.establishment e
  ON e.id = a.establishment
GROUP BY b.id

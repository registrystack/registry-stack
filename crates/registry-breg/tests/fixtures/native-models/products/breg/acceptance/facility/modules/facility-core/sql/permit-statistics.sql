SELECT
  permit.id AS id,
  CASE
    WHEN permit.valid_to IS NULL THEN false
    ELSE permit.valid_to <= registry_context.evaluation_date() + interval '90 days'
  END AS expiring_soon
FROM registry_source.permit AS permit

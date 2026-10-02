SELECT
  report.id AS id,
  report.quantity_value IS NOT NULL AS has_measured_quantity
FROM registry_source.discharge_report AS report

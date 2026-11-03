-- Return only the narrow fact needed for the assertion. The bound parameter
-- comes from the authorized selector; no caller value becomes SQL text.
SELECT status
FROM records
WHERE code = :code
ORDER BY record_id;

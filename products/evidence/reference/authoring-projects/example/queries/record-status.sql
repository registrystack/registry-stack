-- Return only the narrow fact needed for the assertion. The bound parameter
-- comes from the authorized selector; no caller value becomes SQL text.
SELECT qualifying_record_count
FROM records
WHERE reference = :record_reference
ORDER BY record_id;

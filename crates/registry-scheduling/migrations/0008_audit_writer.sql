-- Scheduling writes its audit entries through the process audit writer, so
-- the database holds no audit state. The migration runner refuses this
-- version while the outbox still holds records the earlier publisher had not
-- published.
DROP TABLE scheduling_audit_outbox;

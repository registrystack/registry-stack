-- SPDX-License-Identifier: Apache-2.0
--
-- An access profile's `dailyLimit` is counted over the messages the profile
-- had accepted in the last 24 hours, in the acceptance transaction and under
-- the profile's advisory lock. The accepted messages are the count, so it
-- survives a restart without a counter table; this index keeps the count a
-- range scan of one profile.

CREATE INDEX messaging_messages_profile_accepted_idx
    ON messaging_messages (access_profile, accepted_at);

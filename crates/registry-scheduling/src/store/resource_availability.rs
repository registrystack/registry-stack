// SPDX-License-Identifier: Apache-2.0

//! Operator impact reads over current resource facts. Recording an absence
//! blocks new admissions without cancelling commitments already promised.

use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use super::{PostgresStore, StoreError};

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceSupplyImpact {
    pub claim_id: Uuid,
    pub kind: String,
    pub resource: String,
    pub occupied_start: DateTime<Utc>,
    pub occupied_end: DateTime<Utc>,
}

/// The first 256 affected live resource allocations and the exact total in the same
/// snapshot. Operators use scoped appointment reads to inspect the remaining
/// bookings. Holds retain their ordinary bounded expiry.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceSupplyImpacts {
    pub total: i64,
    pub items: Vec<ResourceSupplyImpact>,
}

impl PostgresStore {
    /// Current impact, not a promise that supply will remain unchanged after
    /// this read. This operator path contains no person or absence reason.
    pub async fn resource_supply_impacts(&self) -> Result<ResourceSupplyImpacts, StoreError> {
        let client = self.client().await?;
        let rows = client.query(
            "WITH supply AS ( \
                SELECT resource_id, available, capacity_units, COALESCE(availability ? 'openings', false) AS bounded, \
                (SELECT range_agg(tstzrange((i->>'start')::timestamptz, (i->>'end')::timestamptz, '[)')) \
                 FROM jsonb_array_elements(COALESCE(availability->'openings', '[]'::jsonb)) i) AS openings, \
                (SELECT range_agg(tstzrange((i->>'start')::timestamptz, (i->>'end')::timestamptz, '[)')) \
                 FROM jsonb_array_elements(COALESCE(availability->'closures', '[]'::jsonb)) i) AS closures \
                FROM scheduling_pool_members \
            ), live AS ( \
                SELECT c.claim_id,c.kind,a.resource_id,a.occupied_start,a.occupied_end,a.units \
                FROM scheduling_claims c JOIN scheduling_claim_allocations a USING(claim_id) \
                WHERE c.state='active' AND a.occupied_end > now() \
                  AND (c.kind IN ('booking','window') OR (c.kind='hold' AND c.hold_expires_at > now())) \
                  AND (c.kind='window' OR (c.operational_mode='exact-time' \
                    AND a.operational_mode='exact-time')) \
            ), events AS ( \
                SELECT resource_id,occupied_start AS instant,units::bigint AS delta FROM live \
                UNION ALL SELECT resource_id,occupied_end,-units::bigint FROM live \
            ), loads AS ( \
                SELECT resource_id,instant,sum(sum(delta)) OVER (PARTITION BY resource_id ORDER BY instant) AS units \
                FROM events GROUP BY resource_id,instant \
            ), impacted AS ( \
                SELECT DISTINCT a.claim_id,a.kind,a.resource_id,a.occupied_start,a.occupied_end \
                FROM live a LEFT JOIN supply m ON m.resource_id=a.resource_id \
                WHERE m.resource_id IS NULL OR NOT m.available \
                  OR (m.bounded AND NOT (COALESCE(m.openings, '{}'::tstzmultirange) @> tstzrange(a.occupied_start, a.occupied_end, '[)'))) \
                  OR m.closures && tstzmultirange(tstzrange(a.occupied_start, a.occupied_end, '[)')) \
                  OR EXISTS (SELECT 1 FROM loads l WHERE l.resource_id=a.resource_id \
                      AND l.instant >= a.occupied_start AND l.instant < a.occupied_end AND l.units > m.capacity_units) \
            ) SELECT claim_id,kind,resource_id,occupied_start,occupied_end,count(*) OVER() FROM impacted \
            ORDER BY occupied_start,claim_id,resource_id,occupied_end LIMIT 256",
            &[],
        ).await?;
        Ok(ResourceSupplyImpacts {
            total: rows.first().map_or(0, |row| row.get(5)),
            items: rows
                .iter()
                .map(|row| ResourceSupplyImpact {
                    claim_id: row.get(0),
                    kind: row.get(1),
                    resource: row.get(2),
                    occupied_start: row.get(3),
                    occupied_end: row.get(4),
                })
                .collect(),
        })
    }
}

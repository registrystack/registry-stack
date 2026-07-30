fn consult(ctx) {
    let exact_tracking_id = #{
        type: "exact",
        term: ctx.input.tracking_id
    };
    let birth_event_clause = #{
        eventType: "birth",
        trackingId: exact_tracking_id
    };
    let response = source.post_json("/api/events/events/search", #{
        query: #{
            type: "and",
            clauses: [birth_event_clause]
        },
        limit: 2,
        offset: 0
    });
    if response.status != 200 {
        return result.fail(failure.source_rejected);
    }

    let events = response.body.results;
    if response.body.total == 0 && events.len == 0 {
        return result.no_match();
    }
    if response.body.total > 1 || events.len > 1 {
        return result.ambiguous();
    }
    if response.body.total != 1 || events.len != 1 {
        return result.fail(failure.source_rejected);
    }

    let event = events[0];
    if event.trackingId != ctx.input.tracking_id {
        return result.fail(failure.subject_mismatch);
    }
    if event.type != "birth" {
        return result.fail(failure.source_rejected);
    }

    result.match(#{
        event_type: event.type,
        registered: event.status == "REGISTERED"
    })
}

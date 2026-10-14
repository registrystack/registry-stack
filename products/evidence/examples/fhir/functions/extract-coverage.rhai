fn extract(response, selectors, context) {
    if response.id != selectors["coverage-record"].values.coverage_id {
        throw("source_protocol_error");
    }
    #{outcome: "match", facts: #{
        status: response.status,
        "beneficiary-reference": response.beneficiary.reference
    }}
}

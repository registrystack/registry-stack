fn prepare(selectors, context) {
    #{query: [], body: #{
        reference: selectors["farmer"]["values"]["farmer-number"],
        fields: context.parameters.requestedFields,
        limit: context.parameters.resultLimit
    }}
}

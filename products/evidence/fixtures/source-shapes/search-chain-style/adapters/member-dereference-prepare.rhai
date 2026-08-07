fn prepare(selectors, context) {
    // This member takes its whole input through the path binding Rust resolves
    // from the allowlisted search fact. The query channel stays open and unused
    // so that an empty query is an observed outcome rather than a policy the
    // channel made unreachable, and the body channel is closed by the method.
    #{
        query: [],
        body: ()
    }
}

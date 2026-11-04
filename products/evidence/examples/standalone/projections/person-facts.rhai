// The reusable source pack owns acquisition and exact-match classification.
// This project retains only the facts its definitions use.
fn project_facts(source) {
    #{
        "birth-date": source["birth-date"],
        "residence-region": source["residence-region"]
    }
}

// One F5 item of the kobo-submissions page (CONCEPT 17.2): the
// route's split runs this script once per submission of the reply's
// `results`, so each submission gets the full script budget however
// many answers its form carries.
//
// Item mapping (both parts are probe-gated hypotheses, see the pack
// README): key = the submission's `_id` as text, revision = `_uuid`,
// value = the submission object with its slash-separated group and
// repeat names nested (`household/household_size` becomes
// `household: {household_size}`), so a job projection can address
// them as dotted paths. Rows of a repeat group arrive with their full
// names (`household/member/member_name`); each row drops its repeat's
// own name before nesting. A name that is both a leaf and a group
// throws. `_validation_status` passes through only inside `value`. A
// submission without an integer `_id` or without `_uuid` throws: a
// page that cannot be keyed or revisioned is an unexpected shape,
// never a silently weaker item. Pure and deterministic; no I/O.
fn shape_item(exchange) {
    let submission = exchange.body;
    if submission.type_of() != "map" {
        throw "kobo result is not an object";
    }
    let id = submission["_id"];
    if id == () {
        throw "submission carries no _id";
    }
    if id.type_of() != "i64" {
        throw "submission _id is not an integer";
    }
    let revision = submission["_uuid"];
    if revision == () {
        throw "submission carries no _uuid";
    }
    #{
        key: `${id}`,
        revision: revision,
        value: nest(submission, "")
    }
}

// One record with its slash-separated names nested. `prefix` is the
// repeat's own name plus `/` for a repeat row, empty for the
// submission itself.
fn nest(record, prefix) {
    let out = #{};
    for name in record.keys() {
        let value = record[name];
        let path = name;
        if prefix != "" && name.starts_with(prefix) {
            path = name.sub_string(prefix.len());
        }
        if value.type_of() == "array" {
            value = nest_rows(value, name + "/");
        }
        if path.contains("/") {
            out = place(out, path.split("/"), value);
        } else {
            if path in out {
                throw "a submission name is both a leaf and a group";
            }
            out[path] = value;
        }
    }
    out
}

// A repeat group's rows nested; any other array passes unchanged.
fn nest_rows(rows, prefix) {
    let out = [];
    for row in rows {
        if row.type_of() == "map" {
            out.push(nest(row, prefix));
        } else {
            out.push(row);
        }
    }
    out
}

// `target` with `value` placed under the segment path.
fn place(target, segments, value) {
    let head = segments[0];
    if segments.len() == 1 {
        if head in target {
            throw "a submission name is both a leaf and a group";
        }
        target[head] = value;
        return target;
    }
    let child = target[head];
    if child == () {
        child = #{};
    } else if child.type_of() != "map" {
        throw "a submission name is both a leaf and a group";
    }
    target[head] = place(child, segments.extract(1), value);
    target
}

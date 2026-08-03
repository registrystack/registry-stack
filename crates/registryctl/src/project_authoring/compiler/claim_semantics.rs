// SPDX-License-Identifier: Apache-2.0

// Shared CEL authoring semantics for Relay consultation and attribute-release
// expressions.

#[derive(Debug, Default, PartialEq, Eq)]
struct CelReferences {
    roots: BTreeSet<String>,
    first_level_members: BTreeMap<String, BTreeSet<String>>,
    uses_index: bool,
}

fn cel_references(expression: &str) -> Result<CelReferences> {
    let program = cel::Program::compile(expression)
        .map_err(|_| anyhow!("CEL expression contains invalid syntax"))?;
    let mut references = CelReferences::default();
    collect_cel_references(program.expression(), &BTreeSet::new(), &mut references);
    Ok(references)
}

fn cel_member_roots(expression: &str) -> Result<BTreeSet<String>> {
    Ok(cel_references(expression)?.roots)
}

fn collect_cel_references(
    expression: &IdedExpr,
    locals: &BTreeSet<String>,
    references: &mut CelReferences,
) {
    match &expression.expr {
        Expr::Unspecified | Expr::Literal(_) => {}
        Expr::Ident(name) => {
            if !name.starts_with('@') && !locals.contains(name) {
                references.roots.insert(name.clone());
            }
        }
        Expr::Select(select) => {
            if let Expr::Ident(root) = &select.operand.expr {
                if !root.starts_with('@') && !locals.contains(root) {
                    references
                        .first_level_members
                        .entry(root.clone())
                        .or_default()
                        .insert(select.field.clone());
                }
            }
            collect_cel_references(&select.operand, locals, references);
        }
        Expr::Call(call) => {
            if matches!(
                call.func_name.as_str(),
                cel::common::ast::operators::INDEX | cel::common::ast::operators::OPT_INDEX
            ) {
                references.uses_index = true;
            }
            if let Some(target) = &call.target {
                collect_cel_references(target, locals, references);
            }
            for argument in &call.args {
                collect_cel_references(argument, locals, references);
            }
        }
        Expr::List(list) => {
            for element in &list.elements {
                collect_cel_references(element, locals, references);
            }
        }
        Expr::Map(map) => {
            for entry in &map.entries {
                collect_cel_entry_references(&entry.expr, locals, references);
            }
        }
        Expr::Struct(value) => {
            for entry in &value.entries {
                collect_cel_entry_references(&entry.expr, locals, references);
            }
        }
        Expr::Comprehension(comprehension) => {
            collect_cel_references(&comprehension.iter_range, locals, references);
            collect_cel_references(&comprehension.accu_init, locals, references);

            let mut scoped_locals = locals.clone();
            scoped_locals.insert(comprehension.iter_var.clone());
            if let Some(iter_var) = &comprehension.iter_var2 {
                scoped_locals.insert(iter_var.clone());
            }
            scoped_locals.insert(comprehension.accu_var.clone());
            collect_cel_references(&comprehension.loop_cond, &scoped_locals, references);
            collect_cel_references(&comprehension.loop_step, &scoped_locals, references);
            collect_cel_references(&comprehension.result, &scoped_locals, references);
        }
    }
}

fn collect_cel_entry_references(
    entry: &EntryExpr,
    locals: &BTreeSet<String>,
    references: &mut CelReferences,
) {
    match entry {
        EntryExpr::StructField(field) => {
            collect_cel_references(&field.value, locals, references);
        }
        EntryExpr::MapEntry(entry) => {
            collect_cel_references(&entry.key, locals, references);
            collect_cel_references(&entry.value, locals, references);
        }
    }
}

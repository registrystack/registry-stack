// Select native record and Proposal hooks from the generated authoring schemas.
export function eventConfiguration(reference) {
  const select = (contractId, prefix, id, title) => {
    const contract = reference.contracts.find((entry) => entry.id === contractId);
    if (!contract) throw new Error(`BReg ${contractId} configuration is missing`);
    const fields = contract.fields
      .filter((field) => field.key_path.startsWith(prefix))
      .map((field) => ({ ...field, key_path: field.key_path.slice(prefix.length) }));
    if (fields.length === 0) throw new Error(`BReg ${id} configuration is empty`);
    return { ...contract, id, title, field_count: fields.length, fields };
  };
  return [
    select('module', 'recordTypes[].hooks[].', 'record-event', 'Record type hooks[]'),
    select('project', 'actions[].execution.proposal.hooks[].', 'proposal-event', 'Proposal hooks[]'),
  ];
}

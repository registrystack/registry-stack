// Select from the same generated schema fields as the full configuration reference.
export function eventConfiguration(reference) {
  const module = reference.contracts.find((contract) => contract.id === 'module');
  if (!module) throw new Error('Server module configuration is missing');
  const prefix = 'entities[].events[].';
  const fields = module.fields
    .filter((field) => field.key_path.startsWith(prefix))
    .map((field) => ({ ...field, key_path: field.key_path.slice(prefix.length) }));
  if (fields.length === 0) throw new Error('Server event configuration is empty');
  return [{ ...module, id: 'event', title: 'events[]', field_count: fields.length, fields }];
}

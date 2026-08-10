# Classification review rationale

The public access profile uses the reviewed pre-derived public view column.
Registrar-only properties retain confidential handling and cannot appear in
public metadata or cacheable responses.

The premises Point and its longitude and latitude carrier columns are each
explicitly reviewed as non-personal public data. Relay exposes only the
classified `location` property. The carrier columns remain internal to the
compiled Point binding and never appear as selectable or serialized fields.

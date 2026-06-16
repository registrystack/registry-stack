# @registry/notary-openfn

OpenFn authoring helpers for Registry Notary OpenFn sidecar workflows.

The sidecar owns HTTP auth, worker isolation, credential loading, projection,
and Registry Data API normalization. This adaptor gives OpenFn authors a small
API for reading the sidecar request and returning a shape the sidecar accepts.

```js
fn((state) => {
  assertNotaryRequest(state);

  const { field, value } = lookup(state);
  const records = state.configuration.fixture_records
    .filter((record) => String(record[field]) === String(value))
    .slice(0, 2);

  return returnRecords(state, records);
});
```

For native batch workflows:

```js
fn((state) => {
  assertBatchRequest(state);

  const items = batchItems(state).map((item) => {
    const { field, value } = batchItemLookup(state, item);
    const data = state.configuration.fixture_records
      .filter((record) => String(record[field]) === String(value))
      .slice(0, 2);
    return { id: item.id, data };
  });

  return returnBatchItems(state, items);
});
```

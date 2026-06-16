// SPDX-License-Identifier: Apache-2.0
// Native batch lookup authored with @registry/notary-openfn helpers.
fn((state) => {
  assertBatchRequest(state);

  const records = state.configuration.fixture_records ?? [];
  const items = batchItems(state).map((item) => {
    const itemLookup = batchItemLookup(state, item);
    const terms = itemLookup.terms ?? [itemLookup];
    const data = records
      .filter((record) =>
        terms.every((term) => String(record[term.field]) === String(term.value)),
      )
      .slice(0, 2);

    return { id: item.id, data };
  });

  return returnBatchItems(state, items);
});

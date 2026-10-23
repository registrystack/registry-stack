// Only these two generated reference components have a text expansion.
// Other MDX remains the responsibility of the normal Astro renderer.
import breg_api from '../data/generated/breg-api.json' with { type: 'json' };
import casework_api from '../data/generated/casework-api.json' with { type: 'json' };
import scheduling_api from '../data/generated/scheduling-api.json' with { type: 'json' };
import messaging_api from '../data/generated/messaging-api.json' with { type: 'json' };
import coordinator_api from '../data/generated/coordinator-api.json' with { type: 'json' };
import breg_events from '../data/generated/breg-events.json' with { type: 'json' };

const generated = {
  'breg-api': breg_api,
  'casework-api': casework_api,
  'scheduling-api': scheduling_api,
  'messaging-api': messaging_api,
  'coordinator-api': coordinator_api,
  'breg-events': breg_events,
};

/** @param {string} body @param {Record<string, Array<{id: string, columns: string[], rows: string[][]}>>} [sources] */
export function expandReferenceTables(body, sources) {
  let fence;
  return body.split(/(.*(?:\r?\n|$))/).map((line) => {
    const marker = line.match(/^\s*(`{3,}|~{3,})/);
    if (marker) {
      if (!fence) fence = marker[1];
      else if (marker[1][0] === fence[0] && marker[1].length >= fence.length) fence = undefined;
      return line;
    }
    if (fence) return line;
    return line.replace(/<(ApiReferenceTable|EventReferenceTable)\b([^>]*?)\/>/g, (_whole, component, attributes) => {
      const fields = new Map();
      const rest = attributes.replace(/\b(id|source)\s*=\s*(["'])(.*?)\2/g, (_attribute, name, _quote, value) => {
        if (fields.has(name)) throw new Error('Duplicate reference table attribute');
        fields.set(name, value);
        return '';
      });
      if (rest.trim() || !fields.get('id') || (component === 'EventReferenceTable' && fields.has('source'))) {
        throw new Error('Invalid reference table attributes; use a literal id and optional API source');
      }
      const source = component === 'EventReferenceTable' ? 'breg-events' : fields.get('source') ?? 'breg-api';
      const tables = sources ? sources[source] : generated[source];
      const table = tables?.find((entry) => entry.id === fields.get('id'));
      if (!table) throw new Error(`Unknown reference table: ${source}/${fields.get('id')}`);
      const cell = (value) => value.replaceAll('|', '\\|').replace(/\r?\n/g, '<br>');
      const row = (values) => `| ${values.map(cell).join(' | ')} |`;
      return [row(table.columns), row(table.columns.map(() => '---')), ...table.rows.map(row)].join('\n');
    });
  }).join('');
}

import { describe, it, expect } from 'vitest';
import {
  FORMS,
  getForm,
  CATALOG,
  autoFetchFields,
  manualField,
  delegatedFields
} from './descriptors';

describe('service form descriptors', () => {
  it('has the four services in presenter-arc order', () => {
    expect(FORMS.map((f) => f.slug)).toEqual([
      'agri-subsidy',
      'education-grant',
      'social-cash',
      'civil-certificate'
    ]);
  });

  it('every field has a valid kind', () => {
    const kinds = new Set(['self', 'verify', 'fetch', 'decision']);
    for (const form of FORMS) {
      for (const field of form.fields) {
        expect(kinds.has(field.kind)).toBe(true);
      }
    }
  });

  it('every verify/fetch/decision field names a notary and a claim', () => {
    for (const form of FORMS) {
      for (const field of form.fields) {
        if (field.kind !== 'self') {
          expect(field.notary, `${field.id} notary`).toBeDefined();
          expect(field.claim, `${field.id} claim`).toBeDefined();
        }
      }
    }
  });

  it('every verify/fetch field carries a disclosure (the minimization line)', () => {
    for (const form of FORMS) {
      for (const field of form.fields) {
        if (field.kind === 'verify' || field.kind === 'fetch' || field.kind === 'decision') {
          expect(field.disclose, `${field.id} disclose`).toBeTruthy();
        }
      }
    }
  });

  it('has exactly one manual climax field across all forms (the social-cash decision)', () => {
    const manual = FORMS.flatMap((f) => f.fields).filter((f) => f.manual === true);
    expect(manual).toHaveLength(1);
    expect(manual[0].id).toBe('combined-support-eligibility');
    expect(manualField(getForm('social-cash')!)?.id).toBe('combined-support-eligibility');
    expect(manualField(getForm('agri-subsidy')!)).toBeUndefined();
  });

  it('flags the delegated civil reads in education-grant only', () => {
    const del = delegatedFields(getForm('education-grant')!);
    expect(del.map((f) => f.id).sort()).toEqual(['birth-event-exists', 'date-of-birth']);
    for (const field of del) {
      expect(field.notary).toBe('civil');
      expect(field.delegated?.dependentRef).toBe('selected-child');
    }
    expect(delegatedFields(getForm('agri-subsidy')!)).toHaveLength(0);
  });

  it('autoFetch excludes self, manual, and delegated fields', () => {
    const auto = autoFetchFields(getForm('social-cash')!);
    expect(auto.every((f) => f.kind === 'verify' || f.kind === 'fetch')).toBe(true);
    expect(auto.some((f) => f.manual)).toBe(false);
    expect(auto.some((f) => f.delegated)).toBe(false);
    // social-cash auto-fetches: person-is-alive, disability-determination,
    // functioning-assessment, household-size (not the manual decision).
    expect(auto.map((f) => f.id)).toEqual([
      'person-is-alive',
      'disability-determination',
      'functioning-assessment',
      'household-size'
    ]);
  });

  it('getForm returns undefined for an unknown slug', () => {
    expect(getForm('does-not-exist')).toBeUndefined();
  });

  it('CATALOG matches the form slugs and titles', () => {
    expect(CATALOG.map((c) => c.slug)).toEqual(FORMS.map((f) => f.slug));
    for (const entry of CATALOG) {
      expect(entry.title).toBe(getForm(entry.slug)!.title);
      expect(entry.summary).toBeTruthy();
    }
  });
});

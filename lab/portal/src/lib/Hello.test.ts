import { render, screen } from '@testing-library/svelte';
import { describe, it, expect } from 'vitest';
import Hello from './Hello.svelte';

describe('Hello (baseline harness test)', () => {
  it('renders welcome text with default name', () => {
    render(Hello);
    expect(screen.getByText('Welcome to Solmara')).toBeInTheDocument();
  });
});

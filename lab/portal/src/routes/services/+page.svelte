<script lang="ts">
  import { CATALOG } from '$lib/forms';
  import type { PageData } from './$types';

  let { data }: { data: PageData } = $props();

  const AUTHORITY_LABEL: Record<string, string> = {
    civil: 'Civil',
    social: 'Social',
    agri: 'Agriculture',
    certs: 'Certificates'
  };
</script>

<section class="catalog">
  <h1>Welcome, {data.displayName}.</h1>
  <p class="intro">
    Choose a service. The form fills itself from the authorities that already hold the facts: you
    do not retype what the state already knows.
  </p>

  <ul class="cards">
    {#each CATALOG as entry (entry.slug)}
      <li class="card">
        <a href={`/services/${entry.slug}`} data-testid={`card-${entry.slug}`}>
          <h2>{entry.title}</h2>
          <p>{entry.summary}</p>
          <div class="authorities">
            {#each entry.authorities as authority (authority)}
              <span class="seal" data-authority={authority}>{AUTHORITY_LABEL[authority] ?? authority}</span>
            {/each}
          </div>
        </a>
      </li>
    {/each}
  </ul>
</section>

<style>
  .catalog {
    font-family: var(--font-ui);
  }

  h1 {
    font-size: var(--text-2xl);
    font-weight: 700;
    color: var(--color-chrome);
    margin: 0 0 var(--space-2);
  }

  .intro {
    font-size: var(--text-base);
    color: var(--color-chrome);
    max-width: 44rem;
    margin: 0 0 var(--space-8);
  }

  .cards {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(18rem, 1fr));
    gap: var(--space-4);
  }

  .card a {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
    height: 100%;
    padding: var(--space-4);
    background: var(--color-surface-raised);
    border: 1px solid color-mix(in srgb, var(--color-chrome) 12%, transparent);
    border-radius: var(--radius-lg);
    text-decoration: none;
    box-shadow: var(--shadow-sm);
    transition: box-shadow var(--transition-base);
  }

  .card a:hover,
  .card a:focus-visible {
    box-shadow: var(--shadow-md);
    outline: none;
  }

  .card h2 {
    font-size: var(--text-lg);
    font-weight: 600;
    color: var(--color-chrome);
    margin: 0;
  }

  .card p {
    font-size: var(--text-sm);
    color: var(--color-channel-self);
    margin: 0;
    flex: 1;
  }

  .authorities {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-1);
  }

  .seal {
    font-size: var(--text-xs);
    font-weight: 600;
    padding: var(--space-1) var(--space-2);
    border-radius: var(--radius-full);
    color: #fff;
  }

  .seal[data-authority='civil'] {
    background: var(--color-ministry-civil);
  }
  .seal[data-authority='social'] {
    background: var(--color-ministry-social);
  }
  .seal[data-authority='agri'] {
    background: var(--color-ministry-agri);
  }
  .seal[data-authority='certs'] {
    background: var(--color-ministry-civil);
  }
</style>

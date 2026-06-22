<script lang="ts">
  import type { StatusIcon } from './states';

  // Inline SVG glyphs. The icon is a load-bearing, non-colour signal paired with
  // every coloured status (WCAG: colour is never the only cue). It inherits the
  // chip's accent via currentColor and an aria-hidden role, since the adjacent
  // text already carries the meaning for assistive tech.
  let { icon, spin = false }: { icon: StatusIcon; spin?: boolean } = $props();
</script>

<svg
  class="status-icon"
  class:spin
  width="16"
  height="16"
  viewBox="0 0 16 16"
  fill="none"
  stroke="currentColor"
  stroke-width="1.6"
  stroke-linecap="round"
  stroke-linejoin="round"
  aria-hidden="true"
  data-icon={icon}
>
  {#if icon === 'check'}
    <path d="M3 8.5 6.5 12 13 4" />
  {:else if icon === 'cross'}
    <path d="M4 4l8 8M12 4l-8 8" />
  {:else if icon === 'lock'}
    <rect x="3.5" y="7" width="9" height="6.5" rx="1" />
    <path d="M5.5 7V5a2.5 2.5 0 0 1 5 0v2" />
  {:else if icon === 'spinner'}
    <path d="M8 1.5a6.5 6.5 0 1 1-6.5 6.5" />
  {:else if icon === 'warning'}
    <path d="M8 2.5 14.5 13.5h-13z" />
    <path d="M8 6.5v3.2" />
    <circle cx="8" cy="11.6" r="0.2" />
  {:else if icon === 'pencil'}
    <path d="M11 2.5 13.5 5 6 12.5l-3 .5.5-3z" />
  {/if}
</svg>

<style>
  .status-icon {
    flex: none;
  }

  .spin {
    animation: status-spin 900ms linear infinite;
    transform-origin: center;
  }

  @keyframes status-spin {
    to {
      transform: rotate(360deg);
    }
  }

  @media (prefers-reduced-motion: reduce) {
    .spin {
      animation: none;
    }
  }
</style>

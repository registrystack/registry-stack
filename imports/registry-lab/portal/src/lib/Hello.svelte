<script lang="ts">
  // Baseline harness test component: proves Svelte 5 compiles in Vitest.
  let { name = 'Solmara' }: { name?: string } = $props();
</script>

<p>Welcome to {name}</p>

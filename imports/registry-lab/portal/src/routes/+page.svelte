<script lang="ts">
  // Landing: the Republic of Solmara portal. The ministry rail (in the layout) is
  // already breathing before any login. Nothing has been shared yet.
</script>

<section class="hero">
  <p class="kicker">Republic of Solmara</p>
  <h1>One door to every public service.</h1>
  <p class="lede">
    Sign in once. Each ministry answers for itself, in the open: nothing is copied into a central
    file, and you watch every connection happen.
  </p>
  <!-- /auth/login is a server endpoint, not a page route: force a full navigation
       so the client router does not try (and fail) to resolve it as a page. -->
  <a class="signin" href="/auth/login" data-sveltekit-reload data-testid="signin">
    Sign in with SolmaraID
  </a>
  <p class="nothing-shared">Nothing has been shared yet.</p>
</section>

<style>
  .hero {
    max-width: 42rem;
    margin: var(--space-12) auto;
    padding: 0 var(--space-4);
    text-align: center;
  }

  .kicker {
    font-family: var(--font-ui);
    font-size: var(--text-sm);
    font-weight: 600;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: var(--color-accent-seal);
    margin-bottom: var(--space-3);
  }

  h1 {
    font-family: var(--font-ui);
    font-size: var(--text-3xl);
    font-weight: 700;
    color: var(--color-chrome);
    margin: 0 0 var(--space-4);
  }

  .lede {
    font-family: var(--font-ui);
    font-size: var(--text-lg);
    color: var(--color-chrome);
    line-height: 1.5;
    margin: 0 auto var(--space-8);
    max-width: 36rem;
  }

  .signin {
    display: inline-block;
    background: var(--color-chrome);
    color: #fff;
    font-family: var(--font-ui);
    font-size: var(--text-base);
    font-weight: 600;
    text-decoration: none;
    padding: var(--space-3) var(--space-8);
    border-radius: var(--radius-md);
    box-shadow: var(--shadow-md);
  }

  .signin:focus-visible {
    outline: none;
    box-shadow: var(--ring-focus);
  }

  .nothing-shared {
    margin-top: var(--space-6);
    font-family: var(--font-mono);
    font-size: var(--text-sm);
    color: var(--color-channel-self);
  }
</style>

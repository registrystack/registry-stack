<script lang="ts">
  // MinistryRail.svelte - the ministry constellation network.
  // Motion signature is the PRIMARY channel cue; colour is secondary.
  //   verify  -> pulse animation on the node
  //   fetch   -> packet travels the edge, then a stamp lands on the node
  //   denied  -> packet bounces back BEFORE the target node lights
  //
  // prefers-reduced-motion: all animation is suppressed; a numbered-sequence
  // list renders instead so the gating and fan-out story remains legible.
  import type { RailEvent, NotaryId } from '$lib/types';
  import { AUTHORITY_NAMES } from '$lib/fields/authorities';

  type Props = {
    events?: RailEvent[];
    citizenName?: string;
  };

  let { events = [], citizenName = 'Maria' }: Props = $props();

  // --- layout constants ---
  const CX = 280;  // SVG width
  const CY = 220;  // SVG height
  const CITIZEN_X = CX / 2;
  const CITIZEN_Y = CY / 2;
  const ORBIT_R = 90;

  // Ministry nodes in clockwise order around the citizen seat.
  // NodeId extends NotaryId with 'health' so the constellation can show the
  // health node as permanently dark (it is intentionally never called in the
  // current demo, and its dark state is itself a proof of minimization).
  type NodeId = NotaryId | 'health';
  type NodeDef = {
    id: NodeId;
    label: string;
    angle: number;   // degrees, 0 = top
    color: string;
    glyph?: string;  // node-circle initial; defaults to label[0]. Override to disambiguate.
  };

  const NODES: NodeDef[] = [
    { id: 'civil',   label: 'Civil',        angle: -90,  color: 'var(--color-ministry-civil)' },
    { id: 'social',  label: 'Social',       angle: -18,  color: 'var(--color-ministry-social)' },
    { id: 'agri',    label: 'Agriculture',  angle:  54,  color: 'var(--color-ministry-agri)' },
    // Certificates is served by the Civil Registry (see AUTHORITY_LABEL.certs), so
    // it shares the civil colour. The glyph carries the difference ('Ce' not 'C') so
    // two blue circles do not read as an accidental duplicate of Civil. Health is the
    // only deliberately-dark, never-called node, so it keeps the distinct vermilion.
    { id: 'certs',   label: 'Certs',        angle: 126,  color: 'var(--color-ministry-civil)', glyph: 'Ce' },
    { id: 'health',  label: 'Health',       angle: 198,  color: 'var(--color-ministry-health)' }
  ];

  // NodeId -> NodeDef lookup. We use string keys so NotaryId events from the
  // wire can be looked up directly.
  const nodeMap = new Map<string, NodeDef>(NODES.map((n) => [n.id, n]));

  function toXY(angleDeg: number, r: number, cx: number, cy: number): [number, number] {
    const rad = (angleDeg * Math.PI) / 180;
    return [cx + r * Math.cos(rad), cy + r * Math.sin(rad)];
  }

  // --- derive per-node active state from events ---
  type NodeState = 'idle' | 'in_flight' | 'sealed' | 'denied';

  // Track which animations are active so we can set data-motion attributes.
  // For reduced-motion the SVG layer is hidden and the list is shown instead.
  const nodeStates = $derived(
    (() => {
      const map = new Map<string, NodeState>();
      for (const node of NODES) map.set(node.id, 'idle');

      // Walk events from newest-last to apply the most recent state.
      for (const ev of events) {
        const current = map.get(ev.authority) ?? 'idle';
        // Only advance state, never go backwards (request->sealed/denied).
        if (ev.phase === 'request' && current === 'idle') {
          map.set(ev.authority, 'in_flight');
        } else if (ev.phase === 'sealed') {
          map.set(ev.authority, 'sealed');
        } else if (ev.phase === 'denied') {
          map.set(ev.authority, 'denied');
        }
      }
      return map;
    })()
  );

  // Active packet animations: one per (authority, channel, phase:'request') event
  // that has not yet reached its terminal phase. We derive this from sequential
  // pairs: a request event whose id is not superseded by a sealed/denied event.
  type Packet = {
    id: string;
    authority: NotaryId;
    channel: string;  // 'verify' | 'fetch' | 'denied'
    motion: 'pulse-target' | 'travel-stamp' | 'bounce';
  };

  const activePackets = $derived(
    (() => {
      // Collect all sealed/denied event authority+channel pairs to filter out
      // resolved packets.
      const resolved = new Set<string>();
      for (const ev of events) {
        if (ev.phase === 'sealed' || ev.phase === 'denied') {
          resolved.add(`${ev.authority}-${ev.channel}`);
        }
      }

      const packets: Packet[] = [];
      for (const ev of events) {
        if (ev.phase !== 'request') continue;
        const key = `${ev.authority}-${ev.channel}`;
        if (resolved.has(key)) continue;
        const motion =
          ev.channel === 'verify' ? 'pulse-target' :
          ev.channel === 'fetch'  ? 'travel-stamp' :
          'bounce';
        packets.push({ id: ev.id, authority: ev.authority as NotaryId, channel: ev.channel, motion } satisfies Packet);
      }
      return packets;
    })()
  );

  // --- sequence list for reduced-motion fallback ---
  // Produce a flat ordered list of human-readable steps.
  type SequenceStep = {
    seq: number;
    text: string;
    channel: string;
    phase: string;
    authority: string;
  };

  const sequenceSteps = $derived(
    events.map((ev, i): SequenceStep => {
      const authLabel = AUTHORITY_NAMES[ev.authority as NotaryId] ?? ev.authority;
      const channelLabel =
        ev.channel === 'verify' ? 'verify' :
        ev.channel === 'fetch'  ? 'fetch'  :
        'denied';
      const phaseLabel =
        ev.phase === 'request' ? 'request sent' :
        ev.phase === 'sealed'  ? 'sealed'        :
        'denied - bounced before registry read';
      return {
        seq: i + 1,
        text: `${authLabel}: ${channelLabel} ${phaseLabel}`,
        channel: ev.channel,
        phase: ev.phase,
        authority: ev.authority
      };
    })
  );
</script>

<!-- The outer wrapper carries a data-motion attribute so tests can verify
     which motion signature is active without relying on colour. -->
<div
  class="rail-root"
  aria-label="Ministry constellation network"
  role="img"
>
  <!--
    Animated SVG layer. Hidden by CSS when prefers-reduced-motion is set.
    Each packet/node element carries data-motion and data-channel attributes
    so tests and accessibility tools can verify the non-colour signals.
  -->
  <svg
    class="rail-svg"
    viewBox={`0 0 ${CX} ${CY}`}
    aria-hidden="true"
    focusable="false"
    width={CX}
    height={CY}
  >
    <!-- Edges from citizen to each ministry -->
    {#each NODES as node}
      {@const [nx, ny] = toXY(node.angle, ORBIT_R, CITIZEN_X, CITIZEN_Y)}
      <line
        x1={CITIZEN_X}
        y1={CITIZEN_Y}
        x2={nx}
        y2={ny}
        class="rail-edge"
        stroke={node.color}
        opacity="0.3"
        stroke-width="1"
      />
    {/each}

    <!-- Packet animations along edges -->
    {#each activePackets as packet}
      {@const nodeDef = nodeMap.get(packet.authority)}
      {#if nodeDef}
        {@const [nx, ny] = toXY(nodeDef.angle, ORBIT_R, CITIZEN_X, CITIZEN_Y)}
        <!--
          data-motion encodes the motion signature (not just colour):
            pulse-target  = verify
            travel-stamp  = fetch
            bounce        = denied
          data-channel names the channel for test assertions.
        -->
        <circle
          class="packet"
          cx={CITIZEN_X}
          cy={CITIZEN_Y}
          r="4"
          fill={nodeDef.color}
          data-motion={packet.motion}
          data-channel={packet.channel}
          data-authority={packet.authority}
          aria-label={`${packet.channel} packet to ${AUTHORITY_NAMES[packet.authority as NotaryId] ?? packet.authority}`}
        >
          {#if packet.motion === 'travel-stamp' || packet.motion === 'bounce'}
            <!-- Travel: move from citizen to node (or partway then back for bounce) -->
            <animateMotion
              dur={packet.motion === 'bounce' ? '0.5s' : '0.7s'}
              repeatCount="indefinite"
              path={packet.motion === 'bounce'
                ? `M ${CITIZEN_X},${CITIZEN_Y} L ${nx * 0.5 + CITIZEN_X * 0.5},${ny * 0.5 + CITIZEN_Y * 0.5} L ${CITIZEN_X},${CITIZEN_Y}`
                : `M ${CITIZEN_X},${CITIZEN_Y} L ${nx},${ny}`
              }
            />
          {:else}
            <!-- Pulse: the packet stays near the target node and pulses -->
            <animateMotion
              dur="0.001s"
              fill="freeze"
              path={`M ${nx},${ny}`}
            />
            <animate
              attributeName="r"
              values="3;7;3"
              dur="1.2s"
              repeatCount="indefinite"
            />
            <animate
              attributeName="opacity"
              values="0.8;0.3;0.8"
              dur="1.2s"
              repeatCount="indefinite"
            />
          {/if}
        </circle>
      {/if}
    {/each}

    <!-- Ministry nodes -->
    {#each NODES as node}
      {@const [nx, ny] = toXY(node.angle, ORBIT_R, CITIZEN_X, CITIZEN_Y)}
      {@const state = nodeStates.get(node.id) ?? 'idle'}
      {@const isActive = state !== 'idle'}
      <!-- Sealed: stamp ring animates outward -->
      {#if state === 'sealed'}
        <circle
          cx={nx}
          cy={ny}
          r="12"
          fill="none"
          stroke={node.color}
          stroke-width="2"
          class="stamp-ring"
          data-motion="stamp"
          data-channel="sealed"
          data-authority={node.id}
        >
          <animate
            attributeName="r"
            values="12;20"
            dur="0.5s"
            fill="freeze"
          />
          <animate
            attributeName="opacity"
            values="1;0"
            dur="0.5s"
            fill="freeze"
          />
        </circle>
      {/if}

      <!-- Node glyph: circle + monoline seal icon -->
      <g
        class="ministry-node"
        class:active={isActive}
        data-node={node.id}
        data-state={state}
        role="img"
        aria-label={`${node.label}: ${state === 'idle' ? 'waiting' : state}`}
      >
        <!-- Node background circle -->
        <circle
          cx={nx}
          cy={ny}
          r={state === 'sealed' ? 13 : 11}
          fill={isActive ? node.color : 'var(--color-surface)'}
          stroke={node.color}
          stroke-width={state === 'sealed' ? 2.5 : 1.5}
          opacity={state === 'idle' ? 0.6 : 1}
        />
        <!-- Denied: X glyph -->
        {#if state === 'denied'}
          <line
            x1={nx - 5} y1={ny - 5}
            x2={nx + 5} y2={ny + 5}
            stroke="var(--color-channel-denied)"
            stroke-width="2"
            stroke-linecap="round"
          />
          <line
            x1={nx + 5} y1={ny - 5}
            x2={nx - 5} y2={ny + 5}
            stroke="var(--color-channel-denied)"
            stroke-width="2"
            stroke-linecap="round"
          />
        {:else}
          <!-- Monoline seal glyph: a small initial representing the ministry -->
          <text
            x={nx}
            y={ny + 4}
            text-anchor="middle"
            font-size="9"
            font-family="var(--font-ui)"
            font-weight="600"
            fill={isActive ? 'white' : node.color}
            aria-hidden="true"
          >{node.glyph ?? node.label.charAt(0)}</text>
        {/if}
      </g>

      <!-- Node label below the circle -->
      <text
        x={nx}
        y={ny + 22}
        text-anchor="middle"
        font-size="8"
        font-family="var(--font-ui)"
        fill={node.color}
        class="node-label"
        aria-hidden="true"
      >{node.label}</text>
    {/each}

    <!-- Citizen seat (centre node) -->
    <g role="img" aria-label={`Citizen seat: ${citizenName}`}>
      <circle
        cx={CITIZEN_X}
        cy={CITIZEN_Y}
        r="14"
        fill="var(--color-chrome)"
        stroke="var(--color-accent-seal)"
        stroke-width="2"
      />
      <text
        x={CITIZEN_X}
        y={CITIZEN_Y + 4}
        text-anchor="middle"
        font-size="10"
        font-family="var(--font-ui)"
        fill="var(--color-accent-seal)"
        aria-hidden="true"
      >{citizenName.charAt(0)}</text>
      <!-- Caption below the seat so first-time viewers know the centre is the citizen -->
      <text
        x={CITIZEN_X}
        y={CITIZEN_Y + 26}
        text-anchor="middle"
        font-size="8"
        font-family="var(--font-ui)"
        font-weight="600"
        fill="var(--color-accent-seal)"
        class="citizen-label"
        aria-hidden="true"
      >{citizenName}</text>
    </g>
  </svg>

  <!--
    Reduced-motion fallback: a numbered-sequence list that makes the ordering,
    gating, and fan-out story legible without any animation.
    Visible ONLY when prefers-reduced-motion: reduce is active.
    Each item carries data-channel and data-phase so tests can assert
    the correct labels without relying on colour.
  -->
  <ol class="sequence-list" aria-label="Event sequence (reduced motion)">
    {#if sequenceSteps.length === 0}
      <li class="sequence-empty">No events yet.</li>
    {:else}
      {#each sequenceSteps as step}
        <li
          class="sequence-step"
          data-channel={step.channel}
          data-phase={step.phase}
          data-authority={step.authority}
        >
          <span class="step-num" aria-hidden="true">{step.seq}.</span>
          <span class="step-text">{step.text}</span>
          <!-- Channel label is always present as text, not only colour -->
          <span class="step-channel" data-channel-label={step.channel}>
            {step.channel === 'verify' ? 'verify' : step.channel === 'fetch' ? 'fetch' : 'denied'}
          </span>
        </li>
      {/each}
    {/if}
  </ol>
</div>

<style>
  .rail-root {
    position: relative;
    display: inline-block;
    font-family: var(--font-ui);
  }

  .rail-svg {
    display: block;
    overflow: visible;
  }

  /* Motion: pulse on sealed nodes */
  .ministry-node.active :global(circle) {
    transition: r var(--transition-base), opacity var(--transition-base);
  }

  .stamp-ring {
    pointer-events: none;
  }

  /* Reduced-motion fallback: hide SVG, show list */
  @media (prefers-reduced-motion: reduce) {
    .rail-svg {
      display: none;
    }

    .sequence-list {
      display: block;
    }
  }

  /* By default the list is visually hidden but present in DOM for screen readers.
     Under reduced-motion it becomes the primary display. */
  .sequence-list {
    display: none;
    margin: 0;
    padding: 0 0 0 var(--space-4);
    list-style: none;
    font-size: var(--text-sm);
    font-family: var(--font-mono);
    color: var(--color-chrome);
  }

  .sequence-empty {
    color: var(--color-channel-self);
    font-style: italic;
  }

  .sequence-step {
    display: flex;
    align-items: baseline;
    gap: var(--space-2);
    padding: var(--space-1) 0;
    border-bottom: 1px solid rgb(0 0 0 / 0.06);
  }

  .step-num {
    flex-shrink: 0;
    width: 1.5rem;
    color: var(--color-channel-self);
  }

  .step-text {
    flex: 1;
  }

  .step-channel {
    flex-shrink: 0;
    font-size: var(--text-xs);
    padding: 1px 6px;
    border-radius: var(--radius-full);
    border: 1px solid currentColor;
  }

  /* Channel colour as secondary cue on the pill (always paired with text label) */
  .step-channel[data-channel-label="verify"] {
    color: var(--color-channel-verify);
  }

  .step-channel[data-channel-label="fetch"] {
    color: var(--color-channel-fetch);
  }

  .step-channel[data-channel-label="denied"] {
    color: var(--color-channel-denied);
  }
</style>

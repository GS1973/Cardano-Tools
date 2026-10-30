<template>
  <v-card class="mb-4">
    <v-card-text class="d-flex align-center" style="gap: 1rem;">
      <h3 class="text-subtitle-1 mt-0 mb-0">Pool</h3>
      <v-spacer />
      <div class="d-flex" style="gap: 0.5rem;">
        <v-btn
          size="small"
          color="primary"
          :variant="mode === 'send' ? 'tonal' : 'outlined'"
          :loading="starting"
          :disabled="!canBuild || !!submitted"
          prepend-icon="mdi-upload"
          style="width: 180px;"
          @click="openConfirmSend"
        >Send to Signer</v-btn>
        <v-btn
          size="small"
          color="primary"
          :variant="mode === 'receive' ? 'tonal' : 'outlined'"
          :disabled="!request || !!submitted"
          prepend-icon="mdi-download"
          style="width: 180px;"
          @click="emit('receive')"
        >Receive from Signer</v-btn>
        <v-btn
          size="small"
          variant="tonal"
          :loading="loading"
          :disabled="!!submitted"
          prepend-icon="mdi-refresh"
          @click="emit('refresh')"
        >Refresh</v-btn>
      </div>
    </v-card-text>

    <v-card-text v-if="error">
      <v-alert type="error" density="compact" variant="tonal">{{ error }}</v-alert>
    </v-card-text>

    <v-card-text v-else-if="!current" class="text-medium-emphasis">Loading…</v-card-text>

    <v-card-text v-else>
      <v-alert
        v-if="!current.is_single_owner"
        type="error"
        density="compact"
        variant="tonal"
        class="mb-3"
      >This pool has {{ current.owners.length }} owners. v1.0 supports single-owner pools only.</v-alert>

      <v-alert
        v-if="!current.can_cover_fee"
        type="warning"
        density="compact"
        variant="tonal"
        class="mb-3"
      >Payment address has insufficient funds to cover the transaction fee
        ({{ fmtAda(current.estimated_fee_lovelace) }}). Top it up before continuing.</v-alert>

      <v-alert
        v-if="current.pending"
        type="warning"
        density="comfortable"
        variant="tonal"
        class="mb-3"
      >
        <div class="d-flex align-center mb-2" style="gap: 0.5rem;">
          <strong>Pending pool-parameter change</strong>
          <v-spacer />
          <span class="text-caption text-medium-emphasis">
            Active in epoch {{ current.pending.active_epoch_no }}:
            {{ pendingCountdown }}
          </span>
        </div>
        <div v-if="pendingDiffs.length" class="text-body-2">
          <div v-for="d in pendingDiffs" :key="d.label" class="d-flex" style="gap: 0.5rem;">
            <span class="text-medium-emphasis" style="min-width: 140px;">{{ d.label }}:</span>
            <span><code class="text-caption">{{ d.from }}</code></span>
            <span class="text-medium-emphasis">→</span>
            <span class="text-gold"><strong><code class="text-caption">{{ d.to }}</code></strong></span>
          </div>
        </div>
        <div class="text-caption text-medium-emphasis mt-2">
          Tx <code>{{ current.pending.tx_hash.slice(0, 16) }}…</code>:
          <a
            :href="`https://explorer.cardano.org/en/transaction?id=${current.pending.tx_hash}`"
            target="_blank"
            rel="noopener"
          >view on explorer</a>
        </div>
      </v-alert>

      <v-table density="compact" class="mb-3">
        <tbody>
          <tr><td class="text-medium-emphasis" style="width: 280px;">Pool ID</td>
              <td><code class="text-caption">{{ current.pool_id_bech32 }}</code></td></tr>
          <tr><td class="text-medium-emphasis">VRF key hash</td>
              <td><code class="text-caption">{{ current.vrf_key_hash }}</code></td></tr>
          <tr><td class="text-medium-emphasis">Pledge (owner) stake address</td>
              <td><code class="text-caption">{{ current.owners[0] }}</code></td></tr>
          <tr><td class="text-medium-emphasis">Payment address</td>
              <td><code class="text-caption">{{ current.payment_address }}</code></td></tr>
          <tr><td class="text-medium-emphasis">Payment total</td>
              <td>{{ fmtAda(current.payment_utxo_total_lovelace) }}</td></tr>
          <tr><td class="text-medium-emphasis">Estimated fee</td>
              <td>{{ fmtAda(current.estimated_fee_lovelace) }}</td></tr>
        </tbody>
      </v-table>

      <template v-if="mode !== 'receive' && !submitted">
        <h3 class="text-subtitle-1 mt-4 mb-2">Edit parameters</h3>
        <p class="text-caption text-medium-emphasis mb-3">
          Fields highlighted in <span class="text-gold">gold</span> differ from the latest known pool state (the pending update if there is one, otherwise the active on-chain values).
        </p>

        <v-row dense>
          <v-col cols="12" md="4">
            <v-text-field
              v-model="form.pledgeAda"
              :class="{ 'changed-field': diffPledge }"
              label="Pledge (₳)"
              type="number"
              step="0.000001"
              min="0"
              density="compact"
              variant="outlined"
              hide-details
            />
          </v-col>
          <v-col cols="12" md="4">
            <v-text-field
              v-model="form.fixedCostAda"
              :class="{ 'changed-field': diffFixedCost }"
              label="Fixed cost (₳)"
              type="number"
              step="0.000001"
              min="170"
              :rules="[v => Number(v) >= MIN_POOL_COST_ADA || `Minimum is ${MIN_POOL_COST_ADA} ₳`]"
              hint="Protocol minimum: 170 ₳"
              persistent-hint
              density="compact"
              variant="outlined"
            />
          </v-col>
          <v-col cols="12" md="4">
            <v-text-field
              v-model="form.marginPercent"
              :class="{ 'changed-field': diffMargin }"
              label="Margin (%)"
              type="number"
              step="0.01"
              min="0"
              max="100"
              density="compact"
              variant="outlined"
              hide-details
            />
          </v-col>
        </v-row>

        <v-alert
          v-if="marginRationalUnavailable"
          type="warning"
          density="compact"
          variant="tonal"
          class="mt-3"
        >
          The exact on-chain margin rational could not be recovered from the
          upstream float. Re-registering sets the margin to exactly the
          percent shown above, which may differ marginally from the current
          on-chain value.
        </v-alert>

        <v-alert
          v-if="pledgePrecheckLoading"
          type="info"
          density="compact"
          variant="tonal"
          class="mt-3"
        >
          Verifying owner stake balance against new pledge…
        </v-alert>

        <v-alert
          v-else-if="diffPledge && pledgePrecheck && pledgePrecheck.meets_pledge"
          type="success"
          density="compact"
          variant="tonal"
          class="mt-3"
        >
          Owner balance {{ fmtAda(pledgePrecheck.owner_balance_lovelace) }}
          meets the new pledge {{ fmtAda(pledgePrecheck.pledge_lovelace) }}.
          <span class="text-caption text-medium-emphasis">
            (Based on current balance: actual pledge check at epoch boundary
            uses the active stake snapshot.)
          </span>
        </v-alert>

        <v-alert
          v-else-if="diffPledge && pledgePrecheck && !pledgePrecheck.meets_pledge"
          type="error"
          density="compact"
          variant="tonal"
          class="mt-3"
        >
          <p class="mb-2">
            Owner balance {{ fmtAda(pledgePrecheck.owner_balance_lovelace) }}
            is below the new pledge {{ fmtAda(pledgePrecheck.pledge_lovelace) }}.
            Shortfall: {{ fmtAda(pledgePrecheck.shortfall_lovelace) }}.
          </p>
          <p class="mb-2 text-body-2">
            The protocol verifies pledge against the active stake snapshot,
            taken 1–2 epochs before activation. Even if you fund the owner
            wallet now, the snapshot may not yet reflect it: the pool
            drops out of leader rotation for at least one epoch until a
            new snapshot includes the funding.
          </p>
          <v-checkbox
            v-model="pledgeForceConfirm"
            label="I understand the snapshot risk and want to proceed anyway"
            density="compact"
            hide-details
            class="mt-2"
          />
        </v-alert>

        <v-alert
          v-else-if="diffPledge && pledgePrecheckFailed"
          type="warning"
          density="compact"
          variant="tonal"
          class="mt-3"
        >
          <p class="mb-2">
            The owner stake balance could not be verified against the new
            pledge (balance lookup failed). If the owner wallet cannot
            cover the pledge, the pool drops out of leader rotation at the
            next epoch snapshot.
          </p>
          <v-checkbox
            v-model="pledgeForceConfirm"
            label="I verified the owner balance myself and want to proceed anyway"
            density="compact"
            hide-details
            class="mt-2"
          />
        </v-alert>

        <v-checkbox
          v-model="form.rewardSameAsOwner"
          label="Reward stake address = Pledge (owner) stake address"
          density="compact"
          hide-details
          class="mt-3 mb-2"
        />
        <v-text-field
          v-model="form.rewardAccountBech32"
          :class="{ 'changed-field': diffRewardAccount }"
          :disabled="form.rewardSameAsOwner"
          label="Reward stake address"
          placeholder="stake1..."
          density="compact"
          variant="outlined"
          hide-details
          class="mb-3"
        />

        <h3 class="text-subtitle-2 mt-3 mb-2">Relays</h3>
        <div v-for="(r, i) in form.relays" :key="i" class="d-flex align-center mb-2" style="gap: 0.5rem;">
          <v-select
            v-model="r.kind"
            :class="{ 'changed-field': relayDiff(i) }"
            :items="relayKindItems"
            label="Type"
            density="compact"
            variant="outlined"
            hide-details
            style="max-width: 180px;"
          />
          <v-text-field
            v-if="r.kind === 'single_host_addr'"
            v-model="r.ipv4"
            :class="{ 'changed-field': relayDiff(i) }"
            label="IPv4"
            placeholder="1.2.3.4"
            density="compact"
            variant="outlined"
            hide-details
          />
          <v-text-field
            v-if="r.kind === 'single_host_addr'"
            v-model="r.ipv6"
            :class="{ 'changed-field': relayDiff(i) }"
            label="IPv6"
            placeholder="2001:db8::1"
            density="compact"
            variant="outlined"
            hide-details
          />
          <v-text-field
            v-else
            v-model="r.dns"
            :class="{ 'changed-field': relayDiff(i) }"
            label="DNS hostname"
            placeholder="relay1.example.com"
            density="compact"
            variant="outlined"
            hide-details
          />
          <v-text-field
            v-if="r.kind !== 'multi_host_name'"
            v-model.number="r.port"
            :class="{ 'changed-field': relayDiff(i) }"
            label="Port"
            type="number"
            min="1"
            max="65535"
            density="compact"
            variant="outlined"
            hide-details
            style="max-width: 120px;"
          />
          <v-btn icon="mdi-close" size="small" variant="text" @click="removeRelay(i)" />
        </div>
        <v-btn size="small" variant="text" prepend-icon="mdi-plus" @click="addRelay">Add relay</v-btn>
        <div v-if="diffRelays" class="text-caption text-gold mt-1">Relays differ from the latest known state.</div>

        <h3 class="text-subtitle-2 mt-4 mb-2">Pool metadata</h3>
        <div class="d-flex align-center mb-2" style="gap: 0.5rem;">
          <v-text-field
            v-model="form.metadataUrl"
            :class="{ 'changed-field': diffMetadataUrl }"
            label="Metadata URL"
            placeholder="https://example.com/pool.json"
            density="compact"
            variant="outlined"
            hide-details
          />
          <v-btn
            v-if="form.metadataUrl"
            size="small"
            variant="tonal"
            :loading="hashingMetadataUrl"
            prepend-icon="mdi-cloud-download"
            @click="fetchMetadataUrlHash"
          >Fetch and hash</v-btn>
        </div>
        <div v-if="metadataUrlHashNote" class="text-caption mb-2" :class="metadataUrlHashMismatch ? 'text-error' : 'text-medium-emphasis'">{{ metadataUrlHashNote }}</div>
        <div class="d-flex align-center mb-2" style="gap: 0.5rem;">
          <v-file-input
            v-model="metadataFile"
            label="Metadata JSON (compute hash)"
            accept="application/json,.json"
            density="compact"
            variant="outlined"
            hide-details
            prepend-icon=""
            prepend-inner-icon="mdi-file-upload"
            show-size
          />
          <v-btn
            v-if="metadataFile"
            size="small"
            variant="tonal"
            :loading="hashingMetadata"
            prepend-icon="mdi-pound"
            @click="computeMetadataHash"
          >Compute hash</v-btn>
        </div>
        <v-text-field
          v-model="form.metadataHashHex"
          :class="{ 'changed-field': diffMetadataHash }"
          label="Metadata hash (Blake2b-256, hex)"
          placeholder="64 hex chars"
          density="compact"
          variant="outlined"
          hide-details
        />
      </template>
    </v-card-text>
  </v-card>

  <PreSendConfirm
    v-model="confirmSendOpen"
    title="Confirm pool parameter update"
    @confirm="onConfirmSend"
  >
    <p class="text-body-2 text-medium-emphasis mb-2">You are about to re-register this pool with the parameters in the form. Verify margin / pledge / fixed-cost / owners / relays / metadata against the on-chain values shown in the form.</p>
  </PreSendConfirm>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import { useNotificationStore } from '@spo-tools/shared-frontend/stores/notification'
import { PLEDGE_PRECHECK_DEBOUNCE_MS } from '@spo-tools/shared-frontend/constants/timings'
import { fmtAda } from '@spo-tools/shared-frontend/utils/format'
import type { RelaySpec } from '@spo-tools/shared-frontend/types/pool'
import type { PoolCurrent, PoolUpdateRequest, SubmittedTx } from '../types/pool-params'
import type { ErrorCode } from '@spo-tools/shared-frontend/types/core'
import { extractError } from '@spo-tools/shared-frontend/utils/error'
import PreSendConfirm from '@spo-tools/shared-frontend/components/PreSendConfirm.vue'

const props = defineProps<{
  current: PoolCurrent | null
  loading: boolean
  error: string | null
  mode: 'idle' | 'send' | 'receive'
  submitted: SubmittedTx | null
  request: PoolUpdateRequest | null
}>()

const emit = defineEmits<{
  (e: 'request-built', payload: { request: PoolUpdateRequest; ur_fragments: string[]; request_fingerprint: string | null; body_hash_hex: string | null }): void
  (e: 'start-error', message: string): void
  (e: 'receive'): void
  (e: 'refresh'): void
  (e: 'not-configured'): void
  (e: 'not-paired'): void
  (e: 'request-reset'): void
  (e: 'form-changed'): void
}>()

const MIN_POOL_COST_ADA = 170

const relayKindItems = [
  { title: 'IPv4/IPv6 + port', value: 'single_host_addr' },
  { title: 'DNS A record + port', value: 'single_host_name' },
  { title: 'DNS SRV record', value: 'multi_host_name' },
]

interface FormRelay {
  kind: 'single_host_addr' | 'single_host_name' | 'multi_host_name'
  ipv4: string
  ipv6: string
  dns: string
  port: number | null
}

const form = ref({
  pledgeAda: '0',
  fixedCostAda: '170',
  marginPercent: '1',
  rewardSameAsOwner: true,
  rewardAccountBech32: '',
  relays: [] as FormRelay[],
  metadataUrl: '',
  metadataHashHex: '',
})

const metadataFile = ref<File | null>(null)
const hashingMetadata = ref(false)
const hashingMetadataUrl = ref(false)
const metadataUrlHashNote = ref('')
const metadataUrlHashMismatch = ref(false)
const starting = ref(false)

interface PledgePrecheck {
  owner_stake_address: string
  owner_balance_lovelace: number
  pledge_lovelace: number
  meets_pledge: boolean
  shortfall_lovelace: number
}
const pledgePrecheck = ref<PledgePrecheck | null>(null)
const pledgePrecheckLoading = ref(false)
const pledgePrecheckFailed = ref(false)
const pledgeForceConfirm = ref(false)
let pledgePrecheckTimer: ReturnType<typeof setTimeout> | null = null

const notify = useNotificationStore()

const latestKnown = computed(() => {
  const c = props.current
  if (!c) return null
  const p = c.pending
  if (!p) {
    return {
      pledge_lovelace: c.pledge_lovelace,
      margin: c.margin,
      margin_numerator: c.margin_numerator,
      margin_denominator: c.margin_denominator,
      fixed_cost_lovelace: c.fixed_cost_lovelace,
      reward_address: c.reward_address,
      relays: c.relays,
      metadata_url: c.metadata_url,
      metadata_hash: c.metadata_hash,
      owners: c.owners,
    }
  }
  // The exact rational is recovered only for the active registration; a
  // pending margin change arrives from Koios as a float alone, so the
  // rational only survives when the pending update leaves margin as-is.
  const marginUnchanged = p.margin == null || p.margin === c.margin
  return {
    pledge_lovelace: p.pledge_lovelace ?? c.pledge_lovelace,
    margin: p.margin ?? c.margin,
    margin_numerator: marginUnchanged ? c.margin_numerator : null,
    margin_denominator: marginUnchanged ? c.margin_denominator : null,
    fixed_cost_lovelace: p.fixed_cost_lovelace ?? c.fixed_cost_lovelace,
    reward_address: p.reward_address ?? c.reward_address,
    relays: p.relays.length ? p.relays : c.relays,
    metadata_url: p.metadata_url,
    metadata_hash: p.metadata_hash,
    owners: p.owners.length ? p.owners : c.owners,
  }
})

// Exact on-chain margin rational the form was prefilled from (null when
// the backend could not recover one, or a pending update overrides the
// margin with a float-only value). While the margin field is untouched
// the build request carries this rational verbatim, so an unrelated
// update (relays, cost) re-registers the identical margin instead of a
// re-rounded percent.
const prefilledMarginRational = ref<{ numerator: number; denominator: number } | null>(null)
const prefilledMarginPercent = ref<string | null>(null)
const marginUntouched = computed(() =>
  prefilledMarginRational.value !== null && form.value.marginPercent === prefilledMarginPercent.value,
)
const marginRationalUnavailable = computed(() =>
  !!latestKnown.value && latestKnown.value.margin_numerator == null,
)

const diffPledge = computed(() =>
  !!latestKnown.value && Math.round(Number(form.value.pledgeAda || 0) * 1_000_000) !== latestKnown.value.pledge_lovelace,
)
const diffFixedCost = computed(() =>
  !!latestKnown.value && Math.round(Number(form.value.fixedCostAda || 0) * 1_000_000) !== latestKnown.value.fixed_cost_lovelace,
)
const diffMargin = computed(() => {
  if (!latestKnown.value) return false
  // Untouched field prefilled from the exact rational: the build sends
  // the identical margin, so it is never a change.
  if (marginUntouched.value) return false
  const cur = latestKnown.value.margin
  const nw = Number(form.value.marginPercent || 0) / 100
  return Math.abs(cur - nw) > 1e-9
})
const diffRewardAccount = computed(() =>
  !!latestKnown.value && form.value.rewardAccountBech32.trim() !== latestKnown.value.reward_address,
)
const diffMetadataUrl = computed(() =>
  !!latestKnown.value && (form.value.metadataUrl || null) !== latestKnown.value.metadata_url,
)
const diffMetadataHash = computed(() =>
  !!latestKnown.value && (form.value.metadataHashHex.toLowerCase() || null) !== (latestKnown.value.metadata_hash?.toLowerCase() ?? null),
)

const diffRelays = computed(() => {
  if (!latestKnown.value) return false
  const a = JSON.stringify(toServerRelays(form.value.relays))
  const b = JSON.stringify(currentRelaysAsSpec(latestKnown.value.relays))
  return a !== b
})

function relayDiff(i: number): boolean {
  if (!latestKnown.value) return false
  const formRelays = toServerRelays(form.value.relays)
  const knownRelays = currentRelaysAsSpec(latestKnown.value.relays)
  return JSON.stringify(formRelays[i]) !== JSON.stringify(knownRelays[i])
}

const canBuild = computed(() => {
  if (!props.current) return false
  if (!props.current.is_single_owner) return false
  if (!props.current.can_cover_fee) return false
  if (Number(form.value.fixedCostAda || 0) < MIN_POOL_COST_ADA) return false
  if (
    diffPledge.value
    && pledgePrecheck.value
    && !pledgePrecheck.value.meets_pledge
    && !pledgeForceConfirm.value
  ) return false
  if (diffPledge.value && pledgePrecheckFailed.value && !pledgeForceConfirm.value) return false
  return true
})

interface PendingDiff { label: string; from: string; to: string }

const pendingDiffs = computed<PendingDiff[]>(() => {
  if (!props.current || !props.current.pending) return []
  const c = props.current
  const p = c.pending!
  const diffs: PendingDiff[] = []
  if (p.pledge_lovelace != null && p.pledge_lovelace !== c.pledge_lovelace) {
    diffs.push({ label: 'Pledge', from: fmtAda(c.pledge_lovelace), to: fmtAda(p.pledge_lovelace) })
  }
  if (p.fixed_cost_lovelace != null && p.fixed_cost_lovelace !== c.fixed_cost_lovelace) {
    diffs.push({ label: 'Fixed cost', from: fmtAda(c.fixed_cost_lovelace), to: fmtAda(p.fixed_cost_lovelace) })
  }
  if (p.margin != null && Math.abs(p.margin - c.margin) > 1e-9) {
    const fmtPct = (x: number) => (x * 100).toFixed(2) + '%'
    diffs.push({ label: 'Margin', from: fmtPct(c.margin), to: fmtPct(p.margin) })
  }
  if (p.reward_address && p.reward_address !== c.reward_address) {
    diffs.push({ label: 'Reward addr', from: c.reward_address.slice(0, 24) + '…', to: p.reward_address.slice(0, 24) + '…' })
  }
  if (p.metadata_url !== c.metadata_url) {
    diffs.push({ label: 'Metadata URL', from: c.metadata_url ?? '(none)', to: p.metadata_url ?? '(none)' })
  }
  return diffs
})

const pendingCountdown = computed(() => {
  if (!props.current?.pending) return ''
  const target = props.current.pending.active_epoch_first_unix
  const now = Math.floor(Date.now() / 1000)
  const secs = target - now
  if (secs <= 0) return 'now'
  const days = Math.floor(secs / 86400)
  const hours = Math.floor((secs % 86400) / 3600)
  if (days > 0) return `in ~${days} day${days === 1 ? '' : 's'} ${hours} h`
  return `in ~${hours} h`
})

function currentRelaysAsSpec(rs: PoolCurrent['relays']): RelaySpec[] {
  return rs.map(r => {
    if (r.ipv4 || r.ipv6) {
      return { kind: 'single_host_addr', port: r.port, ipv4: r.ipv4, ipv6: r.ipv6 }
    }
    // Koios semantics: `dns` is a single_host_name hostname, `srv` a
    // multi_host_name SRV name. The on-chain port is optional, so it
    // must not participate in the classification.
    if (r.dns && !r.srv) {
      return { kind: 'single_host_name', port: r.port, dns: r.dns }
    }
    return { kind: 'multi_host_name', dns: r.srv ?? '' }
  })
}

function toServerRelays(rs: FormRelay[]): RelaySpec[] {
  return rs.map(r => {
    if (r.kind === 'single_host_addr') {
      return { kind: 'single_host_addr', port: r.port ?? null, ipv4: r.ipv4 || null, ipv6: r.ipv6 || null }
    }
    if (r.kind === 'single_host_name') {
      return { kind: 'single_host_name', port: r.port ?? null, dns: r.dns || '' }
    }
    return { kind: 'multi_host_name', dns: r.dns || '' }
  })
}

function addRelay() {
  form.value.relays.push({ kind: 'single_host_name', ipv4: '', ipv6: '', dns: '', port: 3001 })
}
function removeRelay(i: number) {
  form.value.relays.splice(i, 1)
}

type LatestKnown = NonNullable<typeof latestKnown.value>

// Exact lovelace → ADA string via integer arithmetic, so on-chain values
// with a sub-ADA component round-trip through the form unchanged.
function lovelaceToAdaString(lovelace: number): string {
  const whole = Math.floor(lovelace / 1_000_000)
  const frac = lovelace % 1_000_000
  if (frac === 0) return String(whole)
  return `${whole}.${String(frac).padStart(6, '0').replace(/0+$/, '')}`
}

function populateFormFromLatest(c: LatestKnown, owners: string[]) {
  form.value.pledgeAda = lovelaceToAdaString(c.pledge_lovelace)
  form.value.fixedCostAda = lovelaceToAdaString(c.fixed_cost_lovelace)
  if (c.margin_numerator != null && c.margin_denominator != null && c.margin_denominator > 0) {
    // The backend recovered the exact rational behind the Koios float.
    // The percent string is display-only while untouched: the build
    // request carries the rational verbatim (see marginAsRational).
    prefilledMarginRational.value = { numerator: c.margin_numerator, denominator: c.margin_denominator }
    form.value.marginPercent =
      String(Number(((c.margin_numerator / c.margin_denominator) * 100).toFixed(6)))
  } else {
    // No rational available: 4 decimal places of percent is exactly the
    // precision the build request carries (denominator 1e6), so the form
    // shows precisely what a re-registration would set; anything finer
    // on chain gets the gold diff highlight plus a warning alert.
    prefilledMarginRational.value = null
    form.value.marginPercent = String((c.margin * 100).toFixed(4)).replace(/\.?0+$/, '') || '0'
  }
  prefilledMarginPercent.value = form.value.marginPercent
  form.value.rewardAccountBech32 = c.reward_address
  form.value.rewardSameAsOwner = c.reward_address === owners[0]
  form.value.metadataUrl = c.metadata_url ?? ''
  form.value.metadataHashHex = c.metadata_hash ?? ''
  form.value.relays = c.relays.map((r): FormRelay => {
    if (r.ipv4 || r.ipv6) {
      return { kind: 'single_host_addr', ipv4: r.ipv4 ?? '', ipv6: r.ipv6 ?? '', dns: '', port: r.port }
    }
    // Same classification as currentRelaysAsSpec: `dns` alone means
    // single_host_name (port optional), `srv` means multi_host_name.
    if (r.dns && !r.srv) {
      return { kind: 'single_host_name', ipv4: '', ipv6: '', dns: r.dns, port: r.port }
    }
    return { kind: 'multi_host_name', ipv4: '', ipv6: '', dns: r.srv ?? '', port: null }
  })
}

watch(
  () => props.current,
  (c) => {
    if (c && latestKnown.value) populateFormFromLatest(latestKnown.value, c.owners)
  },
  { immediate: true },
)

watch(
  () => form.value.pledgeAda,
  () => {
    if (pledgePrecheckTimer) clearTimeout(pledgePrecheckTimer)
    pledgePrecheckTimer = setTimeout(fetchPledgePrecheck, PLEDGE_PRECHECK_DEBOUNCE_MS)
  },
)
watch(
  () => props.current?.pledge_lovelace,
  () => fetchPledgePrecheck(),
)

watch(() => form.value.rewardSameAsOwner, (same) => {
  if (same && props.current) form.value.rewardAccountBech32 = props.current.owners[0]
})

// Any edit invalidates a previously generated build. The parent decides
// whether a reset is actually needed (only when a request/result exists).
watch(form, () => emit('form-changed'), { deep: true })

async function fetchPledgePrecheck() {
  if (!diffPledge.value) {
    pledgePrecheck.value = null
    pledgePrecheckFailed.value = false
    pledgeForceConfirm.value = false
    return
  }
  // Same rounding rule as buildBuildBody so the prechecked pledge is
  // the exact value the build request will carry.
  const lovelace = Math.round(Number(form.value.pledgeAda || 0) * 1_000_000)
  if (lovelace <= 0) {
    pledgePrecheck.value = null
    pledgePrecheckFailed.value = false
    return
  }
  pledgePrecheckLoading.value = true
  try {
    const r = await fetch(`/api/pool/pledge-precheck?pledge_lovelace=${lovelace}`)
    if (!r.ok) throw new Error(`HTTP ${r.status}`)
    pledgePrecheck.value = await r.json()
    pledgePrecheckFailed.value = false
  } catch {
    // A failed lookup (Koios down, HTTP 5xx) must not silently disable
    // the insufficient-pledge gate: flag it so the UI warns and
    // requires the force-confirm checkbox instead.
    pledgePrecheck.value = null
    pledgePrecheckFailed.value = true
  } finally {
    pledgePrecheckLoading.value = false
  }
}

async function computeMetadataHash() {
  if (!metadataFile.value) return
  hashingMetadata.value = true
  try {
    const buf = await metadataFile.value.arrayBuffer()
    const r = await fetch('/api/pool/metadata-hash', {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: buf,
    })
    if (!r.ok) {
      const err = await extractError<ErrorCode>(r)
      if (err.code === 'not_configured') {
        emit('not-configured')
        return
      }
      if (err.code === 'not_paired') {
        emit('not-paired')
        return
      }
      throw new Error(err.message)
    }
    const data = await r.json()
    form.value.metadataHashHex = data.hash_hex
    notify.success(`Hash computed (${data.size_bytes} bytes)`)
  } catch (e: unknown) {
    notify.error(e instanceof Error ? e.message : String(e))
  } finally {
    hashingMetadata.value = false
  }
}

// Fetch the bytes the metadata URL serves, through the guarded document
// client of the online tool, and hash them: the certificate must carry the
// hash of what the URL serves, not of a local copy that may differ.
async function fetchMetadataUrlHash() {
  const url = form.value.metadataUrl.trim()
  if (!url) return
  hashingMetadataUrl.value = true
  metadataUrlHashNote.value = ''
  metadataUrlHashMismatch.value = false
  try {
    const r = await fetch('/api/pool/metadata-url-hash', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    })
    const d = await r.json()
    if (d.status === 'error') throw new Error(d.message)
    const previous = form.value.metadataHashHex.trim().toLowerCase()
    form.value.metadataHashHex = d.hash_hex
    if (previous && previous !== d.hash_hex) {
      metadataUrlHashMismatch.value = true
      metadataUrlHashNote.value = `The URL serves ${d.byte_len} bytes with hash ${d.hash_hex}, which differs from the hash that was in the field. The field now holds the hash of what the URL serves.`
    } else {
      metadataUrlHashNote.value = `Hash of the ${d.byte_len} bytes the URL serves.`
    }
    notify.success(`Hash computed from the URL (${d.byte_len} bytes)`)
  } catch (e: unknown) {
    metadataUrlHashNote.value = e instanceof Error ? e.message : String(e)
    metadataUrlHashMismatch.value = true
    notify.error(metadataUrlHashNote.value)
  } finally {
    hashingMetadataUrl.value = false
  }
}

function marginAsRational(): { numerator: number; denominator: number } {
  // Untouched margin: return the exact on-chain rational so an unrelated
  // update (relays, cost) round-trips the margin bit-identically.
  if (marginUntouched.value && prefilledMarginRational.value) {
    return prefilledMarginRational.value
  }
  const pct = Number(form.value.marginPercent || 0)
  const num = Math.round(pct * 10_000)
  return { numerator: num, denominator: 1_000_000 }
}

function buildBuildBody() {
  const margin = marginAsRational()
  const reward = form.value.rewardSameAsOwner && props.current
    ? props.current.owners[0]
    : form.value.rewardAccountBech32.trim()
  return {
    pledge_lovelace: Math.round(Number(form.value.pledgeAda || 0) * 1_000_000),
    fixed_cost_lovelace: Math.round(Number(form.value.fixedCostAda || 0) * 1_000_000),
    margin_numerator: margin.numerator,
    margin_denominator: margin.denominator,
    reward_account_bech32: reward,
    relays: toServerRelays(form.value.relays),
    metadata_url: form.value.metadataUrl.trim() || null,
    metadata_hash_hex: form.value.metadataHashHex.trim() || null,
  }
}

const confirmSendOpen = ref(false)

function openConfirmSend() {
  confirmSendOpen.value = true
}

async function onConfirmSend(payload: { pin: string }) {
  confirmSendOpen.value = false
  await startBuild(payload.pin)
}

async function startBuild(pin: string) {
  emit('request-reset')
  starting.value = true
  try {
    const r = await fetch('/api/pool/build', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...buildBuildBody(), pin }),
    })
    if (!r.ok) {
      const err = await extractError<ErrorCode>(r)
      if (err.code === 'not_configured') {
        emit('not-configured')
        return
      }
      if (err.code === 'not_paired') {
        emit('not-paired')
        return
      }
      throw new Error(err.message)
    }
    const data = await r.json()
    emit('request-built', { request: data.request, ur_fragments: data.ur_fragments, request_fingerprint: data.request_fingerprint || null, body_hash_hex: data.body_hash_hex || null })
  } catch (e: unknown) {
    emit('start-error', e instanceof Error ? e.message : String(e))
  } finally {
    starting.value = false
  }
}
</script>

<style scoped>
.changed-field :deep(.v-field__outline) {
  --v-field-border-opacity: 1;
  color: var(--spo-gold);
}
.changed-field :deep(.v-label) {
  color: var(--spo-gold);
}
</style>

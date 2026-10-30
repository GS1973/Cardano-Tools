<template>
  <div>
  <v-card v-if="result && !submitted">
    <v-card-text>
      <div class="d-flex align-center mb-3" style="gap: 0.6rem;">
        <v-icon icon="mdi-check-circle" color="success" />
        <h3 class="text-subtitle-1 mt-0 mb-0">Signed and ready to submit</h3>
      </div>

      <v-alert v-if="!request" type="warning" density="compact" variant="tonal" class="mb-3">
        Result received, but the original transaction is not in this session. Click <strong>Send to Signer</strong> first to build a fresh tx, then receive the signed result for that build.
      </v-alert>

      <v-table density="compact" class="mb-4">
        <tbody>
          <tr v-if="request"><td class="text-medium-emphasis" style="width: 280px;">Pledge</td>
              <td :class="reqDiffPledge ? 'text-gold' : ''">
                <strong v-if="reqDiffPledge">{{ fmtAda(request.pledge_lovelace) }}</strong>
                <span v-else>{{ fmtAda(request.pledge_lovelace) }}</span></td></tr>
          <tr v-if="request"><td class="text-medium-emphasis">Fixed cost</td>
              <td :class="reqDiffFixedCost ? 'text-gold' : ''">
                <strong v-if="reqDiffFixedCost">{{ fmtAda(request.fixed_cost_lovelace) }}</strong>
                <span v-else>{{ fmtAda(request.fixed_cost_lovelace) }}</span></td></tr>
          <tr v-if="request"><td class="text-medium-emphasis">Margin</td>
              <td :class="reqDiffMargin ? 'text-gold' : ''">
                <strong v-if="reqDiffMargin">{{ fmtMargin(request.margin_numerator, request.margin_denominator) }}</strong>
                <span v-else>{{ fmtMargin(request.margin_numerator, request.margin_denominator) }}</span></td></tr>
          <tr v-if="request"><td class="text-medium-emphasis">Reward stake address</td>
              <td><code class="text-caption">{{ request.reward_account_bech32 }}</code></td></tr>
          <tr v-if="request"><td class="text-medium-emphasis">Relays</td>
              <td><code class="text-caption">{{ fmtRelays(request.relays) }}</code></td></tr>
          <tr v-if="request"><td class="text-medium-emphasis">Metadata URL</td>
              <td><code class="text-caption">{{ request.metadata_url ?? '(none)' }}</code></td></tr>
          <tr v-if="request"><td class="text-medium-emphasis">Change back to payment address</td>
              <td>{{ fmtAda(request.change_to_payment_address_lovelace) }}</td></tr>
          <tr v-if="request"><td class="text-medium-emphasis">Fee</td>
              <td>{{ fmtAda(request.fee_lovelace) }}</td></tr>
          <tr v-if="request"><td class="text-medium-emphasis">Valid until slot</td>
              <td>{{ fmtInt(request.ttl_slot) }}</td></tr>
          <tr><td class="text-medium-emphasis">Witnesses signed</td>
              <td>
                <strong>{{ result.witnesses.length }}</strong>
                <span class="text-caption text-medium-emphasis"> ({{ result.witnesses.map(w => w.role).join(' + ') }})</span>
              </td></tr>
        </tbody>
      </v-table>

      <v-expansion-panels v-model="rawOpen" class="mb-3" variant="accordion">
        <v-expansion-panel>
          <v-expansion-panel-title class="text-body-2">{{ rawOpen === 0 ? 'Hide raw data' : 'Show raw data' }}</v-expansion-panel-title>
          <v-expansion-panel-text>
            <div class="text-caption text-medium-emphasis mb-1">Body hash (Blake2b-256)</div>
            <div class="raw-line mb-3">{{ result.body_hash_hex }}</div>
            <template v-if="request">
              <div class="text-caption text-medium-emphasis mb-1">Tx body CBOR (hex)</div>
              <div class="raw-line mb-3">{{ request.tx_body_cbor_hex }}</div>
            </template>
            <div v-for="w in result.witnesses" :key="w.role" class="mb-3">
              <div class="text-caption text-medium-emphasis mb-1">Witness: {{ w.role }}</div>
              <div class="text-caption text-medium-emphasis">vkey</div>
              <div class="raw-line mb-1">{{ w.vkey_hex }}</div>
              <div class="text-caption text-medium-emphasis">signature</div>
              <div class="raw-line">{{ w.signature_hex }}</div>
            </div>
          </v-expansion-panel-text>
        </v-expansion-panel>
      </v-expansion-panels>

      <v-alert v-if="submitError" type="error" density="compact" variant="tonal" class="mb-3">
        {{ submitError }}
      </v-alert>

      <div class="d-flex justify-end" style="gap: 0.5rem;" v-if="!submitted">
        <v-btn
          variant="text"
          prepend-icon="mdi-restart"
          @click="emit('start-new-session')"
        >Start new session</v-btn>
        <v-btn
          color="primary"
          :loading="finalSubmitting"
          :disabled="!request"
          prepend-icon="mdi-send"
          @click="emit('submit')"
        >Submit to chain</v-btn>
      </div>
    </v-card-text>
  </v-card>

  <v-card v-if="submitted" class="mt-4">
    <v-card-text>
      <div class="d-flex align-center mb-3" style="gap: 0.6rem;">
        <v-icon icon="mdi-check-circle" color="success" />
        <h3 class="text-subtitle-1 mt-0 mb-0">Submitted to Cardano</h3>
      </div>
      <v-table density="compact" class="mb-3">
        <tbody>
          <tr><td class="text-medium-emphasis" style="width: 280px;">Transaction hash</td>
              <td><code class="text-caption">{{ submitted.tx_hash }}</code></td></tr>
          <tr v-if="request">
            <td class="text-medium-emphasis">Pledge</td>
            <td :class="reqDiffPledge ? 'text-gold' : ''">
              <strong v-if="reqDiffPledge">{{ fmtAda(request.pledge_lovelace) }}</strong>
              <span v-else>{{ fmtAda(request.pledge_lovelace) }}</span></td>
          </tr>
          <tr v-if="request">
            <td class="text-medium-emphasis">Fixed cost</td>
            <td :class="reqDiffFixedCost ? 'text-gold' : ''">
              <strong v-if="reqDiffFixedCost">{{ fmtAda(request.fixed_cost_lovelace) }}</strong>
              <span v-else>{{ fmtAda(request.fixed_cost_lovelace) }}</span></td>
          </tr>
          <tr v-if="request">
            <td class="text-medium-emphasis">Margin</td>
            <td :class="reqDiffMargin ? 'text-gold' : ''">
              <strong v-if="reqDiffMargin">{{ fmtMargin(request.margin_numerator, request.margin_denominator) }}</strong>
              <span v-else>{{ fmtMargin(request.margin_numerator, request.margin_denominator) }}</span></td>
          </tr>
          <tr v-if="request">
            <td class="text-medium-emphasis">Fee</td>
            <td>{{ fmtAda(request.fee_lovelace) }}</td>
          </tr>
          <tr><td class="text-medium-emphasis">Signed tx size</td>
              <td>{{ submitted.signed_tx_size_bytes }} bytes</td></tr>
        </tbody>
      </v-table>

      <v-expansion-panels v-if="request && result" v-model="rawOpen" class="mb-3" variant="accordion">
        <v-expansion-panel>
          <v-expansion-panel-title class="text-body-2">{{ rawOpen === 0 ? 'Hide raw data' : 'Show raw data' }}</v-expansion-panel-title>
          <v-expansion-panel-text>
            <div class="text-caption text-medium-emphasis mb-1">Body hash (Blake2b-256)</div>
            <div class="raw-line mb-3">{{ result.body_hash_hex }}</div>
            <div class="text-caption text-medium-emphasis mb-1">Tx body CBOR (hex)</div>
            <div class="raw-line mb-3">{{ request.tx_body_cbor_hex }}</div>
            <div v-for="w in result.witnesses" :key="w.role" class="mb-3">
              <div class="text-caption text-medium-emphasis mb-1">Witness: {{ w.role }}</div>
              <div class="text-caption text-medium-emphasis">vkey</div>
              <div class="raw-line mb-1">{{ w.vkey_hex }}</div>
              <div class="text-caption text-medium-emphasis">signature</div>
              <div class="raw-line">{{ w.signature_hex }}</div>
            </div>
          </v-expansion-panel-text>
        </v-expansion-panel>
      </v-expansion-panels>

      <div class="d-flex" style="gap: 0.5rem;">
        <v-btn
          color="primary"
          variant="tonal"
          prepend-icon="mdi-open-in-new"
          :href="submitted.explorer_url"
          target="_blank"
          rel="noopener"
        >Open on Cardano Explorer</v-btn>
        <v-btn variant="text" prepend-icon="mdi-restart" @click="emit('start-new-session')">Start new session</v-btn>
      </div>
    </v-card-text>
  </v-card>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { fmtAda, fmtInt, fmtMargin, fmtRelays } from '@spo-tools/shared-frontend/utils/format'
import type {
  PoolCurrent,
  PoolUpdateRequest,
  PoolUpdateResult,
  SubmittedTx,
} from '../types/pool-params'

const props = defineProps<{
  current: PoolCurrent | null
  request: PoolUpdateRequest | null
  result: PoolUpdateResult | null
  submitted: SubmittedTx | null
  submitError: string | null
  finalSubmitting: boolean
}>()

const emit = defineEmits<{
  (e: 'submit'): void
  (e: 'start-new-session'): void
}>()

const rawOpen = ref<number | null>(null)

const latestKnown = computed(() => {
  const c = props.current
  if (!c) return null
  const p = c.pending
  if (!p) {
    return {
      pledge_lovelace: c.pledge_lovelace,
      margin: c.margin,
      fixed_cost_lovelace: c.fixed_cost_lovelace,
    }
  }
  return {
    pledge_lovelace: p.pledge_lovelace ?? c.pledge_lovelace,
    margin: p.margin ?? c.margin,
    fixed_cost_lovelace: p.fixed_cost_lovelace ?? c.fixed_cost_lovelace,
  }
})

const reqDiffPledge = computed(() =>
  !!latestKnown.value && !!props.request && Number(props.request.pledge_lovelace) !== latestKnown.value.pledge_lovelace,
)
const reqDiffFixedCost = computed(() =>
  !!latestKnown.value && !!props.request && Number(props.request.fixed_cost_lovelace) !== latestKnown.value.fixed_cost_lovelace,
)
const reqDiffMargin = computed(() => {
  if (!latestKnown.value || !props.request) return false
  const cur = latestKnown.value.margin
  const nw = Number(props.request.margin_numerator) / Number(props.request.margin_denominator)
  return Math.abs(cur - nw) > 1e-9
})
</script>

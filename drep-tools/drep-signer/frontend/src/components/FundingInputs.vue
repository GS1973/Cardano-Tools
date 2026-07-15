<script setup lang="ts">
import { computed } from 'vue'
import { fmtAda } from '@drep-tools/shared-frontend/utils/format'

const props = defineProps<{
  inputs: Array<{
    tx_hash_hex: string
    tx_index: number
    amount_lovelace: string
    address_bech32: string
  }>
  paymentAddress: string
}>()

const total = computed(() =>
  props.inputs.reduce((acc, i) => acc + BigInt(i.amount_lovelace), 0n).toString(),
)
const anyForeign = computed(() =>
  props.inputs.some((i) => i.address_bech32 !== props.paymentAddress),
)
</script>

<template>
  <div v-if="inputs && inputs.length" class="field">
    <div class="field-label">Funding inputs ({{ inputs.length }}) — {{ fmtAda(total) }} total</div>
    <div class="field-value">
      <div
        v-for="(i, idx) in inputs"
        :key="idx"
        class="d-flex align-start justify-space-between"
        style="gap: 0.75rem;"
      >
        <!-- Verification aid: the operator must be able to compare the full tx hash and #index — never truncate. -->
        <code class="text-caption" style="word-break: break-all;">{{ i.tx_hash_hex }}#{{ i.tx_index }}</code>
        <span class="text-caption text-no-wrap">{{ fmtAda(i.amount_lovelace) }}</span>
      </div>
      <div v-if="anyForeign" class="text-error text-caption mt-1">
        ⚠ An input claims an address other than the payment address.
      </div>
      <div v-else class="text-caption text-medium-emphasis mt-1">
        All at <code>{{ paymentAddress }}</code>.
      </div>
    </div>
  </div>
</template>

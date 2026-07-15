<template>
  <SignFlowLayout title="Retire DRep" :not-configured="notConfigured" :not-paired="notPaired">
    <v-card class="mb-4">
      <v-card-text class="d-flex align-center" style="gap: 1rem;">
        <h3 class="text-subtitle-1 mt-0 mb-0">Retire DRep</h3>
        <v-spacer />
        <div class="d-flex" style="gap: 0.5rem;">
          <v-btn size="small" color="primary" :variant="mode === 'send' ? 'tonal' : 'outlined'" :loading="starting" :disabled="!canBuild || !!submitted" prepend-icon="mdi-upload" style="width: 180px;" @click="confirmSendOpen = true">Send to Signer</v-btn>
          <v-btn size="small" color="primary" :variant="mode === 'receive' ? 'tonal' : 'outlined'" :disabled="!request || !!submitted" prepend-icon="mdi-download" style="width: 180px;" @click="enterReceive">Receive from Signer</v-btn>
          <v-btn size="small" variant="tonal" :loading="loading" :disabled="!!submitted" prepend-icon="mdi-refresh" @click="startNewSession">Refresh</v-btn>
        </div>
      </v-card-text>

      <v-card-text v-if="error"><v-alert type="error" density="compact" variant="tonal">{{ error }}</v-alert></v-card-text>
      <v-card-text v-else-if="!preview" class="text-medium-emphasis">Loading…</v-card-text>
      <v-card-text v-else>
        <v-alert type="warning" density="compact" variant="tonal" class="mb-4">Retiring deregisters this DRep and refunds the deposit. Any stake vote-delegated to it stops counting until a new DRep is chosen by those holders.</v-alert>
        <v-alert v-if="!preview.can_cover" type="warning" density="compact" variant="tonal" class="mb-4">Payment address cannot cover the fee ({{ fmtAda(preview.estimated_fee_lovelace) }}).</v-alert>

        <v-table density="compact" class="mb-3"><tbody>
          <tr><td class="text-medium-emphasis" style="width: 280px;">DRep id</td><td><code class="text-caption">{{ preview.drep_id }}</code></td></tr>
          <tr><td class="text-medium-emphasis">Payment address</td><td><code class="text-caption">{{ preview.payment_address }}</code></td></tr>
          <tr><td class="text-medium-emphasis">Payment total</td><td>{{ fmtAda(preview.payment_utxo_total_lovelace) }}</td></tr>
          <tr><td class="text-medium-emphasis">Deposit refund</td><td><strong>{{ fmtAda(preview.deposit_refund_lovelace) }}</strong></td></tr>
          <tr><td class="text-medium-emphasis">Estimated fee</td><td>{{ fmtAda(preview.estimated_fee_lovelace) }}</td></tr>
        </tbody></v-table>
      </v-card-text>
    </v-card>

    <SignFlowPanels :flow="flow" @new-session="startNewSession">
      <template #summary>
        <tr v-if="request"><td class="text-medium-emphasis" style="width: 280px;">Retire DRep</td><td><code class="text-caption">{{ request.drep_id_bech32 }}</code></td></tr>
        <tr v-if="request"><td class="text-medium-emphasis">Deposit refund</td><td><strong>{{ fmtAda(request.deposit_refund_lovelace) }}</strong></td></tr>
        <tr v-if="request"><td class="text-medium-emphasis">Change back to payment</td><td>{{ fmtAda(request.change_to_payment_address_lovelace) }}</td></tr>
        <tr v-if="request"><td class="text-medium-emphasis">Fee</td><td>{{ fmtAda(request.fee_lovelace) }}</td></tr>
        <tr v-if="result"><td class="text-medium-emphasis">Witnesses signed</td><td><strong>{{ result.witnesses.length }}</strong> <span class="text-caption text-medium-emphasis">({{ witnessRoles }})</span></td></tr>
      </template>
      <template #submitted-summary>
        <tr v-if="request"><td class="text-medium-emphasis">Retired DRep</td><td><code class="text-caption">{{ request.drep_id_bech32 }}</code></td></tr>
      </template>
    </SignFlowPanels>

    <PreSendConfirm v-model="confirmSendOpen" title="Confirm DRep retirement" @confirm="onConfirmSend">
      <p class="text-body-2 text-medium-emphasis mb-2">You are about to retire <code v-if="preview">{{ preview.drep_id }}</code> and refund its deposit (<strong v-if="preview">{{ fmtAda(preview.deposit_refund_lovelace) }}</strong>). Your DRep key signs.</p>
    </PreSendConfirm>
  </SignFlowLayout>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { fmtAda } from '@drep-tools/shared-frontend/utils/format'
import { extractError } from '@drep-tools/shared-frontend/utils/error'
import type { ErrorCode } from '@drep-tools/shared-frontend/types/errors'
import SignFlowLayout from '../components/SignFlowLayout.vue'
import SignFlowPanels from '../components/SignFlowPanels.vue'
import PreSendConfirm from '@drep-tools/shared-frontend/components/PreSendConfirm.vue'
import { useSignFlow } from '../composables/useSignFlow'

const preview = ref<any>(null)
const error = ref<string | null>(null)
const loading = ref(false)
const notConfigured = ref(false)
const notPaired = ref(false)
const confirmSendOpen = ref(false)

const flow = useSignFlow('/api/retire')
const { mode, starting, submitted, request, result, enterReceive } = flow
flow.setGuards(() => { notConfigured.value = true }, () => { notPaired.value = true })

const canBuild = computed(() => !!preview.value && preview.value.can_cover)
const witnessRoles = computed(() => (result.value?.witnesses ?? []).map((w: any) => w.role).join(' + '))

async function load() {
  loading.value = true
  error.value = null
  try {
    const r = await fetch('/api/retire/preview')
    if (!r.ok) {
      const err = await extractError<ErrorCode>(r)
      if (err.code === 'not_configured') { notConfigured.value = true; return }
      if (err.code === 'not_paired') { notPaired.value = true; return }
      throw new Error(err.message)
    }
    preview.value = await r.json()
  } catch (e: unknown) {
    error.value = e instanceof Error ? e.message : String(e)
  } finally {
    loading.value = false
  }
}

async function onConfirmSend(payload: { pin: string }) {
  confirmSendOpen.value = false
  await flow.start({ pin: payload.pin })
}

function startNewSession() { flow.reset(); load() }
onMounted(load)
</script>

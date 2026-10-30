<template>
  <SignFlowLayout title="Update / refresh DRep" :not-configured="notConfigured" :not-paired="notPaired">
    <v-card class="mb-4">
      <v-card-text class="d-flex align-center" style="gap: 1rem;">
        <h3 class="text-subtitle-1 mt-0 mb-0">Update / refresh DRep</h3>
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
        <v-alert v-if="!preview.is_registered" type="warning" density="compact" variant="tonal" class="mb-4">This DRep is not registered on-chain. Register first.</v-alert>
        <v-alert v-else type="info" density="compact" variant="tonal" class="mb-4">An update resets the <strong>drep_activity</strong> counter (20 epochs): a bare keep-alive with no new manifest is valid and keeps your voting power from going dormant.</v-alert>

        <v-table density="compact" class="mb-3"><tbody>
          <tr><td class="text-medium-emphasis" style="width: 280px;">DRep id</td><td><code class="text-caption">{{ preview.drep_id }}</code></td></tr>
          <tr><td class="text-medium-emphasis">Payment address</td><td><code class="text-caption">{{ preview.payment_address }}</code></td></tr>
          <tr><td class="text-medium-emphasis">Payment total</td><td>{{ fmtAda(preview.payment_utxo_total_lovelace) }}</td></tr>
          <tr><td class="text-medium-emphasis">Estimated fee</td><td>{{ fmtAda(preview.estimated_fee_lovelace) }}</td></tr>
          <tr v-if="preview.current_anchor_url"><td class="text-medium-emphasis">Current manifest</td><td><code class="text-caption">{{ preview.current_anchor_url }}</code></td></tr>
        </tbody></v-table>

        <template v-if="mode !== 'receive'">
          <h3 class="text-subtitle-1 mt-2 mb-2">New manifest (CIP-119, optional)</h3>
          <template v-if="preview.manifest_base_url">
            <p class="text-caption text-medium-emphasis mb-2">Enter just the file name. The on-chain URL is composed from your configured base. Host the updated document first, then compute the hash. Leave the file name empty for a bare keep-alive (no anchor).</p>
            <v-text-field v-model="manifestFile" label="Manifest file name" placeholder="drep.jsonld" density="compact" variant="outlined" hide-details class="mb-2" />
            <p v-if="composedManifestUrl" class="text-caption text-medium-emphasis mb-2">Full URL (goes on-chain): <code style="word-break: break-all;">{{ composedManifestUrl }}</code></p>
            <div class="d-flex align-start" style="gap: 0.5rem;">
              <v-text-field v-model="anchorHash" label="Manifest hash (64 hex chars)" placeholder="blake2b-256 of the document" density="compact" variant="outlined" hide-details />
              <v-btn size="small" variant="outlined" :loading="hashing" :disabled="!composedManifestUrl" prepend-icon="mdi-pound" class="mt-1" @click="computeHash">Compute hash</v-btn>
            </div>
            <v-alert v-if="hashError" type="error" density="compact" variant="tonal" class="mt-2">{{ hashError }}</v-alert>
          </template>
          <v-alert v-else type="info" density="compact" variant="tonal">To set a manifest, add a <strong>Manifest base URL</strong> in Setup first. A bare keep-alive (no manifest) works without it.</v-alert>
        </template>
      </v-card-text>
    </v-card>

    <SignFlowPanels :flow="flow" @new-session="startNewSession">
      <template #summary>
        <tr v-if="request"><td class="text-medium-emphasis" style="width: 280px;">Update DRep</td><td><code class="text-caption">{{ request.drep_id_bech32 }}</code></td></tr>
        <tr v-if="request"><td class="text-medium-emphasis">Manifest</td><td><span v-if="request.anchor"><code class="text-caption">{{ request.anchor.url }}</code></span><span v-else class="text-caption text-medium-emphasis">(keep-alive, no anchor)</span></td></tr>
        <tr v-if="request"><td class="text-medium-emphasis">Change back to payment</td><td>{{ fmtAda(request.change_to_payment_address_lovelace) }}</td></tr>
        <tr v-if="request"><td class="text-medium-emphasis">Fee</td><td>{{ fmtAda(request.fee_lovelace) }}</td></tr>
        <tr v-if="result"><td class="text-medium-emphasis">Witnesses signed</td><td><strong>{{ result.witnesses.length }}</strong> <span class="text-caption text-medium-emphasis">({{ witnessRoles }})</span></td></tr>
      </template>
      <template #submitted-summary>
        <tr v-if="request"><td class="text-medium-emphasis">Updated DRep</td><td><code class="text-caption">{{ request.drep_id_bech32 }}</code></td></tr>
      </template>
    </SignFlowPanels>

    <PreSendConfirm v-model="confirmSendOpen" title="Confirm DRep update" @confirm="onConfirmSend">
      <p class="text-body-2 text-medium-emphasis mb-2">You are about to update <code v-if="preview">{{ preview.drep_id }}</code> (resets the activity counter, sets the manifest anchor to {{ composedManifestUrl ? 'the new document' : 'null: keep-alive' }}). Your DRep key signs.</p>
    </PreSendConfirm>
  </SignFlowLayout>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
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
const manifestFile = ref('')
const anchorHash = ref('')
const hashing = ref(false)
const hashError = ref<string | null>(null)
const confirmSendOpen = ref(false)

const flow = useSignFlow('/api/update')
const { mode, starting, submitted, request, result, enterReceive } = flow
flow.setGuards(() => { notConfigured.value = true }, () => { notPaired.value = true })

const canBuild = computed(() => !!preview.value && preview.value.can_cover && preview.value.is_registered)
const witnessRoles = computed(() => (result.value?.witnesses ?? []).map((w: any) => w.role).join(' + '))

const composedManifestUrl = computed(() => {
  const base = (preview.value?.manifest_base_url || '').replace(/\/+$/, '')
  const file = manifestFile.value.trim().replace(/^\/+/, '')
  return base && file ? `${base}/${file}` : ''
})

async function computeHash() {
  if (!composedManifestUrl.value) return
  hashing.value = true
  hashError.value = null
  try {
    const r = await fetch('/api/manifest-hash', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: composedManifestUrl.value }),
    })
    const d = await r.json()
    if (d.status === 'error') { hashError.value = d.message; return }
    anchorHash.value = d.hash_hex
  } catch (e: unknown) {
    hashError.value = e instanceof Error ? e.message : String(e)
  } finally {
    hashing.value = false
  }
}

async function load() {
  loading.value = true
  error.value = null
  try {
    const r = await fetch('/api/update/preview')
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

watch([manifestFile, anchorHash], () => flow.invalidate())

async function onConfirmSend(payload: { pin: string }) {
  confirmSendOpen.value = false
  await flow.start({
    pin: payload.pin,
    anchor_url: composedManifestUrl.value || null,
    anchor_hash: anchorHash.value.trim() || null,
  })
}

function startNewSession() { flow.reset(); load() }
onMounted(load)
</script>

<template>
  <v-card class="mb-4"><v-card-title>New address</v-card-title></v-card>

  <NotPairedCard v-if="notPaired" />

  <template v-else>
    <v-card class="mb-4">
      <v-card-text>
        <h3 class="text-subtitle-1 mt-0 mb-2">Create a new wallet address</h3>
        <p class="text-body-2 text-medium-emphasis mb-2">
          Generation happens entirely on the air-gapped signer: the keys never
          touch this machine. On the signer's Setup page, use
          <strong>Generate new wallet keys</strong>, then scan the export QR it
          shows (or paste its UR fragments) below. This online tool only ingests
          the public address so you can fund and watch it.
        </p>
      </v-card-text>
    </v-card>

    <ReceiveQrPanel
      v-if="!result"
      ref="scannerRef"
      v-model:result-input="resultInput"
      v-model:camera-enlarged="cameraEnlarged"
      :retrying-camera="retryingCamera"
      :result-error="resultError"
      :submitting="submitting"
      title="Scan the new-address export from the signer"
      submit-label="Import address"
      @scanner-complete="onComplete"
      @scanner-complete-enlarged="onCompleteEnlarged"
      @scanner-error="onScannerError"
      @retry-camera="retry"
      @submit="submitPasted"
    >
      Scan the animated QR shown on the signer after key generation, or paste its UR fragments.
    </ReceiveQrPanel>

    <v-card v-if="result">
      <v-card-text>
        <div class="d-flex align-center mb-3" style="gap: 0.6rem;">
          <v-icon icon="mdi-check-circle" color="success" />
          <h3 class="text-subtitle-1 mt-0 mb-0">New address imported</h3>
        </div>
        <v-table density="compact" class="mb-3"><tbody>
          <tr>
            <td class="text-medium-emphasis" style="width: 220px;">Payment address</td>
            <td>
              <div class="d-flex align-center" style="gap: 0.5rem;">
                <code class="text-caption" style="word-break: break-all;">{{ result.base_address_bech32 }}</code>
                <v-btn size="x-small" variant="text" prepend-icon="mdi-content-copy" @click="copyText(result.base_address_bech32, 'Payment address')">Copy</v-btn>
              </div>
            </td>
          </tr>
          <tr>
            <td class="text-medium-emphasis">Stake address</td>
            <td>
              <div class="d-flex align-center" style="gap: 0.5rem;">
                <code class="text-caption" style="word-break: break-all;">{{ result.stake_address_bech32 }}</code>
                <v-btn size="x-small" variant="text" prepend-icon="mdi-content-copy" @click="copyText(result.stake_address_bech32, 'Stake address')">Copy</v-btn>
              </div>
            </td>
          </tr>
          <tr><td class="text-medium-emphasis">Payment key hash</td><td><code class="text-caption" style="word-break: break-all;">{{ result.payment_keyhash_hex }}</code></td></tr>
          <tr><td class="text-medium-emphasis">Stake key hash</td><td><code class="text-caption" style="word-break: break-all;">{{ result.stake_keyhash_hex }}</code></td></tr>
        </tbody></v-table>

        <h3 class="text-subtitle-1 mt-2 mb-2">Save to address book</h3>
        <p class="text-caption text-medium-emphasis mb-2">
          Add this as one of your own wallets so you can fund it, send from it and delegate it.
          Its signing keys stay on the signer.
        </p>
        <div class="d-flex align-end" style="gap: 0.5rem;">
          <v-text-field
            v-model="saveLabel" label="Label for this wallet" placeholder="e.g. Cold wallet 2"
            density="compact" variant="outlined" hide-details style="max-width: 320px;"
          />
          <v-btn color="primary" :loading="saving" :disabled="!saveLabel.trim()" prepend-icon="mdi-book-plus" @click="saveToBook">Save to book</v-btn>
        </div>
        <v-alert v-if="saveError" type="error" density="compact" variant="tonal" class="mt-3">{{ saveError }}</v-alert>

        <div class="d-flex justify-end mt-3">
          <v-btn variant="text" prepend-icon="mdi-restart" @click="reset">Import another</v-btn>
        </div>
      </v-card-text>
    </v-card>
  </template>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import ReceiveQrPanel from '@wallet-tools/shared-frontend/components/ReceiveQrPanel.vue'
import { useScannerControl } from '@wallet-tools/shared-frontend/composables/useScannerControl'
import { useNotificationStore } from '@wallet-tools/shared-frontend/stores/notification'
import { extractError } from '@wallet-tools/shared-frontend/utils/error'
import type { ErrorCode } from '@wallet-tools/shared-frontend/types/errors'
import type { NewAddressExport } from '@wallet-tools/shared-frontend/types/wire'
import NotPairedCard from '../components/NotPairedCard.vue'

interface BookEntry { label: string; address: string; kind: string }

const notify = useNotificationStore()
const { scannerRef, retryingCamera, retry } = useScannerControl()

const resultInput = ref('')
const cameraEnlarged = ref(false)
const resultError = ref<string | null>(null)
const submitting = ref(false)
const notPaired = ref(false)
const result = ref<NewAddressExport | null>(null)
const saveLabel = ref('')
const saving = ref(false)
const saveError = ref<string | null>(null)

async function receive(fragments: string[]) {
  submitting.value = true
  resultError.value = null
  try {
    if (!fragments.length) throw new Error('no UR fragments to import')
    const r = await fetch('/api/new-address/receive', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ur_fragments: fragments }),
    })
    if (!r.ok) {
      const err = await extractError<ErrorCode>(r)
      if (err.code === 'not_paired') { notPaired.value = true; return }
      throw new Error(err.message)
    }
    result.value = await r.json()
    notify.success('New address imported')
  } catch (e: unknown) {
    resultError.value = e instanceof Error ? e.message : String(e)
  } finally {
    submitting.value = false
  }
}

async function onComplete(fragments: string[]) { await receive(fragments) }
async function onCompleteEnlarged(fragments: string[]) { cameraEnlarged.value = false; await receive(fragments) }
function onScannerError(m: string) { resultError.value = m }
async function submitPasted() {
  const fragments = resultInput.value.split('\n').map(s => s.trim()).filter(Boolean)
  await receive(fragments)
}

async function saveToBook() {
  if (!result.value) return
  saving.value = true
  saveError.value = null
  try {
    const cfg = await fetch('/api/wallet-config')
    if (!cfg.ok) throw new Error(`HTTP ${cfg.status}`)
    const d = await cfg.json()
    const entries: BookEntry[] = (d.address_book || []).map((e: BookEntry) => ({ label: e.label, address: e.address, kind: e.kind }))
    const addr = result.value.base_address_bech32
    if (entries.some((e) => e.address === addr)) {
      notify.success('This address is already in the address book')
      return
    }
    entries.push({ label: saveLabel.value.trim(), address: addr, kind: 'own' })
    const r = await fetch('/api/address-book', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ entries }),
    })
    if (!r.ok) {
      const err = await extractError(r)
      throw new Error(err.message)
    }
    notify.success('Saved to address book')
    saveLabel.value = ''
  } catch (e: unknown) {
    saveError.value = e instanceof Error ? e.message : String(e)
  } finally {
    saving.value = false
  }
}

function reset() {
  result.value = null
  resultInput.value = ''
  resultError.value = null
  saveLabel.value = ''
  saveError.value = null
}

async function copyText(text: string, label = 'Value') {
  try {
    await navigator.clipboard.writeText(text)
    notify.success(`${label} copied to clipboard`)
  } catch {
    notify.error('Could not copy')
  }
}

async function checkPaired() {
  try {
    const r = await fetch('/api/wallet-config')
    if (!r.ok) return
    const d = await r.json()
    notPaired.value = !d.paired
  } catch { /* transient */ }
}

onMounted(checkPaired)
</script>

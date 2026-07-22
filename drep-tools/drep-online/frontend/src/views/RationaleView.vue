<template>
  <SignFlowLayout title="Rationale (CIP-136)" :not-configured="notConfigured" :not-paired="notPaired">
    <v-card class="mb-4">
      <v-card-text class="d-flex align-center" style="gap: 1rem;">
        <h3 class="text-subtitle-1 mt-0 mb-0">Witness a vote rationale</h3>
        <v-spacer />
        <div class="d-flex" style="gap: 0.5rem;">
          <v-btn size="small" color="primary" :variant="mode === 'send' ? 'tonal' : 'outlined'" :loading="starting" :disabled="!canSend" prepend-icon="mdi-upload" style="width: 180px;" @click="confirmSendOpen = true">Send to Signer</v-btn>
          <v-btn size="small" color="primary" :variant="mode === 'receive' ? 'tonal' : 'outlined'" :disabled="!sent || !!witness" prepend-icon="mdi-download" style="width: 180px;" @click="enterReceive">Receive from Signer</v-btn>
          <v-btn size="small" variant="tonal" prepend-icon="mdi-refresh" @click="startNewSession">Refresh</v-btn>
        </div>
      </v-card-text>

      <v-card-text>
        <p class="text-body-2 text-medium-emphasis mb-3">
          Load the CIP-136 rationale you wrote by hand. This adds your DRep's author witness so the anchor renders as a proper rationale instead of raw JSON. Register and update manifests do not need this.
        </p>

        <v-file-input :model-value="file" label="Rationale file (.jsonld)" accept=".jsonld,.json,application/json" density="compact" variant="outlined" hide-details prepend-icon="mdi-file-document-outline" class="mb-3" @update:model-value="onFile" />

        <v-alert v-if="loadError" type="error" density="compact" variant="tonal" class="mb-3">{{ loadError }}</v-alert>

        <template v-if="doc">
          <v-table density="compact" class="mb-3"><tbody>
            <tr><td class="text-medium-emphasis" style="width: 280px;">Author</td><td>{{ checks.authorName || '(unnamed)' }}</td></tr>
            <tr><td class="text-medium-emphasis">Witness as DRep</td><td><code v-if="drepId" class="text-caption">{{ drepId }}</code><span v-else class="text-caption text-medium-emphasis">(configured in Setup)</span></td></tr>
            <tr v-if="bodyHashHex"><td class="text-medium-emphasis">Body hash (Blake2b-256)</td><td><code class="text-caption">{{ bodyHashHex }}</code></td></tr>
          </tbody></v-table>
          <v-alert v-if="checks.fixedLinkType" type="info" density="compact" variant="tonal" class="mb-2">Rewrote a references <code>@type "Link"</code> to <code>"Other"</code>, required for a vote rationale to render.</v-alert>
          <v-alert v-for="(e, i) in checks.errors" :key="i" type="warning" density="compact" variant="tonal" class="mb-2">{{ e }}</v-alert>
          <v-alert v-if="canonError" type="error" density="compact" variant="tonal" class="mb-2">{{ canonError }}</v-alert>
        </template>
      </v-card-text>
    </v-card>

    <SendQrPanel v-if="sent && mode === 'send'" ref="sendPanelRef" :qr-data-url="qrDataUrl" :qr-fragments="qrFragments" :qr-index="qrIndex" :fingerprint="requestFingerprint" title="Witness request" @copy="qr.copyToClipboard" />

    <ReceiveQrPanel v-if="mode === 'receive'" ref="scannerRef" v-model:result-input="resultInput" v-model:camera-enlarged="cameraEnlarged" :retrying-camera="retryingCamera" :result-error="resultError" :submitting="submitting" title="Receive signed witness" @scanner-complete="onScanned" @scanner-complete-enlarged="onScannedEnlarged" @scanner-error="(m: string) => (resultError = m)" @retry-camera="retryCamera" @submit="submitPasted" />

    <v-card v-if="witness" class="mt-2">
      <v-card-text>
        <div class="d-flex align-center mb-3" style="gap: 0.6rem;">
          <v-icon icon="mdi-check-circle" color="success" />
          <h3 class="text-subtitle-1 mt-0 mb-0">Witnessed, ready to publish</h3>
        </div>
        <p class="text-body-2 text-medium-emphasis mb-3">
          Download the finished rationale and publish it at your manifest URL. Then cast the vote on the Vote screen; it computes the anchor hash from the published file for you.
        </p>
        <v-table density="compact" class="mb-3"><tbody>
          <tr><td class="text-medium-emphasis" style="width: 280px;">Witness public key</td><td><code class="text-caption">{{ witness.witness.public_key_hex }}</code></td></tr>
          <tr><td class="text-medium-emphasis">Body hash signed</td><td><code class="text-caption">{{ witness.body_hash_hex }}</code></td></tr>
        </tbody></v-table>
        <div class="d-flex justify-end" style="gap: 0.5rem;">
          <v-btn variant="text" prepend-icon="mdi-restart" @click="startNewSession">Start new</v-btn>
          <v-btn color="primary" prepend-icon="mdi-download" @click="download">Download witnessed file</v-btn>
        </div>
      </v-card-text>
    </v-card>

    <PreSendConfirm v-model="confirmSendOpen" title="Confirm rationale witness" @confirm="onConfirmSend">
      <p class="text-body-2 text-medium-emphasis mb-2">Your DRep key will sign the canonical body of this rationale, a CIP-100 author witness, not a transaction.</p>
    </PreSendConfirm>
  </SignFlowLayout>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { extractError } from '@drep-tools/shared-frontend/utils/error'
import type { ErrorCode } from '@drep-tools/shared-frontend/types/errors'
import type { DRepWitnessResult } from '@drep-tools/shared-frontend/types/wire'
import SignFlowLayout from '../components/SignFlowLayout.vue'
import SendQrPanel from '@drep-tools/shared-frontend/components/SendQrPanel.vue'
import ReceiveQrPanel from '@drep-tools/shared-frontend/components/ReceiveQrPanel.vue'
import PreSendConfirm from '@drep-tools/shared-frontend/components/PreSendConfirm.vue'
import { useQrCarousel } from '@drep-tools/shared-frontend/composables/useQrCarousel'
import { useScannerControl } from '@drep-tools/shared-frontend/composables/useScannerControl'
import { useNotificationStore } from '@drep-tools/shared-frontend/stores/notification'
import { prepareRationale, canonicalBody, type RationaleChecks } from '../canonicalize'

const notify = useNotificationStore()
const qr = useQrCarousel()
const { dataUrl: qrDataUrl, fragments: qrFragments, index: qrIndex } = qr
const scanner = useScannerControl()
const { scannerRef, retryingCamera, retry: retryCamera } = scanner

const file = ref<any>(null)
const fileName = ref('rationale.jsonld')
const doc = ref<any>(null)
const checks = ref<RationaleChecks>({ fixedLinkType: false, authorName: null, errors: [] })
const canonical = ref<string | null>(null)
const canonError = ref<string | null>(null)
const loadError = ref<string | null>(null)
const drepId = ref<string | null>(null)
const bodyHashHex = ref<string | null>(null)

const mode = ref<'idle' | 'send' | 'receive'>('idle')
const starting = ref(false)
const submitting = ref(false)
const sent = ref(false)
const requestFingerprint = ref<string | null>(null)
const resultInput = ref('')
const cameraEnlarged = ref(false)
const resultError = ref<string | null>(null)
const witness = ref<DRepWitnessResult | null>(null)
const confirmSendOpen = ref(false)
const notConfigured = ref(false)
const notPaired = ref(false)
const sendPanelRef = ref<any>(null)

const canSend = computed(() => !!canonical.value && checks.value.errors.length === 0 && !witness.value)

function reset(clearFile: boolean) {
  qr.reset()
  mode.value = 'idle'
  sent.value = false
  witness.value = null
  requestFingerprint.value = null
  resultInput.value = ''
  resultError.value = null
  cameraEnlarged.value = false
  bodyHashHex.value = null
  loadError.value = null
  canonError.value = null
  if (clearFile) {
    file.value = null
    doc.value = null
    canonical.value = null
    checks.value = { fixedLinkType: false, authorName: null, errors: [] }
  }
}

async function onFile(f: any) {
  reset(true)
  const chosen = Array.isArray(f) ? f[0] : f
  if (!chosen) return
  file.value = chosen
  fileName.value = chosen.name || 'rationale.jsonld'
  try {
    const parsedDoc = JSON.parse(await chosen.text())
    checks.value = prepareRationale(parsedDoc)
    doc.value = parsedDoc
    if (checks.value.errors.length === 0) {
      try {
        canonical.value = await canonicalBody(parsedDoc)
      } catch (e: unknown) {
        canonError.value = 'Canonicalization failed: ' + (e instanceof Error ? e.message : String(e))
        canonical.value = null
      }
    }
  } catch (e: unknown) {
    loadError.value = 'Could not read or parse the file: ' + (e instanceof Error ? e.message : String(e))
  }
}

async function loadConfig() {
  try {
    const r = await fetch('/api/drep-config')
    if (r.ok) {
      const c: any = await r.json()
      drepId.value = c?.drep_id ?? c?.config?.drep_id ?? null
    }
  } catch {
    /* display-only; leave null */
  }
}

async function onConfirmSend(payload: { pin: string }) {
  confirmSendOpen.value = false
  if (!canonical.value) return
  reset(false)
  mode.value = 'send'
  starting.value = true
  try {
    const r = await fetch('/api/witness/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ canonical_body: canonical.value, pin: payload.pin }),
    })
    if (!r.ok) {
      const err = await extractError<ErrorCode>(r)
      if (err.code === 'not_configured') { notConfigured.value = true; return }
      if (err.code === 'not_paired') { notPaired.value = true; return }
      throw new Error(err.message)
    }
    const data: any = await r.json()
    drepId.value = data.request?.drep_id_bech32 ?? drepId.value
    bodyHashHex.value = data.body_hash_hex ?? null
    qrFragments.value = data.ur_fragments
    requestFingerprint.value = data.request_fingerprint ?? null
    qrIndex.value = 0
    await qr.renderCurrentFrame()
    qr.startCycle()
    sent.value = true
  } catch (e: unknown) {
    loadError.value = e instanceof Error ? e.message : String(e)
    mode.value = 'idle'
  } finally {
    starting.value = false
  }
}

function enterReceive() {
  qr.reset()
  resultInput.value = ''
  resultError.value = null
  mode.value = 'receive'
}

async function onScanned(fragments: string[]) { await receive(fragments) }
async function onScannedEnlarged(fragments: string[]) { cameraEnlarged.value = false; await receive(fragments) }
async function submitPasted() {
  await receive(resultInput.value.split('\n').map((s) => s.trim()).filter(Boolean))
}

async function receive(fragments: string[]) {
  submitting.value = true
  resultError.value = null
  try {
    if (!fragments.length) throw new Error('no UR fragments to submit')
    const r = await fetch('/api/witness/result', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ur_fragments: fragments }),
    })
    if (!r.ok) {
      const err = await extractError<ErrorCode>(r)
      if (err.code === 'not_paired') { notPaired.value = true; return }
      throw new Error(err.message)
    }
    const data: DRepWitnessResult = await r.json()
    if (!bodyHashHex.value || data.body_hash_hex !== bodyHashHex.value) {
      throw new Error('signed witness does not match the pending request (body hash differs), scan the result for the request shown above')
    }
    witness.value = data
    qr.stopCycle()
    notify.success('Author witness received')
  } catch (e: unknown) {
    resultError.value = e instanceof Error ? e.message : String(e)
  } finally {
    submitting.value = false
  }
}

function download() {
  if (!doc.value || !witness.value) return
  const out = JSON.parse(JSON.stringify(doc.value))
  out.authors[0].witness = {
    witnessAlgorithm: witness.value.witness.witness_algorithm,
    publicKey: witness.value.witness.public_key_hex,
    signature: witness.value.witness.signature_hex,
  }
  const text = JSON.stringify(out, null, 2) + '\n'
  const url = URL.createObjectURL(new Blob([text], { type: 'application/ld+json' }))
  const a = document.createElement('a')
  a.href = url
  a.download = fileName.value
  a.click()
  URL.revokeObjectURL(url)
}

function startNewSession() {
  reset(true)
  loadConfig()
}

watch(file, () => {
  /* editing the chosen file after a build invalidates any pending QR */
  if (sent.value || witness.value) reset(false)
})

onMounted(loadConfig)
</script>

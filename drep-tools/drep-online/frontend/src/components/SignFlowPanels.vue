<template>
  <v-card v-if="startError" class="mb-4">
    <v-card-text><v-alert type="error" density="compact" variant="tonal">{{ startError }}</v-alert></v-card-text>
  </v-card>

  <SendQrPanel
    ref="sendPanelRef"
    v-if="request && mode === 'send'"
    :qr-data-url="qrDataUrl"
    :qr-fragments="qrFragments"
    :qr-index="qrIndex"
    :fingerprint="requestFingerprint"
    title="Request"
    @copy="copyUr"
  />

  <ReceiveQrPanel
    v-if="mode === 'receive'"
    ref="scannerRef"
    v-model:result-input="resultInput"
    v-model:camera-enlarged="cameraEnlarged"
    :retrying-camera="retryingCamera"
    :result-error="resultError"
    :submitting="submitting"
    title="Receive signed result"
    @scanner-complete="onComplete"
    @scanner-complete-enlarged="onCompleteEnlarged"
    @scanner-error="onScannerError"
    @retry-camera="retryCamera"
    @submit="submitPasted"
  />

  <v-card ref="resultCardRef" v-if="result && !submitted">
    <v-card-text>
      <div class="d-flex align-center mb-3" style="gap: 0.6rem;">
        <v-icon icon="mdi-check-circle" color="success" />
        <h3 class="text-subtitle-1 mt-0 mb-0">Signed and ready to submit</h3>
      </div>

      <v-table density="compact" class="mb-4"><tbody><slot name="summary" /></tbody></v-table>

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
              <div class="text-caption text-medium-emphasis mb-1">Witness — {{ w.role }}</div>
              <div class="text-caption text-medium-emphasis">vkey</div>
              <div class="raw-line mb-1">{{ w.vkey_hex }}</div>
              <div class="text-caption text-medium-emphasis">signature</div>
              <div class="raw-line">{{ w.signature_hex }}</div>
            </div>
          </v-expansion-panel-text>
        </v-expansion-panel>
      </v-expansion-panels>

      <v-alert v-if="submitError" type="error" density="compact" variant="tonal" class="mb-3">{{ submitError }}</v-alert>

      <div class="d-flex justify-end" style="gap: 0.5rem;">
        <v-btn variant="text" prepend-icon="mdi-restart" @click="onNewSession">Start new session</v-btn>
        <v-btn color="primary" :loading="finalSubmitting" :disabled="!request" prepend-icon="mdi-send" @click="submit">Submit to chain</v-btn>
      </div>
    </v-card-text>
  </v-card>

  <v-card v-if="submitted" class="mt-4">
    <v-card-text>
      <div class="d-flex align-center mb-3" style="gap: 0.6rem;">
        <v-icon icon="mdi-check-circle" color="success" />
        <h3 class="text-subtitle-1 mt-0 mb-0">Submitted to Cardano</h3>
      </div>
      <v-table density="compact" class="mb-3"><tbody>
        <tr><td class="text-medium-emphasis" style="width: 280px;">Transaction hash</td>
            <td><code class="text-caption">{{ submitted.tx_hash }}</code></td></tr>
        <slot name="submitted-summary" />
        <tr><td class="text-medium-emphasis">Signed tx size</td>
            <td>{{ submitted.signed_tx_size_bytes }} bytes</td></tr>
      </tbody></v-table>
      <div class="d-flex" style="gap: 0.5rem;">
        <v-btn color="primary" variant="tonal" prepend-icon="mdi-open-in-new" :href="submitted.explorer_url" target="_blank" rel="noopener">Open on Cardano Explorer</v-btn>
        <v-btn variant="text" prepend-icon="mdi-restart" @click="onNewSession">Start new session</v-btn>
      </div>
    </v-card-text>
  </v-card>
</template>

<script setup lang="ts">
import { ref, watch, nextTick } from 'vue'
import SendQrPanel from '@drep-tools/shared-frontend/components/SendQrPanel.vue'
import ReceiveQrPanel from '@drep-tools/shared-frontend/components/ReceiveQrPanel.vue'

const props = defineProps<{ flow: any }>()
const emit = defineEmits<{ (e: 'new-session'): void }>()

const f = props.flow
const { mode, request, result, submitted, startError, resultError, submitError, submitting, finalSubmitting, requestFingerprint, resultInput, cameraEnlarged, rawOpen } = f
const { dataUrl: qrDataUrl, fragments: qrFragments, index: qrIndex, copyToClipboard: copyUr } = f.qr
// `scannerRef` must be a setup binding so the template's `ref="scannerRef"`
// wires the panel's exposed `retry` into the flow's scanner control.
const { scannerRef, retryingCamera, retry: retryCamera } = f.scanner

// Move focus to the panel that just became relevant, mirroring the SPO flow:
// the request QR after Send, the scanner after Receive, and the result card
// once a signed result arrives.
const sendPanelRef = ref<any>(null)
const resultCardRef = ref<any>(null)
function scrollToPanel(elRef: any) {
  nextTick(() => {
    elRef.value?.$el?.scrollIntoView?.({ behavior: 'smooth', block: 'start' })
  })
}
watch(request, (r: any) => { if (r && mode.value === 'send') scrollToPanel(sendPanelRef) })
watch(mode, (m: any) => { if (m === 'receive') scrollToPanel(scannerRef) })
watch(result, (r: any) => { if (r) scrollToPanel(resultCardRef) })

async function onComplete(fragments: string[]) { await f.receive(fragments) }
async function onCompleteEnlarged(fragments: string[]) { cameraEnlarged.value = false; await f.receive(fragments) }
function onScannerError(m: string) { resultError.value = m }
async function submitPasted() { await f.submitPasted() }
async function submit() { await f.submit() }
function onNewSession() { emit('new-session') }
</script>

<style scoped>
.raw-line {
  font-family: monospace;
  font-size: 0.75rem;
  word-break: break-all;
  color: rgba(255, 255, 255, 0.75);
}
</style>

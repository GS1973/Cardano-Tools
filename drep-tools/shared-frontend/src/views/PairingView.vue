<template>
  <v-card class="mb-4">
    <v-card-title>Pairing</v-card-title>
  </v-card>

  <v-card v-if="info" class="mb-4">
    <v-card-text class="d-flex align-center" style="gap: 0.75rem;">
      <v-chip
        v-if="info.paired"
        color="success"
        prepend-icon="mdi-check-circle"
        variant="flat"
      >Paired</v-chip>
      <v-chip
        v-else
        color="warning"
        prepend-icon="mdi-shield-alert-outline"
        variant="flat"
      >Not paired</v-chip>
      <span v-if="info.paired" class="text-medium-emphasis">
        Operations on this side use the encrypted channel.
      </span>
      <span v-else class="text-medium-emphasis">
        Operations refuse to run until pairing is complete.
      </span>
    </v-card-text>
  </v-card>

  <v-card v-if="info" class="mb-4">
    <v-card-text>
      <h3 class="text-subtitle-1 mt-0 mb-2">Show this side's public key</h3>
      <p class="text-body-2 text-medium-emphasis mb-3">
        Either scan the QR with the other side, or copy the UR fragments
        and paste them on the other side.
      </p>
      <div class="d-flex" style="gap: 1rem; align-items: flex-start;">
        <div class="d-flex flex-column align-center" style="flex: 0 0 auto;">
          <div class="bg-white pa-2 d-flex align-center justify-center" style="border-radius: 8px;">
            <img
              v-if="ownQrDataUrl"
              :src="ownQrDataUrl"
              alt="own pubkey QR"
              style="width: 160px; height: 160px;"
            />
          </div>
          <v-btn
            class="mt-2"
            size="small"
            variant="text"
            prepend-icon="mdi-arrow-expand"
            @click="qrEnlarged = true"
          >Enlarge</v-btn>
        </div>
        <div style="flex: 1 1 auto; min-width: 0;">
          <div class="d-flex align-center justify-end mb-1" style="gap: 0.75rem;">
            <span
              v-if="info.own_pubkey_ur.length > 1"
              class="text-caption text-medium-emphasis"
            >{{ ownQrIndex + 1 }} / {{ info.own_pubkey_ur.length }}</span>
            <v-btn
              size="x-small"
              variant="text"
              prepend-icon="mdi-content-copy"
              @click="copyOwnUr"
            >Copy</v-btn>
          </div>
          <div class="ur-list">
            <div
              v-for="(f, i) in info.own_pubkey_ur"
              :key="i"
              :class="['ur-row', { 'ur-active': i === ownQrIndex }]"
            >{{ f }}</div>
          </div>
        </div>
      </div>
    </v-card-text>
  </v-card>

  <v-card v-if="info" class="mb-4">
    <v-card-text>
      <h3 class="text-subtitle-1 mt-0 mb-2">Scan the other side's public key</h3>
      <p class="text-body-2 text-medium-emphasis mb-3">
        Scan the QR shown on the other side, or paste the UR fragments below.
      </p>
      <div class="d-flex" style="gap: 1rem; align-items: flex-start;">
        <div v-if="!cameraEnlarged" class="d-flex flex-column align-center" style="flex: 0 0 auto;">
          <div style="width: 160px;">
            <QRScanner
              ref="scannerRef"
              @complete="onScannerComplete"
              @error="(m: string) => scanError = m"
            />
          </div>
          <v-btn
            class="mt-2"
            size="small"
            variant="text"
            prepend-icon="mdi-arrow-expand"
            @click="cameraEnlarged = true"
          >Enlarge</v-btn>
        </div>
        <div style="flex: 1 1 auto; min-width: 0;">
          <!-- Placeholder mirrors airgap-core's UR_TYPE_PAIRING tag ("spo-tools-pairing-v1"), shared across products, not a typo. -->
          <v-textarea
            v-model="pasteInput"
            label="UR fragments from peer"
            rows="6"
            variant="outlined"
            density="compact"
            hide-details
            placeholder="ur:spo-tools-pairing-v1/..."
          />
          <v-btn
            class="mt-2"
            color="primary"
            :loading="previewing"
            :disabled="!pasteInput.trim()"
            prepend-icon="mdi-key-arrow-right"
            @click="previewPasted"
          >Preview fingerprint</v-btn>
        </div>
      </div>
      <v-alert
        v-if="scanError"
        type="error"
        density="compact"
        variant="tonal"
        class="mt-3"
      >{{ scanError }}</v-alert>
    </v-card-text>
  </v-card>

  <v-card v-if="pendingPeer || (info && info.paired)" class="mb-4">
    <v-card-text>
      <div class="text-medium-emphasis mb-1">
        Compare with the other screen: the two strings must match exactly
      </div>
      <div class="fingerprint-strip">
        {{ pendingPeer ? pendingPeer.fingerprint : info?.fingerprint }}
      </div>
      <div v-if="pendingPeer" class="d-flex justify-end mt-4" style="gap: 0.75rem;">
        <v-btn variant="text" @click="cancelPending">Cancel</v-btn>
        <v-btn
          color="primary"
          prepend-icon="mdi-check"
          :loading="confirming"
          @click="confirmPending"
        >Confirm: fingerprints match</v-btn>
      </div>
      <div v-else class="d-flex justify-end mt-4" style="gap: 0.75rem;">
        <v-btn
          color="error"
          variant="tonal"
          prepend-icon="mdi-link-variant-off"
          :loading="clearing"
          @click="clearPairing"
        >Clear pairing</v-btn>
      </div>
    </v-card-text>
  </v-card>

  <v-card v-if="loadError" class="mb-4">
    <v-card-text>
      <v-alert type="error" density="compact" variant="tonal">{{ loadError }}</v-alert>
    </v-card-text>
  </v-card>

  <v-dialog v-model="qrEnlarged" max-width="640">
    <v-card>
      <v-card-text class="d-flex flex-column align-center pa-6">
        <div class="bg-white pa-4 d-flex align-center justify-center" style="border-radius: 8px;">
          <img
            v-if="ownQrDataUrl"
            :src="ownQrDataUrl"
            alt="own pubkey QR"
            style="width: 480px; height: 480px;"
          />
        </div>
        <div
          v-if="info && info.own_pubkey_ur.length > 1"
          class="text-caption text-medium-emphasis mt-2"
        >{{ ownQrIndex + 1 }} / {{ info.own_pubkey_ur.length }}</div>
        <v-btn
          class="mt-3"
          variant="text"
          prepend-icon="mdi-arrow-collapse"
          @click="qrEnlarged = false"
        >Shrink</v-btn>
      </v-card-text>
    </v-card>
  </v-dialog>

  <v-dialog v-model="cameraEnlarged" max-width="640">
    <v-card>
      <v-card-text class="d-flex flex-column align-center pa-6">
        <div style="width: 480px;">
          <QRScanner
            v-if="cameraEnlarged"
            @complete="onScannerCompleteEnlarged"
            @error="(m: string) => { scanError = m; cameraEnlarged = false }"
          />
        </div>
        <v-btn
          class="mt-3"
          variant="text"
          prepend-icon="mdi-arrow-collapse"
          @click="cameraEnlarged = false"
        >Shrink</v-btn>
      </v-card-text>
    </v-card>
  </v-dialog>

  <v-dialog
    :model-value="destructiveOpen !== null"
    max-width="540"
    persistent
    @update:model-value="destructiveOpen = null"
  >
    <v-card>
      <v-card-title class="text-error">
        {{ destructiveOpen === 'repair' ? 'Re-pair over existing channel?' : 'Clear pairing?' }}
      </v-card-title>
      <v-card-text>
        <p>
          The encrypted channel between this online tool and the signer
          is currently active. {{ destructiveOpen === 'repair' ? 'Re-pairing' : 'Clearing the pairing' }}
          discards the existing public key on this side. Operations
          will refuse to run until both sides have re-paired and
          confirmed a new fingerprint.
        </p>
        <p class="mt-2">
          Type <code>{{ REQUIRED_KEYWORD }}</code> in the box below to confirm.
        </p>
        <v-text-field
          v-model="destructiveText"
          density="compact"
          variant="outlined"
          :placeholder="REQUIRED_KEYWORD"
          autofocus
          hide-details
        />
      </v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn variant="text" @click="destructiveOpen = null">Cancel</v-btn>
        <v-btn
          color="error"
          :disabled="destructiveText !== REQUIRED_KEYWORD || confirming || clearing"
          :loading="destructiveOpen === 'repair' ? confirming : clearing"
          @click="destructiveProceed"
        >
          {{ destructiveOpen === 'repair' ? 'Confirm re-pair' : 'Clear pairing' }}
        </v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>

<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'
import QRCode from 'qrcode'
import QRScanner from '@drep-tools/shared-frontend/components/QRScanner.vue'
import { useNotificationStore } from '@drep-tools/shared-frontend/stores/notification'
import { extractError } from '@drep-tools/shared-frontend/utils/error'
import { QR_CYCLE_INTERVAL_MS } from '@drep-tools/shared-frontend/constants/timings'

interface PairingInfo {
  own_pubkey_hex: string
  own_pubkey_ur: string[]
  paired: boolean
  peer_pubkey_hex: string | null
  fingerprint: string | null
}

interface PendingPeer {
  ur_fragments: string[]
  pubkey_hex: string
  fingerprint: string
}

const notify = useNotificationStore()

const info = ref<PairingInfo | null>(null)
const ownQrDataUrl = ref<string | null>(null)
const ownQrIndex = ref(0)
let ownQrTimer: ReturnType<typeof setInterval> | null = null

const cameraEnlarged = ref(false)
const qrEnlarged = ref(false)
const scanError = ref<string | null>(null)
const loadError = ref<string | null>(null)
const pasteInput = ref('')

const pendingPeer = ref<PendingPeer | null>(null)
const previewing = ref(false)
const confirming = ref(false)
const clearing = ref(false)

async function load(): Promise<void> {
  loadError.value = null
  try {
    const r = await fetch('/api/pairing/info')
    if (!r.ok) {
      const err = await extractError(r)
      throw new Error(err.message)
    }
    info.value = (await r.json()) as PairingInfo
    ownQrIndex.value = 0
    await renderOwnFrame()
    startOwnQrCycle()
  } catch (e: unknown) {
    loadError.value = e instanceof Error ? e.message : String(e)
  }
}

async function renderOwnFrame(): Promise<void> {
  if (!info.value || info.value.own_pubkey_ur.length === 0) return
  const fragment = info.value.own_pubkey_ur[ownQrIndex.value]
  ownQrDataUrl.value = await QRCode.toDataURL(fragment, {
    margin: 1,
    width: 800,
    errorCorrectionLevel: 'M',
  })
}

function startOwnQrCycle(): void {
  if (ownQrTimer) {
    clearInterval(ownQrTimer)
    ownQrTimer = null
  }
  if (!info.value || info.value.own_pubkey_ur.length <= 1) return
  ownQrTimer = setInterval(async () => {
    if (!info.value) return
    ownQrIndex.value = (ownQrIndex.value + 1) % info.value.own_pubkey_ur.length
    await renderOwnFrame()
  }, QR_CYCLE_INTERVAL_MS)
}

async function copyOwnUr(): Promise<void> {
  if (!info.value) return
  try {
    await navigator.clipboard.writeText(info.value.own_pubkey_ur.join('\n'))
    notify.success('UR fragments copied to clipboard')
  } catch (e: unknown) {
    notify.error('Could not copy: ' + (e instanceof Error ? e.message : String(e)))
  }
}

async function previewFragments(fragments: string[]): Promise<void> {
  previewing.value = true
  scanError.value = null
  pendingPeer.value = null
  try {
    if (fragments.length === 0) throw new Error('no UR fragments to preview')
    const r = await fetch('/api/pairing/preview', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ur_fragments: fragments }),
    })
    if (!r.ok) {
      const err = await extractError(r)
      throw new Error(err.message)
    }
    const data = (await r.json()) as { peer_pubkey_hex: string; fingerprint: string }
    pendingPeer.value = {
      ur_fragments: fragments,
      pubkey_hex: data.peer_pubkey_hex,
      fingerprint: data.fingerprint,
    }
  } catch (e: unknown) {
    scanError.value = e instanceof Error ? e.message : String(e)
  } finally {
    previewing.value = false
  }
}

async function onScannerComplete(fragments: string[]): Promise<void> {
  await previewFragments(fragments)
}

async function onScannerCompleteEnlarged(fragments: string[]): Promise<void> {
  cameraEnlarged.value = false
  await previewFragments(fragments)
}

async function previewPasted(): Promise<void> {
  const fragments = pasteInput.value
    .split('\n')
    .map((s) => s.trim())
    .filter(Boolean)
  await previewFragments(fragments)
}

const destructiveOpen = ref<null | 'repair' | 'clear'>(null)
const destructiveText = ref('')
const REQUIRED_KEYWORD = 'REPAIR'

function openDestructiveConfirm(kind: 'repair' | 'clear'): void {
  destructiveOpen.value = kind
  destructiveText.value = ''
}

async function confirmPending(): Promise<void> {
  if (!pendingPeer.value) return
  // Re-pair over an existing pairing: require typed confirmation so the
  // operator does not silently overwrite a working channel.
  if (info.value?.paired) {
    openDestructiveConfirm('repair')
    return
  }
  await actuallyConfirmPending()
}

async function actuallyConfirmPending(): Promise<void> {
  if (!pendingPeer.value) return
  confirming.value = true
  try {
    const r = await fetch('/api/pairing/set-peer', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ur_fragments: pendingPeer.value.ur_fragments,
        expected_fingerprint: pendingPeer.value.fingerprint,
      }),
    })
    if (!r.ok) {
      const err = await extractError(r)
      throw new Error(err.message)
    }
    pendingPeer.value = null
    pasteInput.value = ''
    await load()
    notify.success('Paired successfully.')
  } catch (e: unknown) {
    scanError.value = e instanceof Error ? e.message : String(e)
  } finally {
    confirming.value = false
    destructiveOpen.value = null
  }
}

function cancelPending(): void {
  pendingPeer.value = null
  pasteInput.value = ''
}

async function clearPairing(): Promise<void> {
  // Clearing wipes the encrypted channel and requires a full re-pair
  // dance to recover. Same typed-confirmation as repair so a misclick
  // does not destroy a working pairing.
  if (info.value?.paired) {
    openDestructiveConfirm('clear')
    return
  }
  await actuallyClearPairing()
}

async function actuallyClearPairing(): Promise<void> {
  clearing.value = true
  try {
    const r = await fetch('/api/pairing/clear', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    })
    if (!r.ok) {
      const err = await extractError(r)
      throw new Error(err.message)
    }
    await load()
    notify.info('Pairing cleared. Re-pair before any operation.')
  } catch (e: unknown) {
    scanError.value = e instanceof Error ? e.message : String(e)
  } finally {
    clearing.value = false
    destructiveOpen.value = null
  }
}

async function destructiveProceed(): Promise<void> {
  if (destructiveOpen.value === 'repair') await actuallyConfirmPending()
  else if (destructiveOpen.value === 'clear') await actuallyClearPairing()
}

onMounted(load)
onUnmounted(() => {
  if (ownQrTimer) clearInterval(ownQrTimer)
})
</script>

<style scoped>
.fingerprint-strip {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 28px;
  font-weight: 700;
  letter-spacing: 0.06em;
  color: var(--drep-gold);
  background: rgba(var(--drep-gold-rgb), 0.08);
  border: 1px solid rgba(var(--drep-gold-rgb), 0.4);
  border-radius: 8px;
  padding: 14px 18px;
  text-align: center;
}
</style>

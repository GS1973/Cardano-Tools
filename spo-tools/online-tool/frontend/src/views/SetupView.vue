<template>
  <v-card class="mb-4">
    <v-card-title>Setup</v-card-title>
  </v-card>

  <v-alert v-if="loadError" type="error" density="compact" variant="tonal" class="mb-4">{{ loadError }}</v-alert>

  <!-- Persistent until restart: the running backend keeps using the old
       Koios key, so a dismissible toast alone is too easy to miss. -->
  <v-alert v-if="restartNotice" type="warning" density="compact" variant="tonal" class="mb-4">{{ restartNotice }}</v-alert>

  <v-card class="mb-4">
    <v-card-text>
      <div class="d-flex align-center mb-3" style="gap: 0.75rem;">
        <h3 class="text-subtitle-1 mt-0 mb-0">Pool configuration</h3>
        <v-spacer />
        <v-btn
          v-if="locked"
          size="small"
          variant="outlined"
          prepend-icon="mdi-pencil"
          @click="enterEditMode"
        >Edit</v-btn>
      </div>

      <v-table v-if="locked" density="compact" class="mb-1">
        <tbody>
          <tr><td class="text-medium-emphasis" style="width: 220px;">Pool ID</td><td><code class="text-caption">{{ cfg.pool_id }}</code></td></tr>
          <tr><td class="text-medium-emphasis">Payment address</td><td><code class="text-caption">{{ cfg.payment_address }}</code></td></tr>
          <tr><td class="text-medium-emphasis">Reward receive address</td><td><code class="text-caption">{{ cfg.reward_receive_address }}</code></td></tr>
          <tr><td class="text-medium-emphasis">Koios API key</td><td>{{ hasKoiosKey ? 'configured' : 'not set' }}</td></tr>
          <tr>
            <td class="text-medium-emphasis">Paired with signer</td>
            <td>
              <span v-if="paired"><code class="text-caption">{{ pairingFingerprint }}</code></span>
              <span v-else class="text-medium-emphasis">not paired</span>
            </td>
          </tr>
        </tbody>
      </v-table>

      <template v-if="!locked">
        <div class="text-caption text-medium-emphasis mb-1">
          Bech32 pool identifier (mainnet). Once saved, the on-chain pool details are fetched and shown below.
        </div>
        <v-text-field
          v-model="cfg.pool_id"
          label="Pool ID"
          :placeholder="isFocused.pool_id ? '' : 'pool1...'"
          :error-messages="errors.pool_id ? [errors.pool_id] : []"
          density="compact"
          variant="outlined"
          class="mb-3"
          @focus="isFocused.pool_id = true"
          @blur="isFocused.pool_id = false"
        />

        <div class="text-caption text-medium-emphasis mb-1">
          Address whose UTXOs cover transaction fees (pool param updates, reward withdrawals).
        </div>
        <v-text-field
          v-model="cfg.payment_address"
          label="Payment address"
          :placeholder="isFocused.payment_address ? '' : 'addr1...'"
          :error-messages="errors.payment_address ? [errors.payment_address] : []"
          density="compact"
          variant="outlined"
          class="mb-3"
          @focus="isFocused.payment_address = true"
          @blur="isFocused.payment_address = false"
        />

        <div class="text-caption text-medium-emphasis mb-1">
          Destination address for withdrawn rewards. Often the same as the payment address, but can be a different (e.g. cold-storage) address.
        </div>
        <v-text-field
          v-model="cfg.reward_receive_address"
          label="Reward receive address"
          :placeholder="isFocused.reward_receive_address ? '' : 'addr1...'"
          :error-messages="errors.reward_receive_address ? [errors.reward_receive_address] : []"
          density="compact"
          variant="outlined"
          class="mb-3"
          @focus="isFocused.reward_receive_address = true"
          @blur="isFocused.reward_receive_address = false"
        />

        <div class="text-caption text-medium-emphasis mb-1">
          Base URL where you host rationale documents (e.g. https://yoursite/governance/). Optional; when set, the governance-vote view composes the anchor URL from this plus a file name.
        </div>
        <v-text-field
          v-model="cfg.manifest_base_url"
          label="Manifest base URL"
          :placeholder="isFocused.manifest_base_url ? '' : 'https://…/'"
          :error-messages="errors.manifest_base_url ? [errors.manifest_base_url] : []"
          density="compact"
          variant="outlined"
          class="mb-3"
          @focus="isFocused.manifest_base_url = true"
          @blur="isFocused.manifest_base_url = false"
        />

        <v-expansion-panels v-model="advancedOpen" class="mb-2" variant="accordion">
          <v-expansion-panel>
            <v-expansion-panel-title class="text-body-2">Advanced</v-expansion-panel-title>
            <v-expansion-panel-text>
              <div class="text-caption text-medium-emphasis mb-1">
                Optional. Without a key Koios is rate-limited at 5 000 requests/day per IP. With a registered key the limit becomes 50 000/day.
              </div>
              <v-text-field
                v-model="cfg.koios_api_key"
                label="Koios API key"
                density="compact"
                variant="outlined"
                type="password"
                class="mb-1"
                :placeholder="isFocused.koios_api_key ? '' : (hasKoiosKey ? 'stored — leave blank to keep' : 'optional')"
                @focus="isFocused.koios_api_key = true"
                @blur="isFocused.koios_api_key = false"
              />
            </v-expansion-panel-text>
          </v-expansion-panel>
        </v-expansion-panels>

        <div class="d-flex justify-end mt-4" style="gap: 0.5rem;">
          <v-btn
            v-if="hadSavedConfig"
            variant="text"
            prepend-icon="mdi-close"
            @click="cancelEdit"
          >Cancel</v-btn>
          <v-btn
            color="primary"
            :loading="saving"
            prepend-icon="mdi-content-save"
            @click="save"
          >Save</v-btn>
        </div>

        <v-alert v-if="saveError" type="error" density="compact" variant="tonal" class="mt-3">{{ saveError }}</v-alert>
      </template>
    </v-card-text>
  </v-card>

  <v-card v-if="locked">
    <v-card-text>
      <div class="d-flex align-center mb-3" style="gap: 0.75rem;">
        <h3 class="text-subtitle-1 mt-0 mb-0">Resolved on-chain values</h3>
        <v-spacer />
        <v-btn
          size="small"
          variant="tonal"
          prepend-icon="mdi-refresh"
          :loading="resolving"
          @click="loadResolved"
        >Refresh</v-btn>
      </div>

      <v-alert v-if="resolveError" type="error" density="compact" variant="tonal" class="mb-3">{{ resolveError }}</v-alert>

      <v-table v-if="resolved" density="compact">
        <tbody>
          <tr><td class="text-medium-emphasis" style="width: 220px;">Ticker</td><td>{{ resolved.meta_json?.ticker || '—' }}</td></tr>
          <tr><td class="text-medium-emphasis">Name</td><td>{{ resolved.meta_json?.name || '—' }}</td></tr>
          <tr><td class="text-medium-emphasis">Status</td><td>{{ resolved.pool_status || '—' }}</td></tr>
          <tr><td class="text-medium-emphasis">Live stake</td><td>{{ fmtAda(resolved.live_stake, 2) }}</td></tr>
          <tr><td class="text-medium-emphasis">Active stake</td><td>{{ fmtAda(resolved.active_stake, 2) }}</td></tr>
          <tr><td class="text-medium-emphasis">Pledge</td><td>{{ fmtAda(resolved.pledge, 2) }}</td></tr>
          <tr><td class="text-medium-emphasis">Margin</td><td>{{ resolved.margin != null ? `${(resolved.margin * 100).toFixed(2)} %` : '—' }}</td></tr>
          <tr><td class="text-medium-emphasis">Fixed cost</td><td>{{ fmtAda(resolved.fixed_cost, 2) }}</td></tr>
          <tr><td class="text-medium-emphasis">VRF key hash</td><td><code class="text-caption">{{ resolved.vrf_key_hash || '—' }}</code></td></tr>
          <tr><td class="text-medium-emphasis">Reward account</td><td><code class="text-caption">{{ resolved.reward_addr || '—' }}</code></td></tr>
          <tr>
            <td class="text-medium-emphasis">Owners</td>
            <td>
              <div v-for="o in (resolved.owners || [])" :key="o"><code class="text-caption">{{ o }}</code></div>
              <span v-if="!(resolved.owners || []).length">—</span>
            </td>
          </tr>
          <tr>
            <td class="text-medium-emphasis">Relays</td>
            <td>
              <div v-for="(r, i) in (resolved.relays || [])" :key="i" class="text-caption">
                {{ r.dns || r.ipv4 || r.ipv6 || '—' }}<span v-if="r.port">:{{ r.port }}</span>
              </div>
              <span v-if="!(resolved.relays || []).length">—</span>
            </td>
          </tr>
          <tr><td class="text-medium-emphasis">Metadata URL</td><td><span class="text-caption">{{ resolved.meta_url || '—' }}</span></td></tr>
        </tbody>
      </v-table>
      <div v-else-if="!resolveError" class="text-medium-emphasis text-caption">Loading...</div>
    </v-card-text>
  </v-card>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { useNotificationStore } from '@spo-tools/shared-frontend/stores/notification'
import { fmtAda } from '@spo-tools/shared-frontend/utils/format'
import { extractError } from '@spo-tools/shared-frontend/utils/error'

interface OnlineConfig {
  pool_id: string | null
  payment_address: string | null
  reward_receive_address: string | null
  koios_api_key: string | null
  manifest_base_url: string | null
}

interface ConfigStatusResponse {
  saved: boolean
  paired: boolean
  pairing_fingerprint: string | null
  pool_id: string | null
  payment_address: string | null
  reward_receive_address: string | null
  manifest_base_url: string | null
  has_koios_api_key: boolean
  // Present only on the POST response when the stored Koios API key just
  // changed: the backend's HTTP client bakes the Authorization header in
  // at startup, so the new key takes effect only after a restart.
  koios_api_key_restart_notice: string | null
}

interface ResolvedPool {
  pool_status?: string
  meta_json?: { ticker?: string; name?: string } | null
  meta_url?: string | null
  active_stake?: string | null
  live_stake?: string | null
  pledge?: string | null
  margin?: number | null
  fixed_cost?: string | null
  vrf_key_hash?: string | null
  reward_addr?: string | null
  owners?: string[]
  relays?: Array<{ dns?: string; ipv4?: string; ipv6?: string; port?: number }>
}

const notify = useNotificationStore()

const cfg = reactive<OnlineConfig>({
  pool_id: null,
  payment_address: null,
  reward_receive_address: null,
  koios_api_key: null,
  manifest_base_url: null,
})

const errors = reactive<Record<keyof OnlineConfig, string | null>>({
  pool_id: null,
  payment_address: null,
  reward_receive_address: null,
  koios_api_key: null,
  manifest_base_url: null,
})

const isFocused = reactive<Record<keyof OnlineConfig, boolean>>({
  pool_id: false,
  payment_address: false,
  reward_receive_address: false,
  koios_api_key: false,
  manifest_base_url: false,
})

const locked = ref(false)
const hadSavedConfig = ref(false)
const paired = ref(false)
const pairingFingerprint = ref<string | null>(null)
const hasKoiosKey = ref(false)

const saving = ref(false)
const saveError = ref<string | null>(null)
const loadError = ref<string | null>(null)
const advancedOpen = ref<number | null>(null)

const resolved = ref<ResolvedPool | null>(null)
const resolveError = ref<string | null>(null)
const resolving = ref(false)

// Restart-required notice from the last save that changed the Koios API
// key. Deliberately NOT cleared by later saves that leave the key alone:
// the restart is still pending until the operator actually restarts (a
// page reload after restart starts with a clean slate).
const restartNotice = ref<string | null>(null)

function clearForm() {
  cfg.pool_id = null
  cfg.payment_address = null
  cfg.reward_receive_address = null
  cfg.koios_api_key = null
  cfg.manifest_base_url = null
  errors.pool_id = null
  errors.payment_address = null
  errors.reward_receive_address = null
  errors.koios_api_key = null
  errors.manifest_base_url = null
  saveError.value = null
}

function applyStatus(d: ConfigStatusResponse) {
  locked.value = d.saved
  hadSavedConfig.value = d.saved
  paired.value = d.paired
  pairingFingerprint.value = d.pairing_fingerprint
  hasKoiosKey.value = d.has_koios_api_key
  // Pre-populate the editable fields with the stored values so a
  // subsequent Edit click shows the current configuration in the form.
  // pool_id + addresses are public-on-chain; the koios_api_key is
  // operator-secret and stays blank (server preserves on empty POST).
  cfg.pool_id = d.pool_id
  cfg.payment_address = d.payment_address
  cfg.reward_receive_address = d.reward_receive_address
  cfg.manifest_base_url = d.manifest_base_url
}

async function loadConfig() {
  try {
    const r = await fetch('/api/online-config')
    if (!r.ok) throw new Error(`HTTP ${r.status}`)
    const d: ConfigStatusResponse = await r.json()
    applyStatus(d)
    if (d.saved) {
      await loadResolved()
    }
  } catch (e: unknown) {
    loadError.value = e instanceof Error ? e.message : String(e)
  }
}

async function loadResolved() {
  resolving.value = true
  resolveError.value = null
  try {
    const r = await fetch('/api/pool/info')
    if (!r.ok) {
      const err = await extractError(r)
      throw new Error(err.message || `HTTP ${r.status}`)
    }
    resolved.value = await r.json()
  } catch (e: unknown) {
    resolveError.value = e instanceof Error ? e.message : String(e)
    resolved.value = null
  } finally {
    resolving.value = false
  }
}

function enterEditMode() {
  // Keep the pre-populated values from the last GET so the operator
  // can change a single field without retyping the rest. Only clear
  // any leftover error state and the koios_api_key field (the server
  // never echoes that one back, and an empty POST is preserved).
  errors.pool_id = null
  errors.payment_address = null
  errors.reward_receive_address = null
  errors.koios_api_key = null
  saveError.value = null
  cfg.koios_api_key = null
  locked.value = false
}

function cancelEdit() {
  // Reload from server to discard any in-progress edits and restore
  // the locked view with current stored values.
  errors.pool_id = null
  errors.payment_address = null
  errors.reward_receive_address = null
  errors.koios_api_key = null
  saveError.value = null
  cfg.koios_api_key = null
  if (hadSavedConfig.value) {
    locked.value = true
    void loadResolved()
    void loadConfig()
  }
}

async function save() {
  saving.value = true
  saveError.value = null
  errors.pool_id = null
  errors.payment_address = null
  errors.reward_receive_address = null
  errors.koios_api_key = null
  try {
    const r = await fetch('/api/online-config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(cfg),
    })
    if (!r.ok) {
      const err = await extractError(r)
      const msg = err.message
      const lower = msg.toLowerCase()
      if (lower.includes('pool_id')) errors.pool_id = msg
      else if (lower.includes('payment_address')) errors.payment_address = msg
      else if (lower.includes('reward_receive_address')) errors.reward_receive_address = msg
      throw new Error(msg || `HTTP ${r.status}`)
    }
    const d: ConfigStatusResponse = await r.json()
    // Clear the form first, then apply the server's status — doing it the
    // other way round wipes the just-saved values from the locked summary.
    clearForm()
    applyStatus(d)
    locked.value = true
    if (d.koios_api_key_restart_notice) {
      restartNotice.value = d.koios_api_key_restart_notice
      notify.warn(d.koios_api_key_restart_notice, 8000)
    } else {
      notify.success('Pool configuration saved')
    }
    window.dispatchEvent(new Event('spo-config-saved'))
    await loadResolved()
  } catch (e: unknown) {
    saveError.value = e instanceof Error ? e.message : String(e)
  } finally {
    saving.value = false
  }
}

onMounted(loadConfig)
</script>

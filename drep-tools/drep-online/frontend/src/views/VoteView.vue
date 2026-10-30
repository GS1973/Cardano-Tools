<template>
  <SignFlowLayout title="Vote as DRep" :not-configured="notConfigured" :not-paired="notPaired">
    <v-card class="mb-4">
      <v-card-text class="d-flex align-center" style="gap: 1rem;">
        <h3 class="text-subtitle-1 mt-0 mb-0">Cast DRep vote</h3>
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
        <v-alert v-if="!preview.registered" type="warning" density="compact" variant="tonal" class="mb-4">This DRep is not registered yet. Register it first: a vote from an unregistered DRep is rejected by the ledger, and sending one to the signer will be blocked.</v-alert>
        <v-alert v-if="!preview.can_cover" type="warning" density="compact" variant="tonal" class="mb-4">Payment address has insufficient funds to cover the fee ({{ fmtAda(preview.estimated_fee_lovelace) }}). Top it up before continuing.</v-alert>
        <v-table density="compact" class="mb-3"><tbody>
          <tr><td class="text-medium-emphasis" style="width: 280px;">Voting as DRep</td><td><code class="text-caption">{{ preview.drep_id }}</code></td></tr>
          <tr><td class="text-medium-emphasis">Payment address</td><td><code class="text-caption">{{ preview.payment_address }}</code></td></tr>
          <tr><td class="text-medium-emphasis">Payment total</td><td>{{ fmtAda(preview.payment_utxo_total_lovelace) }}</td></tr>
          <tr><td class="text-medium-emphasis">Estimated fee</td><td>{{ fmtAda(preview.estimated_fee_lovelace) }}</td></tr>
        </tbody></v-table>

        <template v-if="mode !== 'receive'">
          <h3 class="text-subtitle-1 mt-2 mb-2">Choose governance action</h3>
          <v-alert v-if="preview.proposals.length === 0" type="info" density="compact" variant="tonal" class="mb-2">No open governance actions right now.</v-alert>
          <v-select v-else v-model="selectedIdx" :items="proposalItems" item-title="label" item-value="value" label="Open governance action" density="compact" variant="outlined" hide-details class="mb-3" />
          <p class="text-caption text-medium-emphasis mb-3">A DRep votes on every action type: parameter changes (including the decentralisation parameters an SPO cannot touch), hard forks, treasury, committee, constitution, info.</p>

          <template v-if="selectedProposal">
            <v-table density="compact" class="mb-3"><tbody>
              <tr><td class="text-medium-emphasis" style="width: 280px;">Action ID</td><td><code class="text-caption">{{ selectedProposal.action_tx_hash }}#{{ selectedProposal.action_index }}</code></td></tr>
              <tr v-if="selectedProposal.proposal_id"><td class="text-medium-emphasis">Gov action (CIP-129)</td><td><code class="text-caption">{{ selectedProposal.proposal_id }}</code></td></tr>
              <tr><td class="text-medium-emphasis">Type</td><td>{{ selectedProposal.proposal_type }}<span v-if="selectedProposal.target_protocol_major != null"> → protocol {{ selectedProposal.target_protocol_major }}</span></td></tr>
              <tr v-if="selectedProposal.expiration_epoch != null"><td class="text-medium-emphasis">Expires (epoch)</td><td>{{ selectedProposal.expiration_epoch }}</td></tr>
            </tbody></v-table>

            <h3 class="text-subtitle-1 mt-2 mb-2">Your vote</h3>
            <v-radio-group v-model="voteChoice" hide-details density="compact" class="mb-2 compact-radios" inline>
              <v-radio value="yes" label="Yes" />
              <v-radio value="no" label="No" />
              <v-radio value="abstain" label="Abstain" />
            </v-radio-group>
            <p class="text-caption text-medium-emphasis mb-3">Signed by your DRep key. It carries the voting power vote-delegated to your DRep.</p>

            <h3 class="text-subtitle-1 mt-2 mb-2">Rationale (CIP-136, optional)</h3>
            <template v-if="preview.manifest_base_url">
              <p class="text-caption text-medium-emphasis mb-2">Enter just the file name. The on-chain URL is composed from your configured base. The hash is the blake2b-256 of the document's contents: host it first, then compute. Leave the file name empty for no anchor.</p>
              <v-text-field v-model="manifestFile" label="Rationale file name" placeholder="rationale.jsonld" density="compact" variant="outlined" hide-details class="mb-2" />
              <p v-if="composedManifestUrl" class="text-caption text-medium-emphasis mb-2">Full URL (goes on-chain): <code style="word-break: break-all;">{{ composedManifestUrl }}</code></p>
              <div class="d-flex align-start" style="gap: 0.5rem;">
                <v-text-field v-model="anchorHash" label="Rationale hash (64 hex chars)" placeholder="blake2b-256 of the document" density="compact" variant="outlined" hide-details />
                <v-btn size="small" variant="outlined" :loading="hashing" :disabled="!composedManifestUrl" prepend-icon="mdi-pound" class="mt-1" @click="computeHash">Compute hash</v-btn>
              </div>
              <v-alert v-if="hashError" type="error" density="compact" variant="tonal" class="mt-2">{{ hashError }}</v-alert>
            </template>
            <v-alert v-else type="info" density="compact" variant="tonal">To attach a rationale, set a <strong>Manifest base URL</strong> in Setup first. You can vote without one.</v-alert>
          </template>
        </template>
      </v-card-text>
    </v-card>

    <SignFlowPanels :flow="flow" @new-session="startNewSession">
      <template #summary>
        <tr v-if="request"><td class="text-medium-emphasis" style="width: 280px;">Vote</td><td><strong>{{ formatVote(request.vote) }}</strong></td></tr>
        <tr v-if="request"><td class="text-medium-emphasis">On action</td><td><code class="text-caption">{{ request.action_tx_hash_hex }}#{{ request.action_index }}</code></td></tr>
        <tr v-if="request"><td class="text-medium-emphasis">As DRep</td><td><code class="text-caption">{{ request.drep_id_bech32 }}</code></td></tr>
        <tr v-if="request"><td class="text-medium-emphasis">Rationale</td><td><span v-if="request.anchor"><code class="text-caption">{{ request.anchor.url }}</code></span><span v-else class="text-caption text-medium-emphasis">(none)</span></td></tr>
        <tr v-if="request"><td class="text-medium-emphasis">Change back to payment</td><td>{{ fmtAda(request.change_to_payment_address_lovelace) }}</td></tr>
        <tr v-if="request"><td class="text-medium-emphasis">Fee</td><td>{{ fmtAda(request.fee_lovelace) }}</td></tr>
        <tr v-if="result"><td class="text-medium-emphasis">Witnesses signed</td><td><strong>{{ result.witnesses.length }}</strong> <span class="text-caption text-medium-emphasis">({{ witnessRoles }})</span></td></tr>
      </template>
      <template #submitted-summary>
        <tr v-if="request"><td class="text-medium-emphasis">Vote</td><td><strong>{{ formatVote(request.vote) }}</strong></td></tr>
        <tr v-if="request"><td class="text-medium-emphasis">On action</td><td><code class="text-caption">{{ request.action_tx_hash_hex }}#{{ request.action_index }}</code></td></tr>
      </template>
    </SignFlowPanels>

    <PreSendConfirm v-model="confirmSendOpen" title="Confirm DRep vote" @confirm="onConfirmSend">
      <p class="text-body-2 text-medium-emphasis mb-2">You are about to cast your DRep vote <strong>{{ selectedProposal ? formatVote(voteChoice) : '' }}</strong> on action <code v-if="selectedProposal">{{ selectedProposal.action_tx_hash }}#{{ selectedProposal.action_index }}</code>. Your DRep key signs.</p>
    </PreSendConfirm>
  </SignFlowLayout>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { fmtAda } from '@drep-tools/shared-frontend/utils/format'
import { extractError } from '@drep-tools/shared-frontend/utils/error'
import type { VoteChoice } from '@drep-tools/shared-frontend/types/wire'
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
const selectedIdx = ref<number | null>(null)
const voteChoice = ref<VoteChoice>('yes')
const manifestFile = ref('')
const anchorHash = ref('')
const hashing = ref(false)
const hashError = ref<string | null>(null)
const confirmSendOpen = ref(false)

const flow = useSignFlow('/api/vote')
const { mode, starting, submitted, request, result, enterReceive } = flow
flow.setGuards(() => { notConfigured.value = true }, () => { notPaired.value = true })

const proposalItems = computed(() =>
  (preview.value?.proposals ?? []).map((p: any, i: number) => ({ value: i, label: proposalLabel(p) })),
)
const selectedProposal = computed<any>(() =>
  selectedIdx.value == null ? null : preview.value?.proposals[selectedIdx.value] ?? null,
)
const canBuild = computed(() => !!preview.value && preview.value.can_cover && !!selectedProposal.value)
const witnessRoles = computed(() => (result.value?.witnesses ?? []).map((w: any) => w.role).join(' + '))

function proposalLabel(p: any): string {
  const head = p.title || p.proposal_type
  const ver = p.target_protocol_major != null ? ` (→ v${p.target_protocol_major})` : ''
  return `${p.proposal_type}${ver}, ${head}, ${p.action_tx_hash.slice(0, 12)}…#${p.action_index}`
}
function formatVote(v: VoteChoice): string { return v === 'yes' ? 'Yes' : v === 'no' ? 'No' : 'Abstain' }

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
    const r = await fetch('/api/vote/preview')
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

watch([selectedIdx, voteChoice, manifestFile, anchorHash], () => flow.invalidate())

async function onConfirmSend(payload: { pin: string }) {
  confirmSendOpen.value = false
  if (!selectedProposal.value) return
  await flow.start({
    pin: payload.pin,
    action_tx_hash: selectedProposal.value.action_tx_hash,
    action_index: selectedProposal.value.action_index,
    vote: voteChoice.value,
    anchor_url: composedManifestUrl.value || null,
    anchor_hash: anchorHash.value.trim() || null,
  })
}

function startNewSession() { flow.reset(); load() }
onMounted(load)
</script>

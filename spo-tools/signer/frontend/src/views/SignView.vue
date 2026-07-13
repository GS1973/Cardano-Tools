<template>
  <v-card class="mb-4">
    <v-card-title>Sign</v-card-title>
  </v-card>

  <NotConfiguredCard v-if="notConfigured" />
  <NotPairedCard v-else-if="notPaired" />

  <template v-else>
  <v-card v-if="!parsed" class="mb-4">
    <v-card-text>
      <h3 class="text-subtitle-1 mt-0 mb-2">Awaiting request</h3>
      <p class="text-body-2 text-medium-emphasis mb-3">
        Scan the QR shown by the online tool, or paste the UR fragments and click Submit.
      </p>
      <div class="d-flex" style="gap: 1rem; align-items: flex-start;">
        <div v-if="!cameraEnlarged" class="d-flex flex-column align-center" style="flex: 0 0 auto;">
          <div style="width: 160px;">
            <QRScanner
              ref="scannerRef"
              @complete="onScannerComplete"
              @error="(m: string) => (receiveError = m)"
            />
          </div>
          <v-btn class="mt-2" size="small" variant="text" prepend-icon="mdi-arrow-expand" @click="cameraEnlarged = true">Enlarge</v-btn>
        </div>
        <div style="flex: 1 1 auto; min-width: 0;">
          <v-textarea
            v-model="pasteInput"
            label="UR fragments from the online tool"
            rows="6"
            variant="outlined"
            density="compact"
            hide-details
            placeholder="ur:spo-tools-action-v1/..."
          />
          <v-btn
            class="mt-2"
            color="primary"
            :loading="receiving"
            :disabled="!pasteInput.trim()"
            prepend-icon="mdi-upload"
            @click="submitPasted"
          >Submit</v-btn>
        </div>
      </div>
      <v-alert v-if="receiveError" type="error" density="compact" variant="tonal" class="mt-3">
        {{ receiveError }}
        <template #append>
          <v-btn
            size="x-small"
            variant="text"
            :loading="retryingCamera"
            class="text-white" prepend-icon="mdi-refresh"
            @click="retryCamera"
          >Try again</v-btn>
        </template>
      </v-alert>
    </v-card-text>
  </v-card>

  <!-- Preview: leaderlog -->
  <v-card v-if="parsed && requestFingerprint" class="mb-4">
    <v-card-text class="py-3">
      <RequestFingerprintBadge :fingerprint="requestFingerprint" />
      <p class="text-caption text-medium-emphasis mt-2 mb-0">
        This must match the fingerprint shown next to the QR on the online tool. If they differ, do not sign.
      </p>
    </v-card-text>
  </v-card>

  <v-card v-if="parsed?.kind === 'leaderlog'" ref="previewCardEl" class="mb-4">
    <v-card-text>
      <h3 class="text-subtitle-1 mt-0 mb-2">Preview — Compute leader schedule</h3>
      <p class="text-body-2 text-medium-emphasis mb-3">
        The signer will compute which slots this pool leads in epoch
        {{ parsed.request.epoch }} using the configured VRF signing key.
        No transaction is sent to the chain.
      </p>
      <v-table density="compact">
        <tbody>
          <tr><td class="text-medium-emphasis">Pool</td><td><code>{{ parsed.request.pool_id_bech32 }}</code></td></tr>
          <tr><td class="text-medium-emphasis">Target epoch</td><td>{{ parsed.request.epoch }}</td></tr>
          <tr><td class="text-medium-emphasis">Pool sigma</td><td>{{ leaderlogSigma(parsed.request) }}</td></tr>
          <tr><td class="text-medium-emphasis">Active slots coeff</td><td>{{ activeSlotsCoeff(parsed.request) }}</td></tr>
          <tr><td class="text-medium-emphasis">Epoch length</td><td>{{ fmtInt(parsed.request.epoch_length) }} slots</td></tr>
        </tbody>
      </v-table>
      <div class="d-flex justify-end mt-3" style="gap: 0.5rem;">
        <v-btn variant="text" prepend-icon="mdi-close" @click="cancelParse">Cancel</v-btn>
        <v-btn
          color="primary"
          :loading="signing"
          prepend-icon="mdi-key-variant"
          @click="confirmAndSign"
        >Confirm and sign</v-btn>
      </div>
    </v-card-text>
  </v-card>

  <!-- Preview: KES rotation -->
  <v-card v-if="parsed?.kind === 'kes-rotation'" ref="previewCardEl" class="mb-4">
    <v-card-text>
      <h3 class="text-subtitle-1 mt-0 mb-2">Preview — Rotate KES key</h3>
      <p class="text-body-2 text-medium-emphasis mb-3">
        The signer will generate a fresh KES keypair and sign an operational
        certificate with the cold key. Output: kes.skey, node.cert, and
        cold.counter for deployment to your block-producer node.
      </p>
      <v-table density="compact">
        <tbody>
          <tr><td class="text-medium-emphasis">Pool</td><td><code>{{ parsed.request.pool_id_bech32 }}</code></td></tr>
          <tr><td class="text-medium-emphasis">New counter</td><td><strong>{{ parsed.request.new_counter }}</strong></td></tr>
          <tr><td class="text-medium-emphasis">KES period</td><td>{{ parsed.request.kes_period }}</td></tr>
        </tbody>
      </v-table>
      <div class="d-flex justify-end mt-3" style="gap: 0.5rem;">
        <v-btn variant="text" prepend-icon="mdi-close" @click="cancelParse">Cancel</v-btn>
        <v-btn
          color="primary"
          :loading="signing"
          prepend-icon="mdi-key-variant"
          @click="confirmAndSign"
        >Confirm and sign</v-btn>
      </div>
    </v-card-text>
  </v-card>

  <!-- Preview: Withdrawal -->
  <v-card v-if="parsed?.kind === 'withdrawal'" ref="previewCardEl" class="mb-4">
    <v-card-text>
      <h3 class="text-subtitle-1 mt-0 mb-2">Preview — Sign reward withdrawal</h3>
      <p class="text-body-2 text-medium-emphasis mb-3">
        The signer will hash the supplied transaction body (Blake2b-256)
        and produce two vkey witnesses: one with the payment signing key,
        one with the reward stake signing key.
      </p>
      <div class="field-stack">
        <div class="field">
          <div class="field-label">Pool reward account</div>
          <div class="field-value"><code class="text-caption">{{ parsed.request.pool_reward_address_bech32 }}</code></div>
        </div>
        <div class="field">
          <div class="field-label">Withdrawing</div>
          <div class="field-value text-gold"><strong>{{ fmtAda(parsed.request.net_to_reward_address_lovelace) }}</strong></div>
        </div>
        <div class="field">
          <div class="field-label">Reward receive address</div>
          <div class="field-value"><code class="text-caption">{{ parsed.request.reward_receive_address_bech32 }}</code></div>
        </div>
        <div class="field">
          <div class="field-label">Change to payment address</div>
          <div class="field-value">
            {{ fmtAda(parsed.request.change_to_payment_address_lovelace) }}
            → <code class="text-caption">{{ parsed.request.payment_address_bech32 }}</code>
          </div>
        </div>
        <FundingInputs :inputs="parsed.request.inputs" :payment-address="parsed.request.payment_address_bech32" />
        <div class="field-row">
          <div class="field">
            <div class="field-label">Fee</div>
            <div class="field-value">{{ fmtAda(parsed.request.fee_lovelace) }}</div>
          </div>
          <div class="field">
            <div class="field-label">TTL slot</div>
            <div class="field-value">{{ fmtInt(parsed.request.ttl_slot) }}</div>
          </div>
          <div class="field">
            <div class="field-label">Tx body size</div>
            <div class="field-value">{{ Math.floor(parsed.request.tx_body_cbor_hex.length / 2) }} bytes</div>
          </div>
        </div>
      </div>
      <div class="d-flex justify-end mt-3" style="gap: 0.5rem;">
        <v-btn variant="text" prepend-icon="mdi-close" @click="cancelParse">Cancel</v-btn>
        <v-btn
          color="primary"
          :loading="signing"
          prepend-icon="mdi-key-variant"
          @click="confirmAndSign"
        >Confirm and sign</v-btn>
      </div>
    </v-card-text>
  </v-card>

  <!-- Preview: DRep delegation -->
  <v-card v-if="parsed?.kind === 'drep-delegation'" ref="previewCardEl" class="mb-4">
    <v-card-text>
      <h3 class="text-subtitle-1 mt-0 mb-2">Preview — Sign DRep delegation</h3>
      <p class="text-body-2 text-medium-emphasis mb-3">
        The signer will hash the supplied transaction body (Blake2b-256)
        and produce two vkey witnesses: one with the payment signing key,
        one with the owner stake signing key (authorising the cert).
      </p>
      <div class="field-stack">
        <div class="field">
          <div class="field-label">Stake credential</div>
          <div class="field-value"><code class="text-caption">{{ parsed.request.stake_credential_bech32 }}</code></div>
        </div>
        <div class="field">
          <div class="field-label">Delegating to</div>
          <div class="field-value text-gold"><strong>{{ formatDrepChoice(parsed.request.drep_choice) }}</strong></div>
        </div>
        <div class="field">
          <div class="field-label">Payment address</div>
          <div class="field-value"><code class="text-caption">{{ parsed.request.payment_address_bech32 }}</code></div>
        </div>
        <FundingInputs :inputs="parsed.request.inputs" :payment-address="parsed.request.payment_address_bech32" />
        <div class="field-row">
          <div class="field">
            <div class="field-label">Change to payment</div>
            <div class="field-value">{{ fmtAda(parsed.request.change_to_payment_address_lovelace) }}</div>
          </div>
          <div class="field">
            <div class="field-label">Fee</div>
            <div class="field-value">{{ fmtAda(parsed.request.fee_lovelace) }}</div>
          </div>
          <div class="field">
            <div class="field-label">TTL slot</div>
            <div class="field-value">{{ fmtInt(parsed.request.ttl_slot) }}</div>
          </div>
          <div class="field">
            <div class="field-label">Tx body size</div>
            <div class="field-value">{{ Math.floor(parsed.request.tx_body_cbor_hex.length / 2) }} bytes</div>
          </div>
        </div>
      </div>
      <div class="d-flex justify-end mt-3" style="gap: 0.5rem;">
        <v-btn variant="text" prepend-icon="mdi-close" @click="cancelParse">Cancel</v-btn>
        <v-btn
          color="primary"
          :loading="signing"
          prepend-icon="mdi-key-variant"
          @click="confirmAndSign"
        >Confirm and sign</v-btn>
      </div>
    </v-card-text>
  </v-card>

  <!-- Preview: SPO governance vote -->
  <v-card v-if="parsed?.kind === 'vote'" ref="previewCardEl" class="mb-4">
    <v-card-text>
      <h3 class="text-subtitle-1 mt-0 mb-2">Preview — Sign SPO governance vote</h3>
      <p class="text-body-2 text-medium-emphasis mb-3">
        The signer will hash the supplied transaction body (Blake2b-256) and
        produce two vkey witnesses: payment (fee) and cold (the pool's voting
        authority). The cold key must hash to the pool id below or the signer
        refuses. This vote carries the pool's full stake weight.
      </p>
      <div class="field-stack">
        <div class="field">
          <div class="field-label">Vote</div>
          <div class="field-value text-gold"><strong>{{ formatVote(parsed.request.vote) }}</strong></div>
        </div>
        <div class="field">
          <div class="field-label">Governance action</div>
          <div class="field-value"><code class="text-caption">{{ parsed.request.action_tx_hash_hex }}#{{ parsed.request.action_index }}</code></div>
        </div>
        <div class="field">
          <div class="field-label">As pool</div>
          <div class="field-value"><code class="text-caption">{{ parsed.request.pool_id_bech32 }}</code></div>
        </div>
        <div class="field">
          <div class="field-label">Rationale anchor</div>
          <div class="field-value">
            <code v-if="parsed.request.anchor" class="text-caption">{{ parsed.request.anchor.url }}</code>
            <span v-else class="text-caption text-medium-emphasis">(none)</span>
          </div>
        </div>
        <div class="field">
          <div class="field-label">Payment address</div>
          <div class="field-value"><code class="text-caption">{{ parsed.request.payment_address_bech32 }}</code></div>
        </div>
        <FundingInputs :inputs="parsed.request.inputs" :payment-address="parsed.request.payment_address_bech32" />
        <div class="field-row">
          <div class="field">
            <div class="field-label">Change to payment</div>
            <div class="field-value">{{ fmtAda(parsed.request.change_to_payment_address_lovelace) }}</div>
          </div>
          <div class="field">
            <div class="field-label">Fee</div>
            <div class="field-value">{{ fmtAda(parsed.request.fee_lovelace) }}</div>
          </div>
          <div class="field">
            <div class="field-label">TTL slot</div>
            <div class="field-value">{{ fmtInt(parsed.request.ttl_slot) }}</div>
          </div>
          <div class="field">
            <div class="field-label">Tx body size</div>
            <div class="field-value">{{ Math.floor(parsed.request.tx_body_cbor_hex.length / 2) }} bytes</div>
          </div>
        </div>
      </div>
      <div class="d-flex justify-end mt-3" style="gap: 0.5rem;">
        <v-btn variant="text" prepend-icon="mdi-close" @click="cancelParse">Cancel</v-btn>
        <v-btn
          color="primary"
          :loading="signing"
          prepend-icon="mdi-key-variant"
          @click="confirmAndSign"
        >Confirm and sign</v-btn>
      </div>
    </v-card-text>
  </v-card>

  <!-- Preview: Pool param update -->
  <v-card v-if="parsed?.kind === 'pool-update'" ref="previewCardEl" class="mb-4">
    <v-card-text>
      <h3 class="text-subtitle-1 mt-0 mb-2">Preview — Sign pool parameter update</h3>
      <p class="text-body-2 text-medium-emphasis mb-3">
        The signer will hash the supplied transaction body (Blake2b-256) and produce
        three vkey witnesses: payment (fee), cold (operator authority), owner stake (pledge).
      </p>
      <div class="field-stack">
        <div class="field">
          <div class="field-label">Pool ID</div>
          <div class="field-value"><code class="text-caption">{{ parsed.request.pool_id_bech32 }}</code></div>
        </div>
        <div class="field">
          <div class="field-label">VRF key hash</div>
          <div class="field-value">
            <code class="text-caption">{{ parsed.request.vrf_keyhash_hex }}</code>
            <span class="text-caption text-medium-emphasis ml-2">must be your pool's current VRF key — unchanged unless you rotated it</span>
          </div>
        </div>
        <div class="field-row">
          <div class="field">
            <div class="field-label">Pledge</div>
            <div class="field-value">{{ fmtAda(parsed.request.pledge_lovelace) }}</div>
          </div>
          <div class="field">
            <div class="field-label">Fixed cost</div>
            <div class="field-value">{{ fmtAda(parsed.request.fixed_cost_lovelace) }}</div>
          </div>
          <div class="field">
            <div class="field-label">Margin</div>
            <div class="field-value">{{ fmtMargin(parsed.request.margin_numerator, parsed.request.margin_denominator) }}</div>
          </div>
        </div>
        <div class="field">
          <div class="field-label">Reward stake address</div>
          <div class="field-value"><code class="text-caption">{{ parsed.request.reward_account_bech32 }}</code></div>
        </div>
        <div class="field">
          <div class="field-label">
            Pledge (owner) stake address<span v-if="parsed.request.pool_owner_stake_addresses.length > 1"> ({{ parsed.request.pool_owner_stake_addresses.length }})</span>
          </div>
          <div class="field-value">
            <div
              v-for="(addr, idx) in parsed.request.pool_owner_stake_addresses"
              :key="addr"
              class="mb-1"
            >
              <code class="text-caption">{{ addr }}</code>
              <span v-if="parsed.request.pool_owner_stake_addresses.length > 1" class="text-caption text-medium-emphasis ml-2">
                #{{ idx + 1 }}
              </span>
            </div>
            <v-alert
              v-if="parsed.request.pool_owner_stake_addresses.length > 1"
              type="warning"
              density="compact"
              variant="tonal"
              class="mt-2"
            >
              Multi-owner pool: every listed owner stake address must visually match the pool's on-chain owners; verify each before signing.
            </v-alert>
          </div>
        </div>
        <div class="field">
          <div class="field-label">Relays</div>
          <div class="field-value"><code class="text-caption">{{ fmtRelays(parsed.request.relays) }}</code></div>
        </div>
        <div class="field">
          <div class="field-label">Metadata URL</div>
          <div class="field-value"><code class="text-caption">{{ parsed.request.metadata_url ?? '(none)' }}</code></div>
        </div>
        <div class="field">
          <div class="field-label">Metadata hash</div>
          <div class="field-value"><code class="text-caption">{{ parsed.request.metadata_hash_hex ?? '(none)' }}</code></div>
        </div>
        <FundingInputs :inputs="parsed.request.inputs" :payment-address="parsed.request.payment_address_bech32" />
        <div class="field-row">
          <div class="field">
            <div class="field-label">Change to payment</div>
            <div class="field-value">{{ fmtAda(parsed.request.change_to_payment_address_lovelace) }}</div>
          </div>
          <div class="field">
            <div class="field-label">Fee</div>
            <div class="field-value">{{ fmtAda(parsed.request.fee_lovelace) }}</div>
          </div>
          <div class="field">
            <div class="field-label">TTL slot</div>
            <div class="field-value">{{ fmtInt(parsed.request.ttl_slot) }}</div>
          </div>
          <div class="field">
            <div class="field-label">Tx body size</div>
            <div class="field-value">{{ Math.floor(parsed.request.tx_body_cbor_hex.length / 2) }} bytes</div>
          </div>
        </div>
      </div>
      <div class="d-flex justify-end mt-3" style="gap: 0.5rem;">
        <v-btn variant="text" prepend-icon="mdi-close" @click="cancelParse">Cancel</v-btn>
        <v-btn
          color="primary"
          :loading="signing"
          prepend-icon="mdi-key-variant"
          @click="confirmAndSign"
        >Confirm and sign</v-btn>
      </div>
    </v-card-text>
  </v-card>

  <v-card v-if="signError" class="mb-4">
    <v-card-text>
      <v-alert type="error" density="compact" variant="tonal">{{ signError }}</v-alert>
    </v-card-text>
  </v-card>

  <v-card v-if="result" ref="resultCardEl" class="mb-4">
    <v-card-text>
      <h3 class="text-subtitle-1 mt-0 mb-2">Result</h3>
      <p class="text-body-2 text-medium-emphasis mb-3">
        Either show the QR to the online tool's webcam or copy the UR fragments and paste them in the online tool's Receive panel.
      </p>
      <div class="d-flex" style="gap: 1rem; align-items: flex-start;">
        <div class="d-flex flex-column align-center" style="flex: 0 0 auto;">
          <div class="bg-white pa-2 d-flex align-center justify-center" style="border-radius: 8px;">
            <img v-if="qrDataUrl" :src="qrDataUrl" alt="QR" style="width: 160px; height: 160px;" />
          </div>
          <v-btn class="mt-2" size="small" variant="text" prepend-icon="mdi-arrow-expand" @click="qrEnlarged = true">Enlarge</v-btn>
        </div>
        <div style="flex: 1 1 auto; min-width: 0;">
          <div class="d-flex align-center justify-end mb-1" style="gap: 0.75rem;">
            <span v-if="result.ur_fragments.length > 1" class="text-caption text-medium-emphasis">
              {{ qrIndex + 1 }} / {{ result.ur_fragments.length }}
            </span>
            <v-btn size="x-small" variant="text" prepend-icon="mdi-content-copy" @click="copyResultUr">Copy</v-btn>
          </div>
          <div class="ur-list">
            <div
              v-for="(f, i) in result.ur_fragments"
              :key="i"
              :class="['ur-row', { 'ur-active': i === qrIndex }]"
            >{{ f }}</div>
          </div>
        </div>
      </div>
      <div class="d-flex justify-end mt-3">
        <v-btn variant="text" prepend-icon="mdi-restart" @click="startNewSession">Start new session</v-btn>
      </div>
    </v-card-text>
  </v-card>

  <v-dialog v-model="qrEnlarged" max-width="640">
    <v-card>
      <v-card-text class="d-flex flex-column align-center pa-6">
        <div class="bg-white pa-4" style="border-radius: 8px;">
          <img v-if="qrDataUrl" :src="qrDataUrl" alt="QR" style="width: 480px; height: 480px;" />
        </div>
        <div v-if="result && result.ur_fragments.length > 1" class="text-caption text-medium-emphasis mt-2">
          {{ qrIndex + 1 }} / {{ result.ur_fragments.length }}
        </div>
        <v-btn class="mt-3" variant="text" prepend-icon="mdi-arrow-collapse" @click="qrEnlarged = false">Shrink</v-btn>
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
            @error="(m: string) => { receiveError = m; cameraEnlarged = false }"
          />
        </div>
        <v-btn class="mt-3" variant="text" prepend-icon="mdi-arrow-collapse" @click="cameraEnlarged = false">Shrink</v-btn>
      </v-card-text>
    </v-card>
  </v-dialog>

  <v-dialog v-model="pinDialogOpen" max-width="480" persistent>
    <v-card>
      <v-card-title>Confirm operator PIN</v-card-title>
      <v-card-text>
        <p class="text-body-2 mb-2">
          Type the same 4-digit PIN you entered on the online tool when you
          clicked Send to Signer. The signer hashes your input and refuses
          to sign if it does not match the PIN already encoded in the
          encrypted payload.
        </p>
        <v-text-field
          v-model="pinInput"
          density="compact"
          variant="outlined"
          type="password"
          inputmode="numeric"
          maxlength="4"
          placeholder="0000"
          :error-messages="pinError ? [pinError] : []"
          hide-details="auto"
          autofocus
          style="max-width: 160px;"
          @keydown.enter="executeWithPin"
        />
      </v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn variant="text" @click="pinDialogOpen = false">Cancel</v-btn>
        <v-btn
          color="primary"
          prepend-icon="mdi-key-variant"
          :loading="signing"
          @click="executeWithPin"
        >Sign</v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
  </template>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted, nextTick } from 'vue'
import QRCode from 'qrcode'
import NotConfiguredCard from '../components/NotConfiguredCard.vue'
import NotPairedCard from '../components/NotPairedCard.vue'
import FundingInputs from '../components/FundingInputs.vue'
import QRScanner from '@spo-tools/shared-frontend/components/QRScanner.vue'
import { QR_CYCLE_INTERVAL_MS } from '@spo-tools/shared-frontend/constants/timings'
import { useNotificationStore } from '@spo-tools/shared-frontend/stores/notification'
import { fmtAda, fmtInt, fmtMargin, fmtRelays } from '@spo-tools/shared-frontend/utils/format'
import { extractError } from '@spo-tools/shared-frontend/utils/error'
import RequestFingerprintBadge from '@spo-tools/shared-frontend/components/RequestFingerprintBadge.vue'
import type {
  LeaderlogRequest,
  KesRotationRequest,
  WithdrawalRequest,
  DRepChoice,
  DRepDelegationRequest,
  PoolUpdateRequest,
  VoteChoice,
  VoteRequest,
} from '@spo-tools/shared-frontend/types/wire'

type ParsedRequest =
  | { kind: 'leaderlog'; request: LeaderlogRequest }
  | { kind: 'kes-rotation'; request: KesRotationRequest }
  | { kind: 'withdrawal'; request: WithdrawalRequest }
  | { kind: 'drep-delegation'; request: DRepDelegationRequest }
  | { kind: 'pool-update'; request: PoolUpdateRequest }
  | { kind: 'vote'; request: VoteRequest }

function formatDrepChoice(c: DRepChoice): string {
  if (c.kind === 'abstain') return 'Abstain (always-abstain DRep)'
  if (c.kind === 'no_confidence') return 'No-confidence DRep'
  if (c.kind === 'key_hash') return `Specific DRep (key) — ${c.hash_hex.slice(0, 16)}…`
  if (c.kind === 'script_hash') return `Specific DRep (script) — ${c.hash_hex.slice(0, 16)}…`
  return 'unknown'
}

function formatVote(v: VoteChoice): string {
  if (v === 'yes') return 'Yes'
  if (v === 'no') return 'No'
  return 'Abstain'
}

function leaderlogSigma(req: LeaderlogRequest): string {
  const pool = Number(req.pool_stake)
  const total = Number(req.total_active_stake)
  if (!total || !Number.isFinite(pool) || !Number.isFinite(total)) return '—'
  return (pool / total).toExponential(4)
}

function activeSlotsCoeff(req: LeaderlogRequest): string {
  const numer = Number(req.active_slots_coeff_numer)
  const denom = Number(req.active_slots_coeff_denom)
  if (!denom || !Number.isFinite(numer) || !Number.isFinite(denom)) return '—'
  return (numer / denom).toString()
}

const notify = useNotificationStore()

const parsed = ref<ParsedRequest | null>(null)
const requestFingerprint = ref<string | null>(null)
const pinDialogOpen = ref(false)
const pinInput = ref('')
const pinError = ref<string | null>(null)
const originalFragments = ref<string[]>([])
const pasteInput = ref('')
const receiving = ref(false)
const receiveError = ref<string | null>(null)
const cameraEnlarged = ref(false)
const signing = ref(false)
const signError = ref<string | null>(null)
const result = ref<{ kind: string; ur_fragments: string[] } | null>(null)
const qrEnlarged = ref(false)
const qrIndex = ref(0)
const qrDataUrl = ref<string | null>(null)
let qrTimer: ReturnType<typeof setInterval> | null = null

async function submitFragments(fragments: string[]) {
  receiving.value = true
  receiveError.value = null
  try {
    const r = await fetch('/api/sign/receive', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ur_fragments: fragments }),
    })
    if (!r.ok) {
      const err = await extractError(r)
      if (err.code === 'not_paired') {
        notPaired.value = true
        return
      }
      throw new Error(err.message)
    }
    const rawResp: any = await r.json()
    requestFingerprint.value = rawResp.request_fingerprint || null
    parsed.value = rawResp
    originalFragments.value = fragments
    notify.success(`Received ${parsed.value?.kind} request`)
    await nextTick()
    previewCardEl.value?.$el?.scrollIntoView?.({ behavior: 'smooth', block: 'start' })
  } catch (e: unknown) {
    receiveError.value = e instanceof Error ? e.message : String(e)
  } finally {
    receiving.value = false
  }
}

async function onScannerComplete(fragments: string[]) {
  await submitFragments(fragments)
}

async function onScannerCompleteEnlarged(fragments: string[]) {
  cameraEnlarged.value = false
  await submitFragments(fragments)
}

async function submitPasted() {
  const fragments = pasteInput.value
    .split('\n')
    .map((s) => s.trim())
    .filter(Boolean)
  if (!fragments.length) return
  await submitFragments(fragments)
}

function cancelParse() {
  parsed.value = null
  requestFingerprint.value = null
  originalFragments.value = []
  pasteInput.value = ''
  receiveError.value = null
  signError.value = null
  result.value = null
  qrDataUrl.value = null
  qrIndex.value = 0
  cameraEnlarged.value = false
  qrEnlarged.value = false
  pinDialogOpen.value = false
  pinInput.value = ''
  pinError.value = null
  if (qrTimer) clearInterval(qrTimer)
  qrTimer = null
}

const scannerRef = ref<{ retry: () => Promise<void> } | null>(null)
const retryingCamera = ref(false)
// Refs to the currently-rendered preview-card (one of 5, dispatched on
// parsed.kind) and to the result-card. Used to scroll the operator's
// viewport to the active card after sign_receive / sign_execute land,
// keeping the focus rule consistent with the online-tool views.
const previewCardEl = ref<{ $el: HTMLElement } | null>(null)
const resultCardEl = ref<{ $el: HTMLElement } | null>(null)

async function retryCamera() {
  retryingCamera.value = true
  receiveError.value = null
  try {
    await scannerRef.value?.retry()
  } finally {
    retryingCamera.value = false
  }
}


function confirmAndSign() {
  if (!originalFragments.value.length) return
  pinInput.value = ''
  pinError.value = null
  pinDialogOpen.value = true
}

async function executeWithPin() {
  if (!/^\d{4}$/.test(pinInput.value)) {
    pinError.value = 'Enter exactly 4 digits'
    return
  }
  pinError.value = null
  pinDialogOpen.value = false
  signing.value = true
  signError.value = null
  try {
    const r = await fetch('/api/sign/execute', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ur_fragments: originalFragments.value, pin: pinInput.value }),
    })
    if (!r.ok) {
      const err = await extractError(r)
      if (err.code === 'not_paired') {
        notPaired.value = true
        return
      }
      throw new Error(err.message)
    }
    const d = await r.json()
    result.value = d
    // Strict signed-flow UX: once a result is present, the request preview
    // is no longer relevant — collapse it so the only visible card is
    // the result with its Start-new-session action. Prevents the user
    // from accidentally clicking the parsed-card's Cancel and losing
    // the just-signed payload.
    parsed.value = null
  requestFingerprint.value = null
    originalFragments.value = []
    pasteInput.value = ''
    qrIndex.value = 0
    await renderCurrentFrame()
    startQrCycle()
    notify.success(`Signed: ${d.kind}`)
    await nextTick()
    resultCardEl.value?.$el?.scrollIntoView?.({ behavior: 'smooth', block: 'start' })
  } catch (e: unknown) {
    signError.value = e instanceof Error ? e.message : String(e)
  } finally {
    signing.value = false
  }
}

async function renderCurrentFrame() {
  if (!result.value || !result.value.ur_fragments.length) return
  const fragment = result.value.ur_fragments[qrIndex.value]
  qrDataUrl.value = await QRCode.toDataURL(fragment, {
    margin: 1,
    width: 800,
    errorCorrectionLevel: 'M',
  })
}

function startQrCycle() {
  if (qrTimer) clearInterval(qrTimer)
  if (!result.value || result.value.ur_fragments.length <= 1) return
  qrTimer = setInterval(async () => {
    qrIndex.value = (qrIndex.value + 1) % (result.value?.ur_fragments.length ?? 1)
    await renderCurrentFrame()
  }, QR_CYCLE_INTERVAL_MS)
}

async function copyResultUr() {
  if (!result.value) return
  try {
    await navigator.clipboard.writeText(result.value.ur_fragments.join('\n'))
    notify.success('Result UR fragments copied to clipboard')
  } catch (e: unknown) {
    notify.error('Could not copy: ' + (e instanceof Error ? e.message : String(e)))
  }
}

function startNewSession() {
  cancelParse()
}

const notConfigured = ref(false)
const notPaired = ref(false)

async function checkConfigured() {
  try {
    const r = await fetch('/api/signer-config')
    if (!r.ok) return
    const d = await r.json()
    notConfigured.value = !d.saved
  } catch {
    // Config endpoint unreachable — leave notConfigured at false rather
    // than blocking the UI on what is likely a transient fetch issue.
  }
}

onMounted(() => {
  checkConfigured()
})

onUnmounted(() => {
  if (qrTimer) clearInterval(qrTimer)
})

</script>

<style scoped>
.field-stack {
  display: flex;
  flex-direction: column;
  gap: 0.85rem;
}
.field-row {
  display: flex;
  gap: 1.5rem;
  flex-wrap: wrap;
}
.field-row .field { flex: 1 1 auto; min-width: 120px; }
.field-label {
  font-size: 0.7rem;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: rgba(255, 255, 255, 0.55);
  margin-bottom: 0.15rem;
}
.field-value {
  font-size: 0.875rem;
  word-break: break-all;
}
</style>

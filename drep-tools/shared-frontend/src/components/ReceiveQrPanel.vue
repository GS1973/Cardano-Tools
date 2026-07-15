<template>
  <div>
  <v-card class="mb-4">
    <v-card-text>
      <h3 class="text-subtitle-1 mt-0 mb-2">{{ title }}</h3>
      <p class="text-body-2 text-medium-emphasis mb-3">
        <slot>
          Scan the animated QR shown on the signer or paste the UR fragments shown on the signer.
        </slot>
      </p>
      <div class="d-flex" style="gap: 1rem; align-items: flex-start;">
        <div v-if="!cameraEnlarged" class="d-flex flex-column align-center" style="flex: 0 0 auto;">
          <div style="width: 160px;">
            <QRScanner
              ref="scannerRef"
              @complete="(fragments: string[]) => $emit('scanner-complete', fragments)"
              @error="(msg: string) => $emit('scanner-error', msg)"
            />
          </div>
          <v-btn class="mt-2" size="small" variant="text" prepend-icon="mdi-arrow-expand" @click="$emit('update:cameraEnlarged', true)">Enlarge</v-btn>
        </div>
        <div style="flex: 1 1 auto; min-width: 0;">
          <!-- Placeholder mirrors airgap-core's UR_TYPE_ACTION tag ("spo-tools-action-v2"), shared across products — not a typo. -->
          <v-textarea
            :model-value="resultInput"
            @update:model-value="(v: string) => $emit('update:resultInput', v)"
            label="UR fragments from signer"
            rows="6"
            variant="outlined"
            density="compact"
            hide-details
            placeholder="ur:spo-tools-action-v2/..."
          />
          <v-btn
            class="mt-2"
            color="primary"
            :loading="submitting"
            :disabled="!resultInput.trim()"
            prepend-icon="mdi-upload"
            @click="$emit('submit')"
          >{{ submitLabel }}</v-btn>
        </div>
      </div>
      <v-alert v-if="resultError" type="error" density="compact" variant="tonal" class="mt-3">
        {{ resultError }}
        <template #append>
          <v-btn
            size="x-small"
            variant="text"
            :loading="retryingCamera"
            class="text-white"
            prepend-icon="mdi-refresh"
            @click="$emit('retry-camera')"
          >Try again</v-btn>
        </template>
      </v-alert>
    </v-card-text>
  </v-card>

  <v-dialog
    :model-value="cameraEnlarged"
    @update:model-value="(v: boolean) => $emit('update:cameraEnlarged', v)"
    max-width="640"
  >
    <v-card>
      <v-card-text class="d-flex flex-column align-center pa-6">
        <div style="width: 480px;">
          <QRScanner
            v-if="cameraEnlarged"
            @complete="(fragments: string[]) => $emit('scanner-complete-enlarged', fragments)"
            @error="(msg: string) => { $emit('scanner-error', msg); $emit('update:cameraEnlarged', false) }"
          />
        </div>
        <v-btn class="mt-3" variant="text" prepend-icon="mdi-arrow-collapse" @click="$emit('update:cameraEnlarged', false)">Shrink</v-btn>
      </v-card-text>
    </v-card>
  </v-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import QRScanner from './QRScanner.vue'

const scannerRef = ref<InstanceType<typeof QRScanner> | null>(null)

withDefaults(
  defineProps<{
    resultInput: string
    cameraEnlarged: boolean
    retryingCamera: boolean
    resultError: string | null
    submitting: boolean
    title?: string
    submitLabel?: string
  }>(),
  {
    title: 'Receive signed result',
    submitLabel: 'Receive result',
    resultError: null,
  },
)

defineEmits<{
  (e: 'update:resultInput', value: string): void
  (e: 'update:cameraEnlarged', value: boolean): void
  (e: 'submit'): void
  (e: 'retry-camera'): void
  (e: 'scanner-complete', fragments: string[]): void
  (e: 'scanner-error', msg: string): void
  (e: 'scanner-complete-enlarged', fragments: string[]): void
}>()

/** Restart the embedded camera scanner. Exposed so parents can bind this
 *  panel into `useScannerControl.scannerRef`, making 'Try again' work. */
async function retry(): Promise<void> {
  await scannerRef.value?.retry()
}

defineExpose({ retry })
</script>

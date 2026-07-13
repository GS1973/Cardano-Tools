<template>
  <v-dialog
    :model-value="modelValue"
    max-width="640"
    persistent
    @update:model-value="(v) => onModelChange(v)"
  >
    <v-card>
      <v-card-title>{{ title }}</v-card-title>
      <v-card-text>
        <p class="text-body-2 text-medium-emphasis mb-3">
          Review the operation summary below. Once you click <strong>Send to signer</strong>,
          the encrypted QR fragments are generated and the operator-PIN you type
          here is hashed into the request. The signer will prompt for the same
          PIN after decrypting the payload.
        </p>
        <slot />
        <div class="mt-4">
          <p class="text-body-2 mb-1"><strong>Operator PIN</strong></p>
          <p class="text-caption text-medium-emphasis mb-2">
            Pick any 4 digits — you will retype the same PIN on the signer screen
            to confirm operator presence at sign time.
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
            @keydown.enter="onConfirmClick"
          />
        </div>
      </v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn variant="text" @click="onCancel">Cancel</v-btn>
        <v-btn
          color="primary"
          prepend-icon="mdi-send"
          :disabled="!pinValid"
          @click="onConfirmClick"
        >
          Send to signer
        </v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue'

const props = defineProps<{
  modelValue: boolean
  title: string
}>()
const emit = defineEmits<{
  (e: 'update:modelValue', v: boolean): void
  (e: 'confirm', payload: { pin: string }): void
}>()

const pinInput = ref('')
const pinError = ref<string | null>(null)

const pinValid = computed(() => /^\d{4}$/.test(pinInput.value))

watch(() => props.modelValue, (v) => {
  if (v) {
    pinInput.value = ''
    pinError.value = null
  }
})

function onModelChange(v: boolean) {
  emit('update:modelValue', v)
}

function onCancel() {
  emit('update:modelValue', false)
}

function onConfirmClick() {
  if (!pinValid.value) {
    pinError.value = 'Enter exactly 4 digits'
    return
  }
  pinError.value = null
  emit('confirm', { pin: pinInput.value })
}
</script>

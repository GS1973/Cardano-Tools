<template>
  <v-card>
    <v-card-text class="text-center py-8">
      <v-icon icon="mdi-shield-link-variant-outline" size="48" class="text-medium-emphasis mb-3" />
      <h3 class="text-h6 mb-2">Not paired with the online tool</h3>
      <p class="text-medium-emphasis mb-4">
        This signer needs to exchange public keys with the online tool
        once before any sign request can be processed. Open Pairing and
        complete the QR / fingerprint compare on both sides.
      </p>
      <v-btn color="primary" prepend-icon="mdi-link-variant" :to="'/pairing'">Go to Pairing</v-btn>
    </v-card-text>
  </v-card>
</template>

<template>
  <v-card>
    <v-card-text class="text-center py-8">
      <v-icon icon="mdi-cog-outline" size="48" class="text-medium-emphasis mb-3" />
      <h3 class="text-h6 mb-2">DRep not configured</h3>
      <p class="text-medium-emphasis mb-4">
        Enter your DRep id and payment address in Setup to start using the tools.
      </p>
      <v-btn color="primary" prepend-icon="mdi-cog" :to="'/setup'">Go to Setup</v-btn>
    </v-card-text>
  </v-card>
</template>

<template>
  <v-card>
    <v-card-text class="text-center py-8">
      <v-icon icon="mdi-wallet-outline" size="48" class="text-medium-emphasis mb-3" />
      <h3 class="text-h6 mb-2">No wallet configured</h3>
      <p class="text-medium-emphasis mb-4">
        Add one of your wallets in the Address book to start using the tools.
      </p>
      <v-btn color="primary" prepend-icon="mdi-book-account" :to="'/address-book'">Go to Address book</v-btn>
    </v-card-text>
  </v-card>
</template>

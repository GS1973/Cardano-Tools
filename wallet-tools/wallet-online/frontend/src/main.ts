import { createApp } from 'vue'
import { createPinia } from 'pinia'
import { createVuetify } from 'vuetify'
import 'vuetify/styles'
import '@mdi/font/css/materialdesignicons.css'
import '@wallet-tools/shared-frontend/style.css'
import { walletToolsTheme, walletToolsDefaults } from '@wallet-tools/shared-frontend/theme'
import App from './App.vue'
import router from './router'

const vuetify = createVuetify({
  theme: walletToolsTheme,
  defaults: walletToolsDefaults,
})

createApp(App).use(createPinia()).use(vuetify).use(router).mount('#app')

import { createApp } from 'vue'
import { createPinia } from 'pinia'
import { createVuetify } from 'vuetify'
import 'vuetify/styles'
import '@mdi/font/css/materialdesignicons.css'
import '@drep-tools/shared-frontend/style.css'
import { drepToolsTheme, drepToolsDefaults } from '@drep-tools/shared-frontend/theme'
import App from './App.vue'
import router from './router'

const vuetify = createVuetify({
  theme: drepToolsTheme,
  defaults: drepToolsDefaults,
})

createApp(App).use(createPinia()).use(vuetify).use(router).mount('#app')

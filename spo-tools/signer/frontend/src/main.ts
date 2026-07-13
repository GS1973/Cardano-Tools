import { createApp } from 'vue'
import { createPinia } from 'pinia'
import { createVuetify } from 'vuetify'
import 'vuetify/styles'
import '@mdi/font/css/materialdesignicons.css'
import '@spo-tools/shared-frontend/style.css'
import { spoToolsTheme, spoToolsDefaults } from '@spo-tools/shared-frontend/theme'
import App from './App.vue'
import router from './router'

const vuetify = createVuetify({
  theme: spoToolsTheme,
  defaults: spoToolsDefaults,
})

createApp(App).use(createPinia()).use(vuetify).use(router).mount('#app')

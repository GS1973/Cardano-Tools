import { defineStore } from 'pinia'

type Color = 'success' | 'error' | 'info' | 'warning'

interface NotificationState {
  visible: boolean
  text: string
  color: Color
  timeout: number
}

export const useNotificationStore = defineStore('notification', {
  state: (): NotificationState => ({
    visible: false,
    text: '',
    color: 'info',
    timeout: 4000,
  }),
  actions: {
    show(text: string, color: Color = 'info', timeout = 4000) {
      this.text = text
      this.color = color
      this.timeout = timeout
      this.visible = true
    },
    success(text: string, timeout = 4000) { this.show(text, 'success', timeout) },
    error(text: string, timeout = 6000) { this.show(text, 'error', timeout) },
    info(text: string, timeout = 4000) { this.show(text, 'info', timeout) },
    warn(text: string, timeout = 5000) { this.show(text, 'warning', timeout) },
  },
})

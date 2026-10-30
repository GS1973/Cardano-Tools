import { ref, onUnmounted } from 'vue'
import QRCode from 'qrcode'
import {
  QR_CYCLE_INTERVAL_MS,
  QRCODE_OPTIONS,
} from '@drep-tools/shared-frontend/constants/timings'
import { useNotificationStore } from '@drep-tools/shared-frontend/stores/notification'

/**
 * Send-side QR carousel state + lifecycle for an operational view.
 *
 * Reactive carousel only: fragments / index / dataUrl + start/stop/reset
 * + clipboard copy. Camera-scanner state lives in `useScannerControl`:
 * a view that needs both calls them as two separate composables, which
 * keeps each one independently testable.
 *
 * Registers its own `onUnmounted` hook so the carousel timer stops when
 * the view leaves the DOM.
 */
export function useQrCarousel() {
  const fragments = ref<string[]>([])
  const index = ref(0)
  const dataUrl = ref<string | null>(null)
  let timer: ReturnType<typeof setInterval> | null = null

  const notify = useNotificationStore()

  async function renderCurrentFrame(): Promise<void> {
    if (!fragments.value.length) return
    dataUrl.value = await QRCode.toDataURL(
      fragments.value[index.value],
      QRCODE_OPTIONS,
    )
  }

  function stopCycle(): void {
    if (timer) {
      clearInterval(timer)
      timer = null
    }
  }

  function startCycle(): void {
    stopCycle()
    if (fragments.value.length <= 1) return
    timer = setInterval(async () => {
      index.value = (index.value + 1) % fragments.value.length
      await renderCurrentFrame()
    }, QR_CYCLE_INTERVAL_MS)
  }

  function reset(): void {
    stopCycle()
    fragments.value = []
    index.value = 0
    dataUrl.value = null
  }

  async function copyToClipboard(): Promise<void> {
    if (!fragments.value.length) return
    try {
      await navigator.clipboard.writeText(fragments.value.join('\n'))
      notify.success('UR fragments copied to clipboard')
    } catch (e: unknown) {
      notify.error(
        'Could not copy: ' + (e instanceof Error ? e.message : String(e)),
      )
    }
  }

  onUnmounted(stopCycle)

  return {
    fragments,
    index,
    dataUrl,
    renderCurrentFrame,
    startCycle,
    stopCycle,
    reset,
    copyToClipboard,
  }
}

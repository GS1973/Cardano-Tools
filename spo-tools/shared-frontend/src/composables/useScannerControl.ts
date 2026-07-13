import { ref } from 'vue'

/**
 * Camera-scanner control split out from `useQrCarousel` so a view that
 * needs only the scanner (paste-only flow, future test-only mounts) can
 * import it without bringing in carousel state or QRCode rendering.
 *
 * Exposes the `scannerRef` ref (bound to a component exposing `retry` —
 * `<QRScanner>` directly or a `<ReceiveQrPanel>` wrapping one), a
 * `retryingCamera` boolean that gates the spinner on the Retry button,
 * and a `retry()` helper that calls into the scanner's exposed `retry`
 * method while flipping the spinner state.
 */
export function useScannerControl() {
  const scannerRef = ref<{ retry?: () => Promise<void> } | null>(null)
  const retryingCamera = ref(false)

  async function retry(): Promise<void> {
    retryingCamera.value = true
    try {
      const r = scannerRef.value?.retry
      if (typeof r === 'function') await r()
    } finally {
      retryingCamera.value = false
    }
  }

  return {
    scannerRef,
    retryingCamera,
    retry,
  }
}

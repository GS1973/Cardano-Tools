// Hand-written, NOT ts_rs-generated. Re-exports the role-neutral error
// types owned by airgap-core so the online views can import them from a
// stable path. The previous re-export lived inside the generated wire.ts
// and was silently dropped by a ts_rs regen; keeping it here is regen-proof.
export type { ErrorCode, ErrorEnvelope } from '@airgap-core/frontend/types/core-wire'

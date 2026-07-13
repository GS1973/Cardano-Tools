// Hand-written — NOT ts_rs-generated. Re-exports the role-neutral wire types
// owned by airgap-core so consumers import them from a stable path that a
// ts_rs regen cannot clobber. The previous re-export was appended to the
// generated wire.ts and only survived because the gen script re-added it; a
// raw `cargo test` would drop it. The types still originate in airgap-core.
export type {
  ChainContext,
  UtxoInput,
  VkeyWitness,
  WitnessRole,
  ErrorCode,
  ErrorEnvelope,
} from '@airgap-core/frontend/types/core-wire'

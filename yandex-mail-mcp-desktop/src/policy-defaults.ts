// policy-defaults.ts -- canonical defaults for the PMLF risk policy.
//
// This file is the foundation for the Phase 1 Policy Module. Numbers below
// derive from the outbound-content-dictionary.md tier system (25/50/75) but
// adjusted to integer cleanness for human tuning. Operators tune at runtime
// by editing <state-dir>/risk-policy.json (HMAC-signed; see policy.ts).
//
// DO NOT mutate DEFAULT_POLICY at runtime: policy.ts deep-freezes the loaded
// or fallback result before caching. We keep this constant as plain data so
// Zod can validate it on every load.

export interface RiskPolicy {
  version: 1;
  weights: {
    // Trust signals
    new_trust: number;
    first_use: number;
    just_auto_trusted: number;

    // Content signals (from Phase 2 outbound scanner)
    base64_in_body: number;
    api_key_pattern: number;
    emails_in_body: number;
    payment_card: number;
    govt_id: number;
    medical_secret: number;
    medical_elevated: number;
    classified_marking: number;
    crypto_seed: number;
    data_shape_anomaly: number;

    // Provenance signals (from Phase 3)
    post_read_send: number;
    cross_thread: number;

    // Volume signals
    multi_recipient: number;
    large_body: number;

    // Velocity signals (from Phase 7 guards)
    burst_pattern: number;

    // Phase 2 plan-02 (cat 2.4 credentials_fuzzy keyword pass)
    // outbound_keyword: per-keyword weight (low because cat 2.4 hits are
    // ALWAYS companion-gated -- never fire standalone).
    // outbound_keyword_cap: maximum aggregate weight contribution from cat 2.4
    // across an entire scan (prevents keyword-spam inflation).
    outbound_keyword: number;
    outbound_keyword_cap: number;
  };
  thresholds: {
    augment: number;
    strict: number;
    block: number;
  };
  outbound_keywords: string[];
  blocked_domains: string[];
  provenance_window_sec: number;
  burst_window_sec: number;
  burst_threshold: number;
  categories: {
    payment_cards: boolean;
    ru_banking: boolean;
    govt_ids: boolean;
    credentials_fuzzy: boolean;
    structural_secrets: boolean;
    crypto_web3: boolean;
    medical: boolean;
    classified_markings: boolean;
    exfil_phrases: boolean;
    data_shapes: boolean;
    demographic_pii: boolean;
  };
  override_block_threshold: boolean;
}

export const DEFAULT_POLICY: RiskPolicy = {
  version: 1,
  weights: {
    new_trust: 30,
    first_use: 20,
    just_auto_trusted: 40,

    base64_in_body: 30,
    api_key_pattern: 75,
    emails_in_body: 20,
    payment_card: 60,
    govt_id: 60,
    medical_secret: 40,
    medical_elevated: 60,
    classified_marking: 50,
    crypto_seed: 75,
    data_shape_anomaly: 30,

    post_read_send: 30,
    cross_thread: 15,

    multi_recipient: 20,
    large_body: 15,

    burst_pattern: 25,

    outbound_keyword: 10,
    outbound_keyword_cap: 40,
  },
  thresholds: {
    augment: 30,
    strict: 60,
    block: 100,
  },
  outbound_keywords: [],
  blocked_domains: [],
  provenance_window_sec: 30,
  burst_window_sec: 120,
  burst_threshold: 3,
  categories: {
    payment_cards: true,
    ru_banking: true,
    govt_ids: true,
    credentials_fuzzy: true,
    structural_secrets: true,
    crypto_web3: true,
    medical: true,
    classified_markings: true,
    exfil_phrases: true,
    data_shapes: true,
    demographic_pii: true,
  },
  override_block_threshold: false,
};

;; OmniSkill - Decentralized Skill Verification Protocol
;; Clarity Version: 2
;; Epoch: 2.1
;;
;; Features:
;;   - Skill attestation and credential minting
;;   - Time-weighted reputation scoring
;;   - Skill decay over time (credential weakens unless refreshed)
;;   - Authorized verifier access control
;;   - Progressive skill disclosure (commitment-reveal scheme)
;;   - Cross-user skill endorsements

;; ============================================================
;; Constants
;; ============================================================

(define-constant CONTRACT-OWNER tx-sender)

;; Error codes
(define-constant ERR-NOT-AUTHORIZED        (err u100))
(define-constant ERR-SKILL-NOT-FOUND       (err u101))
(define-constant ERR-ALREADY-EXISTS        (err u102))
(define-constant ERR-INVALID-SCORE         (err u103))
(define-constant ERR-NOT-VERIFIER          (err u104))
(define-constant ERR-COMMITMENT-MISMATCH   (err u105))
(define-constant ERR-ALREADY-REVEALED      (err u106))
(define-constant ERR-INVALID-DECAY         (err u107))
(define-constant ERR-SELF-ENDORSE          (err u108))

;; Skill decay period: number of blocks before full decay (~1 year at ~144 blocks/day)
(define-constant DECAY-PERIOD u52560)

;; Maximum reputation score
(define-constant MAX-SCORE u1000)

;; ============================================================
;; Data Variables
;; ============================================================

;; Tracks the next skill NFT token ID
(define-data-var next-skill-id uint u1)

;; ============================================================
;; Data Maps
;; ============================================================

;; Core skill credential record
;; skill-id -> credential metadata
(define-map skill-credentials
  { skill-id: uint }
  {
    owner:          principal,
    skill-name:     (string-ascii 64),
    ;; Hashed metadata: keccak256(skill-details + salt) stored as commitment
    metadata-hash:  (buff 32),
    issued-at:      uint,      ;; block height at issuance
    refreshed-at:   uint,      ;; block height of last refresh
    base-score:     uint,      ;; 0-1000
    is-revealed:    bool       ;; whether owner has revealed plaintext metadata
  }
)

;; Maps owner -> list of their skill IDs (up to 20 skills per user)
(define-map owner-skills
  { owner: principal }
  { skill-ids: (list 20 uint) }
)

;; Authorized verifiers: only verifiers can read revealed metadata
(define-map authorized-verifiers
  { verifier: principal }
  { domain: (string-ascii 64), active: bool }
)

;; Verifier endorsements: (verifier, skill-id) -> endorsement score
(define-map endorsements
  { verifier: principal, skill-id: uint }
  { score: uint, endorsed-at: uint }
)

;; Commitment-reveal: owner commits plaintext skill details off-chain,
;; stores a hash, and can later reveal to authorized verifiers.
;; skill-id -> revealed plaintext (only set after reveal)
(define-map revealed-metadata
  { skill-id: uint }
  { plaintext: (string-ascii 256), revealed-at: uint }
)

;; Tracks which (verifier, skill-id) pairs have been granted access
(define-map verifier-access
  { verifier: principal, skill-id: uint }
  { granted-at: uint }
)

;; ============================================================
;; Private Helpers
;; ============================================================

;; Compute time-weighted score applying linear decay.
;; Score reduces proportionally as blocks pass since last refresh.
;; Returns 0 if past the full decay period.
(define-private (compute-effective-score (base-score uint) (refreshed-at uint))
  (let (
    (elapsed (- block-height refreshed-at))
  )
    (if (>= elapsed DECAY-PERIOD)
      u0
      (/ (* base-score (- DECAY-PERIOD elapsed)) DECAY-PERIOD)
    )
  )
)

;; Check if caller is the contract owner
(define-private (is-owner)
  (is-eq tx-sender CONTRACT-OWNER)
)

;; Check if a principal is an active authorized verifier
(define-private (is-active-verifier (addr principal))
  (match (map-get? authorized-verifiers { verifier: addr })
    entry (get active entry)
    false
  )
)

;; ============================================================
;; Verifier Management (owner only)
;; ============================================================

;; Register a new verifier with a domain label
(define-public (register-verifier (verifier principal) (domain (string-ascii 64)))
  (begin
    (asserts! (is-owner) ERR-NOT-AUTHORIZED)
    (asserts! (is-none (map-get? authorized-verifiers { verifier: verifier })) ERR-ALREADY-EXISTS)
    (ok (map-set authorized-verifiers
      { verifier: verifier }
      { domain: domain, active: true }
    ))
  )
)

;; Deactivate a verifier
(define-public (deactivate-verifier (verifier principal))
  (begin
    (asserts! (is-owner) ERR-NOT-AUTHORIZED)
    (match (map-get? authorized-verifiers { verifier: verifier })
      entry (ok (map-set authorized-verifiers
                  { verifier: verifier }
                  (merge entry { active: false })
                ))
      ERR-NOT-VERIFIER
    )
  )
)

;; ============================================================
;; Skill Credential Minting
;; ============================================================

;; Mint a new skill credential NFT.
;; Owner stores a commitment hash; plaintext is kept off-chain.
(define-public (mint-skill
    (skill-name     (string-ascii 64))
    (metadata-hash  (buff 32))
    (base-score     uint))
  (let (
    (skill-id (var-get next-skill-id))
    (current-skills (default-to { skill-ids: (list) }
                      (map-get? owner-skills { owner: tx-sender })))
  )
    (asserts! (<= base-score MAX-SCORE) ERR-INVALID-SCORE)
    (asserts! (is-none (map-get? skill-credentials { skill-id: skill-id })) ERR-ALREADY-EXISTS)

    ;; Store credential
    (map-set skill-credentials
      { skill-id: skill-id }
      {
        owner:         tx-sender,
        skill-name:    skill-name,
        metadata-hash: metadata-hash,
        issued-at:     block-height,
        refreshed-at:  block-height,
        base-score:    base-score,
        is-revealed:   false
      }
    )

    ;; Append skill-id to owner index (max 20 skills enforced by list limit)
    (map-set owner-skills
      { owner: tx-sender }
      { skill-ids: (unwrap-panic (as-max-len?
          (append (get skill-ids current-skills) skill-id)
          u20)) }
    )

    ;; Advance token counter
    (var-set next-skill-id (+ skill-id u1))
    (ok skill-id)
  )
)

;; ============================================================
;; Skill Refresh (resets decay timer)
;; ============================================================

(define-public (refresh-skill (skill-id uint))
  (match (map-get? skill-credentials { skill-id: skill-id })
    credential
    (begin
      (asserts! (is-eq tx-sender (get owner credential)) ERR-NOT-AUTHORIZED)
      (ok (map-set skill-credentials
            { skill-id: skill-id }
            (merge credential { refreshed-at: block-height })
          ))
    )
    ERR-SKILL-NOT-FOUND
  )
)

;; ============================================================
;; Commitment-Reveal Scheme
;; ============================================================

;; Owner reveals plaintext metadata for a skill.
;; The hash of (plaintext + salt) must match the stored commitment.
;; Salt is hashed off-chain; here we verify the caller is the owner
;; and that the skill has not already been revealed.
;; Full ZK proof verification would occur off-chain or via an oracle.
(define-public (reveal-skill-metadata
    (skill-id  uint)
    (plaintext (string-ascii 256)))
  (match (map-get? skill-credentials { skill-id: skill-id })
    credential
    (begin
      (asserts! (is-eq tx-sender (get owner credential)) ERR-NOT-AUTHORIZED)
      (asserts! (not (get is-revealed credential)) ERR-ALREADY-REVEALED)

      ;; Mark credential as revealed
      (map-set skill-credentials
        { skill-id: skill-id }
        (merge credential { is-revealed: true })
      )

      ;; Store revealed plaintext
      (map-set revealed-metadata
        { skill-id: skill-id }
        { plaintext: plaintext, revealed-at: block-height }
      )
      (ok true)
    )
    ERR-SKILL-NOT-FOUND
  )
)

;; ============================================================
;; Verifier Access Grant
;; ============================================================

;; Skill owner grants a specific verifier access to their revealed metadata.
;; Implements progressive disclosure based on trust.
(define-public (grant-verifier-access (skill-id uint) (verifier principal))
  (match (map-get? skill-credentials { skill-id: skill-id })
    credential
    (begin
      (asserts! (is-eq tx-sender (get owner credential)) ERR-NOT-AUTHORIZED)
      (asserts! (is-active-verifier verifier) ERR-NOT-VERIFIER)
      (ok (map-set verifier-access
            { verifier: verifier, skill-id: skill-id }
            { granted-at: block-height }
          ))
    )
    ERR-SKILL-NOT-FOUND
  )
)

;; ============================================================
;; Endorsements (Proof-of-Skill by Validators)
;; ============================================================

;; An authorized verifier endorses a skill with a score.
;; Verifiers must be active and cannot endorse their own credentials.
(define-public (endorse-skill (skill-id uint) (score uint))
  (begin
    (asserts! (is-active-verifier tx-sender) ERR-NOT-VERIFIER)
    (asserts! (<= score MAX-SCORE) ERR-INVALID-SCORE)

    (match (map-get? skill-credentials { skill-id: skill-id })
      credential
      (begin
        (asserts! (not (is-eq tx-sender (get owner credential))) ERR-SELF-ENDORSE)
        ;; Verifier must have been granted access before endorsing
        (asserts!
          (is-some (map-get? verifier-access { verifier: tx-sender, skill-id: skill-id }))
          ERR-NOT-AUTHORIZED)
        (ok (map-set endorsements
              { verifier: tx-sender, skill-id: skill-id }
              { score: score, endorsed-at: block-height }
            ))
      )
      ERR-SKILL-NOT-FOUND
    )
  )
)

;; ============================================================
;; Read-Only Functions
;; ============================================================

;; Get credential public info (hash, name, scores) - always public
(define-read-only (get-credential (skill-id uint))
  (match (map-get? skill-credentials { skill-id: skill-id })
    credential
    (ok {
      owner:          (get owner credential),
      skill-name:     (get skill-name credential),
      metadata-hash:  (get metadata-hash credential),
      issued-at:      (get issued-at credential),
      refreshed-at:   (get refreshed-at credential),
      base-score:     (get base-score credential),
      effective-score: (compute-effective-score
                          (get base-score credential)
                          (get refreshed-at credential)),
      is-revealed:    (get is-revealed credential)
    })
    ERR-SKILL-NOT-FOUND
  )
)

;; Get revealed metadata - only callable by authorized verifiers with access
(define-read-only (get-revealed-metadata (skill-id uint))
  (begin
    (asserts! (is-active-verifier tx-sender) ERR-NOT-VERIFIER)
    (asserts!
      (is-some (map-get? verifier-access { verifier: tx-sender, skill-id: skill-id }))
      ERR-NOT-AUTHORIZED)
    (match (map-get? revealed-metadata { skill-id: skill-id })
      data (ok data)
      ERR-SKILL-NOT-FOUND
    )
  )
)

;; Get all skill IDs for a given owner
(define-read-only (get-owner-skills (owner principal))
  (default-to { skill-ids: (list) } (map-get? owner-skills { owner: owner }))
)

;; Get endorsement for a (verifier, skill) pair
(define-read-only (get-endorsement (verifier principal) (skill-id uint))
  (map-get? endorsements { verifier: verifier, skill-id: skill-id })
)

;; Get effective (decay-adjusted) score for a skill
(define-read-only (get-effective-score (skill-id uint))
  (match (map-get? skill-credentials { skill-id: skill-id })
    credential
    (ok (compute-effective-score
          (get base-score credential)
          (get refreshed-at credential)))
    ERR-SKILL-NOT-FOUND
  )
)

;; Check if a verifier is active
(define-read-only (get-verifier-info (verifier principal))
  (map-get? authorized-verifiers { verifier: verifier })
)

;; Check if a verifier has been granted access to a skill
(define-read-only (has-verifier-access (verifier principal) (skill-id uint))
  (is-some (map-get? verifier-access { verifier: verifier, skill-id: skill-id }))
)

;; Identity Registry
;; Core identity management with verification levels and metadata

;; Constants
(define-constant ERR_UNAUTHORIZED (err u401))
(define-constant ERR_NOT_FOUND (err u404))
(define-constant ERR_ALREADY_EXISTS (err u409))
(define-constant ERR_INVALID_LEVEL (err u400))
(define-constant ERR_INSUFFICIENT_LEVEL (err u403))
(define-constant ERR_EXPIRED (err u410))

;; Data Variables
(define-data-var registry-admin principal tx-sender)
(define-data-var identity-counter uint u0)
(define-data-var verification-fee uint u100000) ;; 0.1 STX in microSTX

;; Verification Levels
(define-constant LEVEL_UNVERIFIED u0)
(define-constant LEVEL_EMAIL u1)
(define-constant LEVEL_PHONE u2)
(define-constant LEVEL_DOCUMENT u3)
(define-constant LEVEL_BIOMETRIC u4)
(define-constant LEVEL_INSTITUTION u5)

;; Identity Status
(define-constant STATUS_ACTIVE u1)
(define-constant STATUS_SUSPENDED u2)
(define-constant STATUS_REVOKED u3)

;; Maps
(define-map identities
    { did: principal }
    {
        identity-id: uint,
        verification-level: uint,
        status: uint,
        creation-date: uint,
        last-update: uint,
        reputation-score: uint,
        metadata-hash: (optional (string-ascii 64)), ;; IPFS hash for extended metadata
        recovery-address: (optional principal),
        verification-expiry: uint
    }
)

(define-map verification-history
    { did: principal, verification-id: uint }
    {
        verification-type: uint,
        issuer: principal,
        verification-date: uint,
        expiry-date: uint,
        proof-hash: (string-ascii 64),
        status: uint
    }
)

(define-map trusted-issuers
    { issuer: principal }
    {
        name: (string-ascii 100),
        verification-types: uint, ;; Bitmask of supported verification types
        reputation: uint,
        registration-date: uint,
        is-active: bool
    }
)

(define-map identity-attributes
    { did: principal, attribute-type: (string-ascii 50) }
    {
        value-hash: (string-ascii 64), ;; Hashed value for privacy
        is-verified: bool,
        verifier: (optional principal),
        verification-date: uint,
        access-level: uint ;; Who can access this attribute
    }
)

(define-map recovery-requests
    { did: principal }
    {
        requester: principal,
        new-recovery-address: principal,
        request-date: uint,
        approval-count: uint,
        required-approvals: uint,
        status: uint
    }
)

;; Statistics
(define-data-var total-verifications uint u0)
(define-data-var verification-counter uint u0)

;; Register new identity
(define-public (register-identity (metadata-hash (optional (string-ascii 64))) (recovery-address (optional principal)))
    (let ((identity-id (+ (var-get identity-counter) u1)))
        
        ;; Check if identity already exists
        (asserts! (is-none (map-get? identities { did: tx-sender })) ERR_ALREADY_EXISTS)
        
        ;; Create identity record
        (map-set identities { did: tx-sender }
            {
                identity-id: identity-id,
                verification-level: LEVEL_UNVERIFIED,
                status: STATUS_ACTIVE,
                creation-date: block-height,
                last-update: block-height,
                reputation-score: u100, ;; Start with neutral reputation
                metadata-hash: metadata-hash,
                recovery-address: recovery-address,
                verification-expiry: (+ block-height u52560) ;; ~1 year
            }
        )
        
        (var-set identity-counter identity-id)
        (ok identity-id)
    )
)

;; Update verification level (called by trusted issuers)
(define-public (verify-identity 
    (did principal) 
    (verification-type uint) 
    (proof-hash (string-ascii 64))
    (expiry-blocks uint)
)
    (let ((identity-data (unwrap! (map-get? identities { did: did }) ERR_NOT_FOUND))
          (issuer-data (unwrap! (map-get? trusted-issuers { issuer: tx-sender }) ERR_UNAUTHORIZED))
          (verification-id (+ (var-get verification-counter) u1)))
        
        ;; Check issuer is authorized for this verification type
        (asserts! (get is-active issuer-data) ERR_UNAUTHORIZED)
        ;; Simplified authorization check - in production would use proper bitwise operations
        (asserts! (> (get verification-types issuer-data) u0) ERR_UNAUTHORIZED)
        
        ;; Create verification record
        (map-set verification-history { did: did, verification-id: verification-id }
            {
                verification-type: verification-type,
                issuer: tx-sender,
                verification-date: block-height,
                expiry-date: (+ block-height expiry-blocks),
                proof-hash: proof-hash,
                status: STATUS_ACTIVE
            }
        )
        
        ;; Update identity verification level if higher
        (let ((new-level (if (> verification-type (get verification-level identity-data))
                            verification-type
                            (get verification-level identity-data))))
            
            (map-set identities { did: did }
                (merge identity-data 
                    {
                        verification-level: new-level,
                        last-update: block-height,
                        verification-expiry: (+ block-height expiry-blocks),
                        reputation-score: (if (< (+ (get reputation-score identity-data) u50) u1000)
                                              (+ (get reputation-score identity-data) u50)
                                              u1000)
                    }
                )
            )
        )
        
        (var-set verification-counter verification-id)
        (var-set total-verifications (+ (var-get total-verifications) u1))
        (ok verification-id)
    )
)

;; Add or update identity attribute
(define-public (set-attribute 
    (attribute-type (string-ascii 50))
    (value-hash (string-ascii 64))
    (access-level uint)
)
    (let ((identity-data (unwrap! (map-get? identities { did: tx-sender }) ERR_NOT_FOUND)))
        
        (map-set identity-attributes { did: tx-sender, attribute-type: attribute-type }
            {
                value-hash: value-hash,
                is-verified: false,
                verifier: none,
                verification-date: u0,
                access-level: access-level
            }
        )
        
        (ok true)
    )
)

;; Verify attribute (called by trusted issuers)
(define-public (verify-attribute 
    (did principal)
    (attribute-type (string-ascii 50))
    (value-hash (string-ascii 64))
)
    (let ((identity-data (unwrap! (map-get? identities { did: did }) ERR_NOT_FOUND))
          (issuer-data (unwrap! (map-get? trusted-issuers { issuer: tx-sender }) ERR_UNAUTHORIZED))
          (current-attr (map-get? identity-attributes { did: did, attribute-type: attribute-type })))
        
        ;; Check issuer is active
        (asserts! (get is-active issuer-data) ERR_UNAUTHORIZED)
        
        ;; Verify the hash matches (if attribute exists)
        (match current-attr
            attr (begin
                (asserts! (is-eq (get value-hash attr) value-hash) ERR_INVALID_LEVEL)
                true
            )
            false
        )
        (asserts! (is-some current-attr) ERR_NOT_FOUND)
        
        ;; Update attribute as verified
        (map-set identity-attributes { did: did, attribute-type: attribute-type }
            (merge (unwrap-panic current-attr)
                {
                    is-verified: true,
                    verifier: (some tx-sender),
                    verification-date: block-height
                }
            )
        )
        
        (ok true)
    )
)

;; Register trusted issuer (admin only)
(define-public (register-issuer 
    (issuer principal)
    (name (string-ascii 100))
    (verification-types uint)
)
    (begin
        (asserts! (is-eq tx-sender (var-get registry-admin)) ERR_UNAUTHORIZED)
        
        (map-set trusted-issuers { issuer: issuer }
            {
                name: name,
                verification-types: verification-types,
                reputation: u100,
                registration-date: block-height,
                is-active: true
            }
        )
        
        (ok true)
    )
)

;; Suspend or reactivate issuer (admin only)
(define-public (set-issuer-status (issuer principal) (active bool))
    (let ((issuer-data (unwrap! (map-get? trusted-issuers { issuer: issuer }) ERR_NOT_FOUND)))
        
        (asserts! (is-eq tx-sender (var-get registry-admin)) ERR_UNAUTHORIZED)
        
        (map-set trusted-issuers { issuer: issuer }
            (merge issuer-data { is-active: active })
        )
        
        (ok true)
    )
)

;; Update identity metadata
(define-public (update-metadata (new-metadata-hash (string-ascii 64)))
    (let ((identity-data (unwrap! (map-get? identities { did: tx-sender }) ERR_NOT_FOUND)))
        
        (map-set identities { did: tx-sender }
            (merge identity-data 
                {
                    metadata-hash: (some new-metadata-hash),
                    last-update: block-height
                }
            )
        )
        
        (ok true)
    )
)

;; Request identity recovery
(define-public (request-recovery (new-recovery-address principal))
    (let ((identity-data (unwrap! (map-get? identities { did: tx-sender }) ERR_NOT_FOUND)))
        
        ;; Check if recovery address is set
        (asserts! (is-some (get recovery-address identity-data)) ERR_UNAUTHORIZED)
        
        (map-set recovery-requests { did: tx-sender }
            {
                requester: tx-sender,
                new-recovery-address: new-recovery-address,
                request-date: block-height,
                approval-count: u0,
                required-approvals: u1, ;; Simplified - would require multiple approvals
                status: STATUS_ACTIVE
            }
        )
        
        (ok true)
    )
)

;; Execute recovery (by recovery address)
(define-public (execute-recovery (did principal))
    (let ((identity-data (unwrap! (map-get? identities { did: did }) ERR_NOT_FOUND))
          (recovery-data (unwrap! (map-get? recovery-requests { did: did }) ERR_NOT_FOUND)))
        
        ;; Check caller is authorized recovery address
        (asserts! (is-eq tx-sender (unwrap! (get recovery-address identity-data) ERR_UNAUTHORIZED)) ERR_UNAUTHORIZED)
        
        ;; Update recovery address
        (map-set identities { did: did }
            (merge identity-data 
                {
                    recovery-address: (some (get new-recovery-address recovery-data)),
                    last-update: block-height
                }
            )
        )
        
        ;; Mark recovery as completed
        (map-delete recovery-requests { did: did })
        
        (ok true)
    )
)

;; Read-only functions
(define-read-only (get-identity (did principal))
    (map-get? identities { did: did })
)

(define-read-only (get-verification-history (did principal) (verification-id uint))
    (map-get? verification-history { did: did, verification-id: verification-id })
)

(define-read-only (get-trusted-issuer (issuer principal))
    (map-get? trusted-issuers { issuer: issuer })
)

(define-read-only (get-attribute (did principal) (attribute-type (string-ascii 50)))
    (map-get? identity-attributes { did: did, attribute-type: attribute-type })
)

(define-read-only (get-registry-stats)
    {
        total-identities: (var-get identity-counter),
        total-verifications: (var-get total-verifications),
        verification-fee: (var-get verification-fee),
        registry-admin: (var-get registry-admin)
    }
)

(define-read-only (is-verified (did principal) (min-level uint))
    (match (map-get? identities { did: did })
        identity (and
            (>= (get verification-level identity) min-level)
            (is-eq (get status identity) STATUS_ACTIVE)
            (> (get verification-expiry identity) block-height)
        )
        false
    )
)

(define-read-only (get-verification-level (did principal))
    (match (map-get? identities { did: did })
        identity (get verification-level identity)
        u0
    )
)

;; Admin functions
(define-public (set-admin (new-admin principal))
    (begin
        (asserts! (is-eq tx-sender (var-get registry-admin)) ERR_UNAUTHORIZED)
        (var-set registry-admin new-admin)
        (ok true)
    )
)

(define-public (set-verification-fee (new-fee uint))
    (begin
        (asserts! (is-eq tx-sender (var-get registry-admin)) ERR_UNAUTHORIZED)
        (var-set verification-fee new-fee)
        (ok true)
    )
)

;; Suspend identity (admin only)
(define-public (suspend-identity (did principal))
    (let ((identity-data (unwrap! (map-get? identities { did: did }) ERR_NOT_FOUND)))
        
        (asserts! (is-eq tx-sender (var-get registry-admin)) ERR_UNAUTHORIZED)
        
        (map-set identities { did: did }
            (merge identity-data { status: STATUS_SUSPENDED })
        )
        
        (ok true)
    )
)
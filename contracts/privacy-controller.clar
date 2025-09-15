;; Privacy Controller
;; Privacy controls, data sharing permissions, and access management

;; Constants
(define-constant ERR_UNAUTHORIZED (err u401))
(define-constant ERR_NOT_FOUND (err u404))
(define-constant ERR_INVALID_PERMISSION (err u400))
(define-constant ERR_PERMISSION_DENIED (err u403))
(define-constant ERR_EXPIRED (err u410))

;; Data Variables
(define-data-var permission-counter uint u0)
(define-data-var access-log-counter uint u0)
(define-data-var privacy-admin principal tx-sender)

;; Permission Types
(define-constant PERMISSION_READ u1)
(define-constant PERMISSION_WRITE u2)
(define-constant PERMISSION_SHARE u4)
(define-constant PERMISSION_DELETE u8)
(define-constant PERMISSION_ALL u15) ;; Bitmask for all permissions

;; Access Levels
(define-constant ACCESS_PRIVATE u0)
(define-constant ACCESS_CONTACTS u1)
(define-constant ACCESS_VERIFIED u2)
(define-constant ACCESS_PUBLIC u3)

;; Consent Status
(define-constant CONSENT_PENDING u1)
(define-constant CONSENT_GRANTED u2)
(define-constant CONSENT_DENIED u3)
(define-constant CONSENT_REVOKED u4)

;; Maps
(define-map data-permissions
    { owner: principal, requester: principal, data-type: (string-ascii 50) }
    {
        permission-id: uint,
        permissions: uint, ;; Bitmask of allowed operations
        granted-date: uint,
        expiry-date: uint,
        purpose: (string-ascii 200),
        conditions: (string-ascii 300),
        status: uint,
        usage-count: uint,
        max-usage: uint
    }
)

(define-map consent-requests
    { request-id: uint }
    {
        requester: principal,
        data-owner: principal,
        data-types: (string-ascii 300), ;; Comma-separated list
        requested-permissions: uint,
        purpose: (string-ascii 200),
        request-date: uint,
        expiry-date: uint,
        status: uint,
        justification: (string-ascii 500)
    }
)

(define-map access-logs
    { log-id: uint }
    {
        accessor: principal,
        data-owner: principal,
        data-type: (string-ascii 50),
        access-type: uint, ;; READ, WRITE, etc.
        access-date: uint,
        purpose: (string-ascii 200),
        result: bool, ;; Success or failure
        ip-hash: (optional (string-ascii 64)) ;; Hashed IP for audit
    }
)

(define-map privacy-settings
    { user: principal }
    {
        default-access-level: uint,
        data-retention-days: uint,
        allow-data-export: bool,
        require-explicit-consent: bool,
        notification-preferences: uint, ;; Bitmask for notification types
        last-updated: uint
    }
)

(define-map data-classifications
    { data-type: (string-ascii 50) }
    {
        sensitivity-level: uint, ;; 1-5 scale
        retention-period: uint,
        default-permissions: uint,
        requires_explicit_consent: bool,
        can_be_shared: bool,
        encryption_required: bool
    }
)

(define-map trusted-verifiers
    { verifier: principal }
    {
        name: (string-ascii 100),
        verification-types: uint, ;; Bitmask of supported verification types
        trust-score: uint,
        registration-date: uint,
        is-active: bool
    }
)

;; Zero-knowledge proof requests
(define-map zk-proof-requests
    { proof-id: uint }
    {
        requester: principal,
        prover: principal,
        claim-type: (string-ascii 50), ;; age, location, membership, etc.
        threshold: uint, ;; Minimum value to prove (e.g., age > 18)
        request-date: uint,
        expiry-date: uint,
        status: uint,
        proof-hash: (optional (string-ascii 64))
    }
)

(define-data-var zk-proof-counter uint u0)

;; Request data access permission
(define-public (request-permission
    (data-owner principal)
    (data-types (string-ascii 300))
    (requested-permissions uint)
    (purpose (string-ascii 200))
    (justification (string-ascii 500))
    (duration-blocks uint)
)
    (let ((request-id (+ (var-get permission-counter) u1)))
        
        ;; Validate permission request
        (asserts! (> requested-permissions u0) ERR_INVALID_PERMISSION)
        (asserts! (<= requested-permissions PERMISSION_ALL) ERR_INVALID_PERMISSION)
        (asserts! (> duration-blocks u0) ERR_INVALID_PERMISSION)
        
        ;; Create consent request
        (map-set consent-requests { request-id: request-id }
            {
                requester: tx-sender,
                data-owner: data-owner,
                data-types: data-types,
                requested-permissions: requested-permissions,
                purpose: purpose,
                request-date: block-height,
                expiry-date: (+ block-height duration-blocks),
                status: CONSENT_PENDING,
                justification: justification
            }
        )
        
        (var-set permission-counter request-id)
        (ok request-id)
    )
)

;; Grant or deny permission (data owner only)
(define-public (respond-to-permission-request
    (request-id uint)
    (approve bool)
    (conditions (optional (string-ascii 300)))
    (max-usage uint)
)
    (let ((request-data (unwrap! (map-get? consent-requests { request-id: request-id }) ERR_NOT_FOUND)))
        
        ;; Only data owner can respond
        (asserts! (is-eq tx-sender (get data-owner request-data)) ERR_UNAUTHORIZED)
        
        ;; Check request is still pending and not expired
        (asserts! (is-eq (get status request-data) CONSENT_PENDING) ERR_EXPIRED)
        (asserts! (<= block-height (get expiry-date request-data)) ERR_EXPIRED)
        
        ;; Update consent request status
        (map-set consent-requests { request-id: request-id }
            (merge request-data { status: (if approve CONSENT_GRANTED CONSENT_DENIED) })
        )
        
        ;; If approved, create data permission
        (if approve
            (map-set data-permissions 
                { owner: (get data-owner request-data), requester: (get requester request-data), data-type: "general" }
                {
                    permission-id: request-id,
                    permissions: (get requested-permissions request-data),
                    granted-date: block-height,
                    expiry-date: (get expiry-date request-data),
                    purpose: (get purpose request-data),
                    conditions: (default-to "" conditions),
                    status: CONSENT_GRANTED,
                    usage-count: u0,
                    max-usage: max-usage
                }
            )
            true
        )
        
        (ok approve)
    )
)

;; Revoke permission
(define-public (revoke-permission
    (requester principal)
    (data-type (string-ascii 50))
)
    (let ((permission-data (unwrap! (map-get? data-permissions { owner: tx-sender, requester: requester, data-type: data-type }) ERR_NOT_FOUND)))
        
        ;; Update permission status
        (map-set data-permissions { owner: tx-sender, requester: requester, data-type: data-type }
            (merge permission-data { status: CONSENT_REVOKED })
        )
        
        (ok true)
    )
)

;; Log data access
(define-public (log-access
    (data-owner principal)
    (data-type (string-ascii 50))
    (access-type uint)
    (purpose (string-ascii 200))
    (result bool)
)
    (let ((log-id (+ (var-get access-log-counter) u1))
          (permission-data (map-get? data-permissions { owner: data-owner, requester: tx-sender, data-type: data-type })))
        
        ;; Check if access is authorized
        (match permission-data
            perm (begin
                ;; Check permission is still valid
                (asserts! (is-eq (get status perm) CONSENT_GRANTED) ERR_PERMISSION_DENIED)
                (asserts! (> (get expiry-date perm) block-height) ERR_EXPIRED)
                ;; Simplified permission check - in production would use proper bitwise operations
                (asserts! (> (get permissions perm) u0) ERR_PERMISSION_DENIED)
                
                ;; Check usage limits
                (if (> (get max-usage perm) u0)
                    (asserts! (< (get usage-count perm) (get max-usage perm)) ERR_PERMISSION_DENIED)
                    true
                )
                
                ;; Update usage count
                (map-set data-permissions { owner: data-owner, requester: tx-sender, data-type: data-type }
                    (merge perm { usage-count: (+ (get usage-count perm) u1) })
                )
                true
            )
            false
        )
        
        ;; Log the access
        (map-set access-logs { log-id: log-id }
            {
                accessor: tx-sender,
                data-owner: data-owner,
                data-type: data-type,
                access-type: access-type,
                access-date: block-height,
                purpose: purpose,
                result: result,
                ip-hash: none ;; Would be populated with hashed IP in real implementation
            }
        )
        
        (var-set access-log-counter log-id)
        (ok log-id)
    )
)

;; Update privacy settings
(define-public (update-privacy-settings
    (default-access-level uint)
    (data-retention-days uint)
    (allow-data-export bool)
    (require-explicit-consent bool)
    (notification-preferences uint)
)
    (begin
        ;; Validate access level
        (asserts! (<= default-access-level ACCESS_PUBLIC) ERR_INVALID_PERMISSION)
        
        (map-set privacy-settings { user: tx-sender }
            {
                default-access-level: default-access-level,
                data-retention-days: data-retention-days,
                allow-data-export: allow-data-export,
                require-explicit-consent: require-explicit-consent,
                notification-preferences: notification-preferences,
                last-updated: block-height
            }
        )
        
        (ok true)
    )
)

;; Request zero-knowledge proof
(define-public (request-zk-proof
    (prover principal)
    (claim-type (string-ascii 50))
    (threshold uint)
    (duration-blocks uint)
)
    (let ((proof-id (+ (var-get zk-proof-counter) u1)))
        
        (map-set zk-proof-requests { proof-id: proof-id }
            {
                requester: tx-sender,
                prover: prover,
                claim-type: claim-type,
                threshold: threshold,
                request-date: block-height,
                expiry-date: (+ block-height duration-blocks),
                status: CONSENT_PENDING,
                proof-hash: none
            }
        )
        
        (var-set zk-proof-counter proof-id)
        (ok proof-id)
    )
)

;; Submit zero-knowledge proof
(define-public (submit-zk-proof
    (proof-id uint)
    (proof-hash (string-ascii 64))
)
    (let ((request-data (unwrap! (map-get? zk-proof-requests { proof-id: proof-id }) ERR_NOT_FOUND)))
        
        ;; Only the prover can submit
        (asserts! (is-eq tx-sender (get prover request-data)) ERR_UNAUTHORIZED)
        (asserts! (is-eq (get status request-data) CONSENT_PENDING) ERR_EXPIRED)
        (asserts! (<= block-height (get expiry-date request-data)) ERR_EXPIRED)
        
        ;; Update proof request with submitted proof
        (map-set zk-proof-requests { proof-id: proof-id }
            (merge request-data 
                {
                    status: CONSENT_GRANTED,
                    proof-hash: (some proof-hash)
                }
            )
        )
        
        (ok true)
    )
)

;; Register trusted verifier (admin only)
(define-public (register-verifier
    (verifier principal)
    (name (string-ascii 100))
    (verification-types uint)
)
    (begin
        (asserts! (is-eq tx-sender (var-get privacy-admin)) ERR_UNAUTHORIZED)
        
        (map-set trusted-verifiers { verifier: verifier }
            {
                name: name,
                verification-types: verification-types,
                trust-score: u100,
                registration-date: block-height,
                is-active: true
            }
        )
        
        (ok true)
    )
)

;; Classify data type (admin only)
(define-public (classify-data-type
    (data-type (string-ascii 50))
    (sensitivity-level uint)
    (retention-period uint)
    (default-permissions uint)
    (requires-explicit-consent bool)
    (can-be-shared bool)
    (encryption-required bool)
)
    (begin
        (asserts! (is-eq tx-sender (var-get privacy-admin)) ERR_UNAUTHORIZED)
        (asserts! (<= sensitivity-level u5) ERR_INVALID_PERMISSION)
        
        (map-set data-classifications { data-type: data-type }
            {
                sensitivity-level: sensitivity-level,
                retention-period: retention-period,
                default-permissions: default-permissions,
                requires_explicit_consent: requires-explicit-consent,
                can_be_shared: can-be-shared,
                encryption_required: encryption-required
            }
        )
        
        (ok true)
    )
)

;; Read-only functions
(define-read-only (get-permission (owner principal) (requester principal) (data-type (string-ascii 50)))
    (map-get? data-permissions { owner: owner, requester: requester, data-type: data-type })
)

(define-read-only (get-consent-request (request-id uint))
    (map-get? consent-requests { request-id: request-id })
)

(define-read-only (get-access-log (log-id uint))
    (map-get? access-logs { log-id: log-id })
)

(define-read-only (get-privacy-settings (user principal))
    (map-get? privacy-settings { user: user })
)

(define-read-only (get-data-classification (data-type (string-ascii 50)))
    (map-get? data-classifications { data-type: data-type })
)

(define-read-only (get-zk-proof-request (proof-id uint))
    (map-get? zk-proof-requests { proof-id: proof-id })
)

(define-read-only (get-trusted-verifier (verifier principal))
    (map-get? trusted-verifiers { verifier: verifier })
)

;; Check if access is authorized
(define-read-only (is-access-authorized
    (owner principal)
    (requester principal)
    (data-type (string-ascii 50))
    (access-type uint)
)
    (match (map-get? data-permissions { owner: owner, requester: requester, data-type: data-type })
        perm (and
            (is-eq (get status perm) CONSENT_GRANTED)
            (> (get expiry-date perm) block-height)
            ;; Simplified permission check
            (> (get permissions perm) u0)
            (or (is-eq (get max-usage perm) u0)
                (< (get usage-count perm) (get max-usage perm)))
        )
        false
    )
)

(define-read-only (get-privacy-stats)
    {
        total-permissions: (var-get permission-counter),
        total-access-logs: (var-get access-log-counter),
        total-zk-proofs: (var-get zk-proof-counter),
        privacy-admin: (var-get privacy-admin)
    }
)

;; Get user's active permissions (as data owner)
(define-read-only (get-user-permissions-count (user principal))
    ;; This would require iterating through permissions - simplified for now
    u0
)

;; Check if data type requires explicit consent
(define-read-only (requires-explicit-consent-check (data-type (string-ascii 50)))
    (match (map-get? data-classifications { data-type: data-type })
        classification (get requires_explicit_consent classification)
        true ;; Default to requiring consent if not classified
    )
)

;; Admin functions
(define-public (set-admin (new-admin principal))
    (begin
        (asserts! (is-eq tx-sender (var-get privacy-admin)) ERR_UNAUTHORIZED)
        (var-set privacy-admin new-admin)
        (ok true)
    )
)

(define-public (deactivate-verifier (verifier principal))
    (let ((verifier-data (unwrap! (map-get? trusted-verifiers { verifier: verifier }) ERR_NOT_FOUND)))
        
        (asserts! (is-eq tx-sender (var-get privacy-admin)) ERR_UNAUTHORIZED)
        
        (map-set trusted-verifiers { verifier: verifier }
            (merge verifier-data { is-active: false })
        )
        
        (ok true)
    )
)

;; Bulk revoke permissions (admin emergency function)
(define-public (emergency-revoke-permissions (requester principal))
    (begin
        (asserts! (is-eq tx-sender (var-get privacy-admin)) ERR_UNAUTHORIZED)
        ;; This would revoke all permissions for a specific requester
        ;; Implementation would require iterating through permissions
        (ok true)
    )
)
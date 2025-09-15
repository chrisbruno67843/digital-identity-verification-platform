;; Credential Issuer
;; Issue and manage verifiable credentials and attestations

;; Constants
(define-constant ERR_UNAUTHORIZED (err u401))
(define-constant ERR_NOT_FOUND (err u404))
(define-constant ERR_ALREADY_EXISTS (err u409))
(define-constant ERR_INVALID_CREDENTIAL (err u400))
(define-constant ERR_EXPIRED (err u410))
(define-constant ERR_REVOKED (err u411))
(define-constant ERR_INSUFFICIENT_LEVEL (err u403))

;; Data Variables
(define-data-var credential-counter uint u0)
(define-data-var template-counter uint u0)
(define-data-var issuer-admin principal tx-sender)

;; Credential Status
(define-constant STATUS_ACTIVE u1)
(define-constant STATUS_EXPIRED u2)
(define-constant STATUS_REVOKED u3)
(define-constant STATUS_SUSPENDED u4)

;; Credential Types
(define-constant TYPE_IDENTITY u1)
(define-constant TYPE_EDUCATION u2)
(define-constant TYPE_EMPLOYMENT u3)
(define-constant TYPE_PROFESSIONAL u4)
(define-constant TYPE_FINANCIAL u5)
(define-constant TYPE_SOCIAL u6)

;; Maps
(define-map credentials
    { credential-id: uint }
    {
        holder: principal,
        issuer: principal,
        credential-type: uint,
        template-id: uint,
        claims-hash: (string-ascii 64), ;; Hash of claims data
        proof-hash: (string-ascii 64), ;; Cryptographic proof
        issue-date: uint,
        expiry-date: uint,
        status: uint,
        verification-method: (string-ascii 100),
        metadata-uri: (optional (string-ascii 200)) ;; IPFS or HTTP URI
    }
)

(define-map credential-templates
    { template-id: uint }
    {
        name: (string-ascii 100),
        description: (string-ascii 300),
        credential-type: uint,
        required-fields: (string-ascii 500), ;; JSON schema of required fields
        issuer-restrictions: uint, ;; Bitmask of who can issue
        verification-requirements: uint, ;; Required verification level
        validity-period: uint, ;; Blocks until expiry
        is-active: bool
    }
)

(define-map issuer-authorizations
    { issuer: principal, template-id: uint }
    {
        authorized: bool,
        authorization-date: uint,
        authorized-by: principal,
        specializations: (string-ascii 200) ;; Specific areas of expertise
    }
)

(define-map credential-schemas
    { schema-id: (string-ascii 50) }
    {
        schema-hash: (string-ascii 64),
        version: (string-ascii 20),
        fields: (string-ascii 1000), ;; JSON schema definition
        validation-rules: (string-ascii 500),
        created-by: principal,
        creation-date: uint
    }
)

(define-map revocation-registry
    { credential-id: uint }
    {
        revoked-by: principal,
        revocation-date: uint,
        reason: (string-ascii 200),
        replacement-credential: (optional uint)
    }
)

(define-map verification-requests
    { request-id: uint }
    {
        verifier: principal,
        credential-id: uint,
        requested-claims: (string-ascii 300), ;; Specific claims requested
        request-date: uint,
        response-deadline: uint,
        status: uint,
        holder-response: (optional bool)
    }
)

(define-data-var verification-request-counter uint u0)

;; Issue credential
(define-public (issue-credential
    (holder principal)
    (template-id uint)
    (claims-hash (string-ascii 64))
    (proof-hash (string-ascii 64))
    (verification-method (string-ascii 100))
    (metadata-uri (optional (string-ascii 200)))
)
    (let ((credential-id (+ (var-get credential-counter) u1))
          (template-data (unwrap! (map-get? credential-templates { template-id: template-id }) ERR_NOT_FOUND))
          (auth-data (map-get? issuer-authorizations { issuer: tx-sender, template-id: template-id })))
        
        ;; Check issuer is authorized for this template
        (asserts! (default-to false (get authorized auth-data)) ERR_UNAUTHORIZED)
        (asserts! (get is-active template-data) ERR_INVALID_CREDENTIAL)
        
        ;; Create credential
        (map-set credentials { credential-id: credential-id }
            {
                holder: holder,
                issuer: tx-sender,
                credential-type: (get credential-type template-data),
                template-id: template-id,
                claims-hash: claims-hash,
                proof-hash: proof-hash,
                issue-date: block-height,
                expiry-date: (+ block-height (get validity-period template-data)),
                status: STATUS_ACTIVE,
                verification-method: verification-method,
                metadata-uri: metadata-uri
            }
        )
        
        (var-set credential-counter credential-id)
        (ok credential-id)
    )
)

;; Create credential template (admin only)
(define-public (create-template
    (name (string-ascii 100))
    (description (string-ascii 300))
    (credential-type uint)
    (required-fields (string-ascii 500))
    (issuer-restrictions uint)
    (verification-requirements uint)
    (validity-period uint)
)
    (let ((template-id (+ (var-get template-counter) u1)))
        
        (asserts! (is-eq tx-sender (var-get issuer-admin)) ERR_UNAUTHORIZED)
        
        (map-set credential-templates { template-id: template-id }
            {
                name: name,
                description: description,
                credential-type: credential-type,
                required-fields: required-fields,
                issuer-restrictions: issuer-restrictions,
                verification-requirements: verification-requirements,
                validity-period: validity-period,
                is-active: true
            }
        )
        
        (var-set template-counter template-id)
        (ok template-id)
    )
)

;; Authorize issuer for template (admin only)
(define-public (authorize-issuer
    (issuer principal)
    (template-id uint)
    (specializations (string-ascii 200))
)
    (let ((template-data (unwrap! (map-get? credential-templates { template-id: template-id }) ERR_NOT_FOUND)))
        
        (asserts! (is-eq tx-sender (var-get issuer-admin)) ERR_UNAUTHORIZED)
        
        (map-set issuer-authorizations { issuer: issuer, template-id: template-id }
            {
                authorized: true,
                authorization-date: block-height,
                authorized-by: tx-sender,
                specializations: specializations
            }
        )
        
        (ok true)
    )
)

;; Revoke credential
(define-public (revoke-credential
    (credential-id uint)
    (reason (string-ascii 200))
    (replacement-credential (optional uint))
)
    (let ((credential-data (unwrap! (map-get? credentials { credential-id: credential-id }) ERR_NOT_FOUND)))
        
        ;; Only issuer or holder can revoke
        (asserts! (or (is-eq tx-sender (get issuer credential-data))
                     (is-eq tx-sender (get holder credential-data))) ERR_UNAUTHORIZED)
        
        ;; Update credential status
        (map-set credentials { credential-id: credential-id }
            (merge credential-data { status: STATUS_REVOKED })
        )
        
        ;; Record revocation details
        (map-set revocation-registry { credential-id: credential-id }
            {
                revoked-by: tx-sender,
                revocation-date: block-height,
                reason: reason,
                replacement-credential: replacement-credential
            }
        )
        
        (ok true)
    )
)

;; Request credential verification
(define-public (request-verification
    (credential-id uint)
    (requested-claims (string-ascii 300))
    (deadline-blocks uint)
)
    (let ((request-id (+ (var-get verification-request-counter) u1))
          (credential-data (unwrap! (map-get? credentials { credential-id: credential-id }) ERR_NOT_FOUND)))
        
        ;; Create verification request
        (map-set verification-requests { request-id: request-id }
            {
                verifier: tx-sender,
                credential-id: credential-id,
                requested-claims: requested-claims,
                request-date: block-height,
                response-deadline: (+ block-height deadline-blocks),
                status: STATUS_ACTIVE,
                holder-response: none
            }
        )
        
        (var-set verification-request-counter request-id)
        (ok request-id)
    )
)

;; Respond to verification request (credential holder only)
(define-public (respond-to-verification
    (request-id uint)
    (approve bool)
)
    (let ((request-data (unwrap! (map-get? verification-requests { request-id: request-id }) ERR_NOT_FOUND))
          (credential-data (unwrap! (map-get? credentials { credential-id: (get credential-id request-data) }) ERR_NOT_FOUND)))
        
        ;; Only credential holder can respond
        (asserts! (is-eq tx-sender (get holder credential-data)) ERR_UNAUTHORIZED)
        
        ;; Check request is still active and not expired
        (asserts! (is-eq (get status request-data) STATUS_ACTIVE) ERR_EXPIRED)
        (asserts! (<= block-height (get response-deadline request-data)) ERR_EXPIRED)
        
        ;; Update request with response
        (map-set verification-requests { request-id: request-id }
            (merge request-data 
                {
                    holder-response: (some approve),
                    status: (if approve STATUS_ACTIVE u2) ;; 2 = completed
                }
            )
        )
        
        (ok true)
    )
)

;; Create credential schema
(define-public (create-schema
    (schema-id (string-ascii 50))
    (schema-hash (string-ascii 64))
    (version (string-ascii 20))
    (fields (string-ascii 1000))
    (validation-rules (string-ascii 500))
)
    (begin
        ;; Check schema doesn't already exist
        (asserts! (is-none (map-get? credential-schemas { schema-id: schema-id })) ERR_ALREADY_EXISTS)
        
        (map-set credential-schemas { schema-id: schema-id }
            {
                schema-hash: schema-hash,
                version: version,
                fields: fields,
                validation-rules: validation-rules,
                created-by: tx-sender,
                creation-date: block-height
            }
        )
        
        (ok true)
    )
)

;; Batch issue credentials (for efficiency)
(define-public (batch-issue-credentials
    (holders (list 10 principal))
    (template-id uint)
    (claims-hashes (list 10 (string-ascii 64)))
    (proof-hashes (list 10 (string-ascii 64)))
)
    (let ((template-data (unwrap! (map-get? credential-templates { template-id: template-id }) ERR_NOT_FOUND))
          (auth-data (map-get? issuer-authorizations { issuer: tx-sender, template-id: template-id })))
        
        ;; Check authorization
        (asserts! (default-to false (get authorized auth-data)) ERR_UNAUTHORIZED)
        (asserts! (get is-active template-data) ERR_INVALID_CREDENTIAL)
        (asserts! (is-eq (len holders) (len claims-hashes)) ERR_INVALID_CREDENTIAL)
        (asserts! (is-eq (len holders) (len proof-hashes)) ERR_INVALID_CREDENTIAL)
        
        ;; This would require implementing fold/map functions for batch processing
        ;; For now, return success - in production would iterate through lists
        (ok true)
    )
)

;; Read-only functions
(define-read-only (get-credential (credential-id uint))
    (map-get? credentials { credential-id: credential-id })
)

(define-read-only (get-template (template-id uint))
    (map-get? credential-templates { template-id: template-id })
)

(define-read-only (get-issuer-authorization (issuer principal) (template-id uint))
    (map-get? issuer-authorizations { issuer: issuer, template-id: template-id })
)

(define-read-only (get-schema (schema-id (string-ascii 50)))
    (map-get? credential-schemas { schema-id: schema-id })
)

(define-read-only (get-verification-request (request-id uint))
    (map-get? verification-requests { request-id: request-id })
)

(define-read-only (get-revocation-info (credential-id uint))
    (map-get? revocation-registry { credential-id: credential-id })
)

;; Verify credential is valid and not revoked
(define-read-only (is-credential-valid (credential-id uint))
    (match (map-get? credentials { credential-id: credential-id })
        credential (and
            (is-eq (get status credential) STATUS_ACTIVE)
            (> (get expiry-date credential) block-height)
            (is-none (map-get? revocation-registry { credential-id: credential-id }))
        )
        false
    )
)

(define-read-only (get-issuer-stats)
    {
        total-credentials: (var-get credential-counter),
        total-templates: (var-get template-counter),
        total-verification-requests: (var-get verification-request-counter),
        issuer-admin: (var-get issuer-admin)
    }
)

;; Get credentials by holder
(define-read-only (get-holder-credential-count (holder principal))
    ;; This would require iterating through all credentials - simplified for now
    u0
)

;; Check if credential meets verification level
(define-read-only (meets-verification-requirements (credential-id uint) (required-level uint))
    (match (map-get? credentials { credential-id: credential-id })
        credential (let ((template-data (map-get? credential-templates { template-id: (get template-id credential) })))
            (match template-data
                template (>= (get verification-requirements template) required-level)
                false
            )
        )
        false
    )
)

;; Admin functions
(define-public (set-admin (new-admin principal))
    (begin
        (asserts! (is-eq tx-sender (var-get issuer-admin)) ERR_UNAUTHORIZED)
        (var-set issuer-admin new-admin)
        (ok true)
    )
)

(define-public (deactivate-template (template-id uint))
    (let ((template-data (unwrap! (map-get? credential-templates { template-id: template-id }) ERR_NOT_FOUND)))
        
        (asserts! (is-eq tx-sender (var-get issuer-admin)) ERR_UNAUTHORIZED)
        
        (map-set credential-templates { template-id: template-id }
            (merge template-data { is-active: false })
        )
        
        (ok true)
    )
)

(define-public (revoke-issuer-authorization (issuer principal) (template-id uint))
    (let ((auth-data (unwrap! (map-get? issuer-authorizations { issuer: issuer, template-id: template-id }) ERR_NOT_FOUND)))
        
        (asserts! (is-eq tx-sender (var-get issuer-admin)) ERR_UNAUTHORIZED)
        
        (map-set issuer-authorizations { issuer: issuer, template-id: template-id }
            (merge auth-data { authorized: false })
        )
        
        (ok true)
    )
)
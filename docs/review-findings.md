# Open review findings / known gaps

Tracked items from the 2026-06-16 independent security-correctness review of the
detection path. Resolved items are dropped from this list.

## [RESOLVED] ESC4 misses blanket `WriteProperty` on templates

Fixed in PR #9: `_DANGEROUS_TEMPLATE_CONTROL` now includes `writepropertyall`
(blanket WriteProperty). Collector emits `WritePropertyAll` for zero-GUID
ObjectType on WriteProperty ACEs.

## [RESOLVED] No per-template signal when a template's DACL was unreadable

Fixed in PR #10: `CertTemplate.acl_obtained` field + `detect_template_acl_gaps`
detector + collector `acl_obtained` marker. ESC1/2/3/4/13 skip templates where
`acl_obtained` is False; `TEMPLATE_ACL_UNREADABLE` notes the gap.

## [RESOLVED] ESC1/2/3 finding details include `published_by`

ESC1/2/3 findings now name the normalized CA list that publishes each affected
template, state when it is confirmed unpublished, or mark publication state
unknown when the enrollment-services export was absent. Availability is carried
explicitly in the normalized manifest: a present valid empty export confirms
templates are unpublished, while a missing export remains unknown. Unpublished
vulnerable templates remain findings at the same severity: they are latent risks
that could be published, including through an ESC4-style control path.

## [RESOLVED] Deny-ACE precedence now evaluated

Detectors now apply explicit-Deny precedence per (trustee, right) with a
right-implication map (GenericAll/FullControl cover all; AllExtendedRights covers
Enroll+AutoEnroll; GenericWrite covers WritePropertyAll; specific rights cover
themselves). A capability is suppressed only when every granting right for the
trustee is blocked, so the change cannot introduce false negatives. Residual
limitation: only same-trustee Deny ACEs are considered (no group-token expansion);
inherited Deny ordering is not modeled (collector reads the resolved DACL).

This also corrected a latent false positive: `_ENROLL_RIGHTS` is now the single
`Enroll` right (broad rights still satisfy it via the implication map).
`AutoEnroll` is intentionally excluded — AD CS issuance is gated on the Enroll
extended right, so a principal with only AutoEnroll cannot obtain a certificate,
and including it would make `Allow AutoEnroll + Deny Enroll` fire (a false
positive, since the principal lacks Enroll).

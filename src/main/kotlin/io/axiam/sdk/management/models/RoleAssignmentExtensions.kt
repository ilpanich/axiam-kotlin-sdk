package io.axiam.sdk.management.models

/**
 * Whether [RoleAssignment] reaches the descendants of `resourceId` (CONTRACT.md
 * §27.13 S-10 rule 3, contract 1.51).
 *
 * `RoleAssignment.inherit` is OPTIONAL on the wire (unlike the role-side listings
 * [RoleUserAssignment.inherit] / [RoleGroupAssignment.inherit] /
 * [RoleServiceAccountAssignment.inherit], which are required-but-defaulted at
 * generation time — see `DEFAULT_TRUE_FIELDS` in `scripts/gen_management.py`), so
 * `null` decodes to exactly that field's raw value: not invented, not defaulted at
 * decode time. This is the ONE place the default is decided, so a caller never
 * writes `inherit ?: true` itself and risks getting it backwards.
 *
 * Hand-written rather than generated: [RoleAssignment] itself is generated from
 * `openapi.json` and regenerated verbatim on every run, so a default belongs beside
 * it rather than inside it.
 */
fun RoleAssignment.inherits(): Boolean = inherit ?: true

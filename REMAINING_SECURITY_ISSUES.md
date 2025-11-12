# Remaining Security Issues Requiring Architectural Review

The following security vulnerabilities from the audit require deeper architectural analysis and design decisions before implementation. GitHub issues should be created for each.

## Issues Requiring Architectural Decisions

### CVE-CAL-2025-003: Unsafe Memory Access Without Bounds Validation (CRITICAL)
**File:** `rom/dev/src/flow/cold_reset/fw_processor.rs:509-531`

**Issue:** ROM creates raw pointers from manifest addresses without re-validating ICCM bounds, despite image verifier having already validated them.

**Why Complex:**
- Manifest is already validated by ImageVerifier (which now has overflow protection)
- Adding redundant validation may be unnecessary
- Proper fix might be architectural: have ImageVerifier return validated memory ranges
- Or create safe wrapper types that encode the validation in the type system

**Recommendation:** Discuss whether defense-in-depth validation should be added to ROM, or whether architectural changes (e.g., validated range types) are preferred.

---

### CVE-CAL-2025-005: Authorization Bypass via ignore_auth_check Flag (CRITICAL)
**File:** `runtime/src/authorize_and_stash.rs:72-75`

**Issue:** The `ignore_auth_check` flag allows complete bypass of image digest verification if set in manifest.

**Why Complex:**
- This is a design decision: should this flag exist at all?
- If it should exist, what controls access to it?
- Combined with CVE-CAL-2025-004 (now fixed), this allowed complete bypass
- With the PL0 restriction now in place, only trusted PL0 can set manifests
- But should the flag still be removed or made fuse-controlled?

**Recommendation:** Discuss with security team whether `ignore_auth_check` flag should:
1. Be removed entirely
2. Be made fuse-controlled instead of manifest-controlled
3. Remain as-is (now that PL0 restriction is in place)

---

### CVE-CAL-2025-009: TOCTOU in CSR Generation (HIGH)
**File:** `rom/dev/src/flow/cold_reset/idev_id.rs:56-58, 95-96, 306-326`

**Issue:** Code checks `mfg_flag_gen_idev_id_csr()` multiple times and uses busy-wait loops.

**Why Complex:**
- Requires understanding hardware behavior
- Need to know if flag can change asynchronously
- Timeout values need to be determined based on hardware specs
- May require hardware team input

**Recommendation:** Consult with hardware team about:
1. Can `mfg_flag_gen_idev_id_csr()` change asynchronously?
2. What is appropriate timeout for busy-wait loop?
3. Should flag be read once and cached?

---

### CVE-CAL-2025-010: Inconsistent Key Revocation Validation (HIGH)
**File:** `image/verify/src/verifier.rs:231, 276`

**Issue:** ECC uses `from_bits_truncate` (silently drops invalid bits) while LMS uses raw bit operations.

**Why Complex:**
- Need to determine which approach is correct
- `from_bits_truncate` may be intentional to handle future/unknown bits
- Or it may be a bug that masks invalid revocation states
- Requires understanding of revocation fuse format specification

**Recommendation:** Review revocation fuse specification to determine:
1. Are bits beyond the 4 valid keys reserved for future use?
2. Should invalid bits cause an error or be ignored?
3. Should both ECC and LMS use the same approach?

---

### CVE-CAL-2025-011: Optional Vendor Signature Verification (HIGH)
**File:** `runtime/src/set_auth_manifest.rs:241-244`

**Issue:** Vendor signature verification is optional based on manifest flag.

**Why Complex:**
- This is a design/policy decision
- Flag is in the manifest itself, which could be controlled by attacker (before our PL0 fix)
- Now that PL0 restriction is in place, only trusted PL0 can set this
- But should it be fuse-controlled instead for defense-in-depth?

**Recommendation:** With PL0 restriction now in place, discuss whether:
1. Current design is acceptable (PL0 controls the flag)
2. Should move to fuse-based policy for additional security
3. Should always require vendor signature

---

### CVE-CAL-2025-012: Binary Search on Potentially Corrupted Data (HIGH)
**File:** `runtime/src/authorize_and_stash.rs:136-140`

**Issue:** Binary search assumes list is sorted, but doesn't validate after loading from persistent storage.

**Why Complex:**
- Performance implications of validation
- Need to determine threat model: can persistent storage be corrupted?
- What level of corruption protection is needed?
- Should use checksums, signatures, or just sort validation?

**Recommendation:** Determine:
1. Can persistent storage be tampered with?
2. What is performance impact of sort validation?
3. Should add checksum/signature to persistent data?

---

### CVE-CAL-2025-014: Unsafe Pointer Cast Without Alignment (MEDIUM)
**File:** `runtime/src/set_auth_manifest.rs:380-381`

**Issue:** Raw pointer cast from `&[u8]` without verifying alignment.

**Why Complex:**
- Need to check if `zerocopy` crate is available in this context
- May require adding new dependency or using different safe abstraction
- Need to verify if alignment is guaranteed by caller

**Recommendation:** Investigate whether:
1. Alignment is guaranteed by mailbox hardware/driver
2. Can use `zerocopy::Ref::new()` or similar safe abstraction
3. Should add manual alignment check

---

### CVE-CAL-2025-015: Integer Overflow in Metadata Size Calculation (MEDIUM)
**File:** `runtime/src/set_auth_manifest.rs:390-394`

**Issue:** Multiplication can overflow before comparison check.

**Why Complex:**
- entry_count IS validated against max (line 384)
- Need to verify if existing validation is sufficient
- May be theoretical issue only

**Recommendation:** Review validation at line 384 to confirm it prevents overflow.

---

### CVE-CAL-2025-017: SVN Maximum Value Inconsistency (MEDIUM)
**Files:**
- `image/verify/src/verifier.rs:799` (FMC max=32)
- `image/verify/src/verifier.rs:891` (Runtime max=128)

**Issue:** Different max SVN values without clear justification.

**Why Complex:**
- May be intentional design decision
- Need to understand anti-rollback requirements for each component
- Requires product/security team input

**Recommendation:** Clarify:
1. Is asymmetry intentional?
2. What determines appropriate max SVN for each component?
3. Should define constants for clarity

---

### CVE-CAL-2025-018: Missing Zeroization in Error Paths (MEDIUM)
**File:** `rom/dev/src/flow/cold_reset/crypto.rs:221-228`

**Issue:** If `ecc384.sign()` fails, digest may not be zeroized.

**Why Complex:**
- Need to verify control flow and `okmutref` behavior
- May require RAII pattern or drop implementation
- Need to ensure all error paths zeroize

**Recommendation:** Analyze all error paths in crypto operations for proper zeroization.

---

### CVE-CAL-2025-019: Insufficient Image Size Validation (MEDIUM)
**File:** `rom/dev/src/flow/cold_reset/fw_processor.rs:209-212`

**Issue:** Missing validation for word alignment and minimum size.

**Why Complex:**
- ImageVerifier should already validate these
- Need to determine if redundant checks are needed
- Need to know minimum manifest size constants

**Recommendation:** Verify ImageVerifier's validation coverage and determine if defense-in-depth checks are needed.

---

### CVE-CAL-2025-021: Non-Constant-Time Comparison in LMS (LOW)
**File:** `drivers/src/lms.rs:451-456`

**Issue:** Timing side-channel in hash comparison.

**Why Complex:**
- Compares public hash values, not secrets
- May not be exploitable
- Fixing could impact performance
- Need threat model assessment

**Recommendation:** This was already assessed as LOW risk. Document that timing variance is acceptable for public value comparison.

---

## Summary

- **3 CRITICAL** issues requiring architectural decisions
- **6 HIGH** severity issues requiring investigation/policy decisions
- **3 MEDIUM** severity issues requiring analysis
- **1 LOW** severity issue (informational)

**Note:** All other critical and high-severity issues with clear fixes have been addressed in the accompanying commit.

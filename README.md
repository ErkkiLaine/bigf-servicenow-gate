# BIGF v2.4 Runtime Gate for ServiceNow Change Management

**Zero-dependency ServiceNow ITSM enforcement module for the Business Impact Governance Framework (BIGF v2.4).**

**Author & Copyright Holder:** Erkki Laine  
**Core Specification (Zenodo):** [DOI 10.5281/zenodo.24215776](https://doi.org/10.5281/zenodo.24215776)  
**Compiler & Studio:** [github.com/ErkkiLaine/bigf-gate-studio](https://github.com/ErkkiLaine/bigf-gate-studio)

---

## Overview

Instead of relying on subjective 15-person Change Advisory Board (CAB) meetings, this integration intercepts `change_request` state transitions (`Assess` / `Authorize`) inside ServiceNow, canonicalizes the payload according to **RFC 8785 (JCS)**, converts financial exposure metrics into **pure-integer 10^-4 fixed-point arithmetic**, and queries an **Open Policy Agent (OPA / Rego v1)** runtime gate.

If `Authority = f(B, S, T)` is satisfied, the change is deterministically authorized (`200 OK`) and a cryptographic **Canonical Decision Record (CDR)** is written directly to the ticket's Work Notes. If telemetry is stale, policy hashes drift, or business impact thresholds are exceeded, the gate enforces a strict **Fail-Closed (`403 HARD HALT`)**, aborts the transition, and persists the immutable CDR out-of-band via `gs.eventQueue` so audit evidence survives ServiceNow transaction rollbacks.

---

## Architecture & Guarantees

* **Zero External Middleware:** Uses native ServiceNow `Script Include` (`GlideDigest`, `sn_ws.RESTMessageV2`), `Business Rule`, and `Script Action` primitives—no MID Server overhead or proprietary third-party connectors required.
* **Rollback-Proof Audit Trail:** Because `current.setAbortAction(true)` rolls back synchronous database writes in ServiceNow, `403 HARD HALT` decisions emit an asynchronous `x_bigf.gate.hard_halt` event that commits the Canonical Decision Record to `u_bigf_decision_log`, `syslog`, and post-abort `work_notes` in an isolated transaction.
* **IEEE-754 Floating-Point Elimination:** All `EUR/h` / `USD/h` exposure values and `BIII` scores are scaled to 10^-4 integer units (`toFixedPoint10k`) via string parsing before leaving ServiceNow.
* **RFC 8785 Canonicalization:** Deterministic lexicographical key sorting (`canonicalizeJCS`) ensures identical SHA-256 digests across ServiceNow, OPA, and external audit logs.

---

## Installation (3 Minutes)

1. **Compile your Rego Policy:** Generate `bigf_gate.rego` using the browser-based [BIGF v2.4 Gate Compiler & Studio](https://erkkilaine.github.io/bigf-gate-studio/) and copy the compiled policy SHA-256 digest (e.g., `7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069`).
2. **Create System Properties (`sys_properties`):**
   * `x_bigf.opa.endpoint` — URL of your OPA decision API (e.g., `https://opa-gate.internal:8181/v1/data/bigf/gate/decision`). Fails closed if left blank.
   * `x_bigf.policy.sha256` — Pinned SHA-256 digest from BIGF Gate Studio.
   * `x_bigf.telemetry.max_age_ms` — Maximum allowed telemetry age in milliseconds (default: `5000`).
   * `x_bigf.bia.max_exposure_scaled` — Maximum hourly business impact in 10^-4 integer units (default: `50000000` = `5000.0000`).
   * `x_bigf.bia.min_biii_scaled` — Minimum Business Impact Integrity Index (default: `8000` = `0.8000`).
3. **Install Script Include:** Create `BIGFGateClient` using `BIGFGateClient.js` (`Accessible from: All application scopes`).
4. **Attach Business Rule:** Create a `Before Update` Business Rule on `change_request` using `BIGF_Change_Gate_BR.js` triggered when state changes to `Assess` or `Authorize`.
5. **Register HALT Script Action:** Create a Script Action listening for `x_bigf.gate.hard_halt` using `BIGF_Persist_Halt_CDR.js` to guarantee post-abort CDR persistence.

---

## Intellectual Property, Copyright & Licensing

**Copyright (c) 2026 Erkki Laine. All Rights Reserved.**

1. **Authorship & Attribution:** The *Business Impact Governance Framework (BIGF)*, the `Authority = f(B, S, T)` formal model, the `10^-4` integer canonicalization architecture, and all software artifacts in this repository are the original intellectual property of **Erkki Laine**. Any permitted reference, fork, or academic citation must explicitly credit **Erkki Laine** and reference the canonical Zenodo record (`DOI: 10.5281/zenodo.24215776`).
2. **Strict Dual-Licensing (No Proprietary Redistribution):**
   * **Open-Source / Non-Commercial Use:** Licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)** for non-commercial research, internal evaluation, and open-source projects, provided full source code of any derivative or network-accessible service incorporating this code is made publicly available under AGPL-3.0.
   * **Commercial & Proprietary Enterprise Use:** Any proprietary integration, closed-source SaaS offering, commercial consulting deployment, or redistribution without full AGPL-3.0 source disclosure is strictly prohibited without a prior written commercial license agreement executed by **Erkki Laine**.
3. **No Implied Trademark or Endorsement Rights:** Nothing in this repository grants permission to use the names *Erkki Laine*, *Business Impact Governance Framework*, or *BIGF* to endorse, certify, or market third-party products or services without explicit written authorization from the copyright holder.
4. **Disclaimer of Warranty:** THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. IN NO EVENT SHALL ERKKI LAINE BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY ARISING FROM THE USE OF THIS SOFTWARE.

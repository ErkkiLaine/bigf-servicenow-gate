var BIGFGateClient = Class.create();
BIGFGateClient.prototype = {
    initialize: function() {
        // System properties for zero-hardcoding configuration (Fail-Closed if unconfigured)
        this.opaEndpoint = String(gs.getProperty('x_bigf.opa.endpoint', '')).trim();
        this.pinnedPolicyHash = String(gs.getProperty('x_bigf.policy.sha256', '')).trim().toLowerCase();
        this.maxTelemetryAgeMs = parseInt(gs.getProperty('x_bigf.telemetry.max_age_ms', '5000'), 10);
        this.maxExposureScaled = parseInt(gs.getProperty('x_bigf.bia.max_exposure_scaled', '50000000'), 10); // 5000.0000 EUR/h
        this.minBiiiScaled = parseInt(gs.getProperty('x_bigf.bia.min_biii_scaled', '8000'), 10); // 0.8000
        this.timeoutMs = parseInt(gs.getProperty('x_bigf.opa.timeout_ms', '1500'), 10);
    },

    /**
     * Converts decimal number or numeric string into pure-integer 10^-4 fixed-point scale.
     * Eliminates IEEE-754 floating-point drift before policy evaluation.
     */
    toFixedPoint10k: function(val) {
        if (val === null || val === undefined || val === '') {
            return 0;
        }
        var str = String(val).trim();
        var negative = false;
        if (str.charAt(0) === '-') {
            negative = true;
            str = str.substring(1);
        }
        var parts = str.split('.');
        var whole = parseInt(parts[0] || '0', 10);
        var fracStr = (parts[1] || '') + '0000';
        var frac = parseInt(fracStr.substring(0, 4), 10);
        var scaled = (whole * 10000) + frac;
        return negative ? -scaled : scaled;
    },

    /**
     * RFC 8785 (JSON Canonicalization Scheme) deterministic serializer.
     * Sorts object keys lexicographically by UTF-16 code units with zero whitespace.
     */
    canonicalizeJCS: function(obj) {
        if (obj === null || typeof obj !== 'object') {
            if (typeof obj === 'number' && (!isFinite(obj) || Math.floor(obj) !== obj)) {
                throw new Error('RFC 8785 Gate Guard: Non-integer float detected in canonical payload. Scale via toFixedPoint10k().');
            }
            return JSON.stringify(obj);
        }
        if (Array.isArray(obj)) {
            var arrItems = [];
            for (var i = 0; i < obj.length; i++) {
                arrItems.push(this.canonicalizeJCS(obj[i]));
            }
            return '[' + arrItems.join(',') + ']';
        }
        var keys = Object.keys(obj).sort();
        var props = [];
        for (var j = 0; j < keys.length; j++) {
            var k = keys[j];
            if (obj[k] !== undefined) {
                props.push(JSON.stringify(k) + ':' + this.canonicalizeJCS(obj[k]));
            }
        }
        return '{' + props.join(',') + '}';
    },

    /**
     * Computes SHA-256 hex digest using native ServiceNow GlideDigest
     */
    sha256Hex: function(inputStr) {
        var digest = new GlideDigest();
        return String(digest.getSHA256Hex(inputStr)).toLowerCase();
    },

    /**
     * Evaluates a Change Request (GlideRecord) against the BIGF v2.4 OPA Runtime Gate.
     * Enforces strict Fail-Closed (403 HARD HALT) and persists immutable CDR even on transaction abort.
     */
    evaluateChangeRequest: function(chgGr) {
        var nowMs = new GlideDateTime().getNumericValue();
        var lastTelemetryMs = parseInt(chgGr.getValue('u_bigf_telemetry_epoch_ms') || '0', 10);
        var telemetryAgeMs = lastTelemetryMs > 0 ? (nowMs - lastTelemetryMs) : 999999999;

        var hourlyExposureRaw = chgGr.getValue('u_bigf_hourly_exposure') || '0';
        var biiiRaw = chgGr.getValue('u_bigf_biii_score') || '0';

        var payload = {
            a2a_or_itsm_source: 'servicenow_change_management',
            change_number: String(chgGr.getValue('number')),
            change_sys_id: String(chgGr.getUniqueValue()),
            change_type: String(chgGr.getValue('type')),
            risk_level: String(chgGr.getValue('risk')),
            compiled_policy_sha256: this.pinnedPolicyHash,
            request_policy_sha256: String(chgGr.getValue('u_bigf_policy_sha256') || this.pinnedPolicyHash).toLowerCase(),
            telemetry_age_ms: telemetryAgeMs,
            max_telemetry_age_ms: this.maxTelemetryAgeMs,
            business_impact: {
                hourly_exposure_scaled: this.toFixedPoint10k(hourlyExposureRaw),
                max_exposure_scaled: this.maxExposureScaled,
                biii_scaled: this.toFixedPoint10k(biiiRaw),
                min_biii_scaled: this.minBiiiScaled
            }
        };

        var canonicalPayload = this.canonicalizeJCS(payload);
        var payloadSha256 = this.sha256Hex(canonicalPayload);

        var decisionRecord = {
            spec_version: 'BIGF-v2.4',
            evaluated_at_utc: new GlideDateTime().getDisplayValueInternal(),
            change_number: payload.change_number,
            change_sys_id: payload.change_sys_id,
            canonical_input_sha256: payloadSha256,
            pinned_policy_sha256: this.pinnedPolicyHash,
            allow: false,
            http_status: 403,
            halt_reason: 'UNINITIALIZED_FAIL_CLOSED'
        };

        // Pre-flight 0: Endpoint configuration guard
        if (!this.opaEndpoint) {
            decisionRecord.halt_reason = '403 HARD HALT: OPA endpoint (x_bigf.opa.endpoint) not configured';
            this._persistDecision(chgGr, decisionRecord);
            return decisionRecord;
        }

        // Pre-flight 1: Structural State (S) policy SHA-256 guard
        if (!this.pinnedPolicyHash || payload.request_policy_sha256 !== this.pinnedPolicyHash) {
            decisionRecord.halt_reason = '403 HARD HALT: Structural State (S) policy SHA-256 mismatch or unpinned policy';
            this._persistDecision(chgGr, decisionRecord);
            return decisionRecord;
        }

        // Pre-flight 2: Telemetry (T) freshness guard
        if (telemetryAgeMs < 0 || telemetryAgeMs > this.maxTelemetryAgeMs) {
            decisionRecord.halt_reason = '403 HARD HALT: Telemetry (T) stale or missing (' + telemetryAgeMs + ' ms > ' + this.maxTelemetryAgeMs + ' ms)';
            this._persistDecision(chgGr, decisionRecord);
            return decisionRecord;
        }

        // Execute outbound REST call to OPA Runtime Gate
        try {
            var restMessage = new sn_ws.RESTMessageV2();
            restMessage.setEndpoint(this.opaEndpoint);
            restMessage.setHttpMethod('POST');
            restMessage.setRequestHeader('Content-Type', 'application/json');
            restMessage.setRequestHeader('Accept', 'application/json');
            restMessage.setHttpTimeout(this.timeoutMs);
            restMessage.setRequestBody(JSON.stringify({ input: payload }));

            var response = restMessage.execute();
            var statusCode = response.getStatusCode();
            var responseBody = response.getBody();

            if (statusCode !== 200 || !responseBody) {
                decisionRecord.halt_reason = '403 HARD HALT: OPA Gate unreachable or non-200 status (' + statusCode + ')';
                this._persistDecision(chgGr, decisionRecord);
                return decisionRecord;
            }

            var parsed = JSON.parse(responseBody);
            var result = parsed.result || {};

            if (result.allow === true) {
                decisionRecord.allow = true;
                decisionRecord.http_status = 200;
                decisionRecord.halt_reason = 'AUTHORIZED: Authority = f(B, S, T) satisfied';
            } else {
                decisionRecord.allow = false;
                decisionRecord.http_status = 403;
                decisionRecord.halt_reason = result.reason || '403 HARD HALT: Business Impact (B) or Gate invariant violated';
            }
        } catch (ex) {
            decisionRecord.allow = false;
            decisionRecord.http_status = 403;
            decisionRecord.halt_reason = '403 HARD HALT: Runtime exception (' + ex.message + ')';
        }

        this._persistDecision(chgGr, decisionRecord);
        return decisionRecord;
    },

    /**
     * Persists the Canonical Decision Record (CDR) across transaction boundaries:
     * 1. On ALLOW (200): appends directly to change_request.work_notes + audit log.
     * 2. On HALT (403): survives setAbortAction(true) rollback via sysevent queue + system error log.
     */
    _persistDecision: function(chgGr, decisionRecord) {
        var canonicalCDR = this.canonicalizeJCS(decisionRecord);
        var cdrHash = this.sha256Hex(canonicalCDR);

        var formattedAuditEntry = '[BIGF v2.4 RUNTIME GATE — ' + (decisionRecord.allow ? '200 AUTHORIZED' : '403 HARD HALT') + ']\n' +
                                  'Reason: ' + decisionRecord.halt_reason + '\n' +
                                  'CDR SHA-256: ' + cdrHash + '\n' +
                                  'Canonical Decision Record (RFC 8785):\n' + canonicalCDR;

        if (decisionRecord.allow === true) {
            chgGr.work_notes = formattedAuditEntry;
        } else {
            gs.eventQueue('x_bigf.gate.hard_halt', chgGr, cdrHash, canonicalCDR);
            gs.error('[BIGF-CDR-IMMUTABLE] ' + formattedAuditEntry);
        }

        if (gs.tableExists('u_bigf_decision_log') && decisionRecord.allow === true) {
            var logGr = new GlideRecord('u_bigf_decision_log');
            logGr.initialize();
            logGr.setValue('u_change_request', decisionRecord.change_sys_id);
            logGr.setValue('u_decision', 'ALLOW');
            logGr.setValue('u_cdr_sha256', cdrHash);
            logGr.setValue('u_canonical_cdr', canonicalCDR);
            logGr.insert();
        }
    },

    type: 'BIGFGateClient'
};

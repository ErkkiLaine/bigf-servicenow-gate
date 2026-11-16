(function(event, current) {
    var cdrHash = String(event.parm1 || '');
    var canonicalCDR = String(event.parm2 || '');
    var parsed = {};
    try {
        parsed = JSON.parse(canonicalCDR);
    } catch (e) {}

    if (gs.tableExists('u_bigf_decision_log')) {
        var logGr = new GlideRecord('u_bigf_decision_log');
        logGr.initialize();
        logGr.setValue('u_change_request', parsed.change_sys_id || '');
        logGr.setValue('u_decision', '403_HARD_HALT');
        logGr.setValue('u_cdr_sha256', cdrHash);
        logGr.setValue('u_canonical_cdr', canonicalCDR);
        logGr.insert();
    }

    if (parsed.change_sys_id) {
        var chgGr = new GlideRecord('change_request');
        if (chgGr.get(parsed.change_sys_id)) {
            chgGr.work_notes = '[BIGF v2.4 RUNTIME GATE — 403 HARD HALT (POST-ABORT AUDIT)]\n' +
                               'Reason: ' + (parsed.halt_reason || 'HARD HALT') + '\n' +
                               'CDR SHA-256: ' + cdrHash + '\n' +
                               'Canonical Decision Record (RFC 8785):\n' + canonicalCDR;
            chgGr.setWorkflow(false);
            chgGr.update();
        }
    }
})(event, current);

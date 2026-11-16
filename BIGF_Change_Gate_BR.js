(function executeRule(current, previous /*null when async*/) {
    var gate = new BIGFGateClient();
    var decision = gate.evaluateChangeRequest(current);

    if (decision.allow === true) {
        current.approval = 'approved';
        gs.addInfoMessage('BIGF v2.4 Gate: Change ' + current.getValue('number') + ' AUTHORIZED (200 OK). Canonical Decision Record logged.');
    } else {
        current.approval = 'rejected';
        current.setAbortAction(true);
        gs.addErrorMessage('BIGF v2.4 Gate: ' + decision.halt_reason + ' — State transition aborted (Fail-Closed).');
    }
})(current, previous);

// Copyright (C) 2017-2022 BinaryMist Limited. All rights reserved.

// Use of this software is governed by the Business Source License
// included in the file /licenses/bsl.md

// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0

// Originally created for gemeni.health
/* eslint-disable */

function log(msg) {
    print('[' + this['zap.script.name'] + '] ' + msg);
}

var HttpSender = Java.type('org.parosproxy.paros.network.HttpSender');
var ScriptVars = Java.type('org.zaproxy.zap.extension.script.ScriptVars');
var HtmlParameter = Java.type('org.parosproxy.paros.network.HtmlParameter')
var debug = true;

function sendingRequest(msg, initiator, helper) {
    debug && log('sendingRequest. Initiator: ' + initiator);
    if (initiator === HttpSender.AUTHENTICATION_INITIATOR) {
        log("Zap is trying to authenticate");
        return msg;
    }

    var accessToken = ScriptVars.getGlobalVar("accessToken");
    if (!accessToken) {
        log('Zap has not yet stored the access token, so unable to add it as a header.');
        msg.getRequestHeader().setHeader('Authorization', 'Bearer notset');
        return msg;
    }
    log("Added authorization token " + accessToken.slice(0, 20) + " ... ");
    msg.getRequestHeader().setHeader('Authorization', 'Bearer ' + accessToken);
    return msg;
}

function responseReceived(msg, initiator, helper) {
    debug && log('responseReceived. Initiator: ' + initiator);
    var resbody     = msg.getResponseBody().toString();
    var resheaders  = msg.getResponseHeader();

    if (initiator !== HttpSender.AUTHENTICATION_INITIATOR) { 
        return;
    }

    log("Handling authentication response")
    if (resheaders.getStatusCode() > 299) {
        log("Zap authentication failed.");
        return;
    }

    // Is response JSON? @todo check content-type
    log('content-type header value: ' + resheaders.getHeader('content-type'));
    
    if (!resheaders.hasContentType('application/json')) {
        log("authentication response was not JSON.");
        log('auth resp follows: ' + resbody);
        return;
    }

    try {
        var data = JSON.parse(resbody);
    } catch (e) {
        log("authentication response was unable to be parsed as JSON.")
        return;
    }

    // If auth request was not succesful move on
    if (!data['access_token']) {
        log("authentication response contained no access token.");
        return;
    }
    
    // @todo abstract away to be configureable
    var accessToken = data["access_token"];
    log("Capturing access token for JWT and storing to Zap:\n" + accessToken);
    ScriptVars.setGlobalVar("accessToken", accessToken);
}
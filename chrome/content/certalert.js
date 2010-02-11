/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *  
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete 
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *                              
 * ***** END LICENSE BLOCK ***** */

(function() {
if (typeof(Cc) == "undefined")
    var Cc = Components.classes;
if (typeof(Ci) == "undefined")
    var Ci = Components.interfaces;
  
var CertAlert = {

  log: function (s) {
    var _consoleService = Cc["@mozilla.org/consoleservice;1"].getService(Ci.nsIConsoleService);
    _consoleService.logStringMessage(s);
  },
    
    
  onLoad: function(e) {
    var content = document.getElementById("content");
    if(content) {
        content.addEventListener("DOMContentLoaded", this.onPageLoad, true);
    }
  },
  
  onPageLoad: function(event) {
    var doc = event.originalTarget;
    if (doc.location.protocol == "https:") {
        CertAlert.onSecurePageLoad(doc);
    }
  },
  
  onSecurePageLoad: function(doc) {
  
    const promptStrings = document.getElementById('certalert-stringbundle-prompt');

    var browser = gBrowser.getBrowserForDocument(doc);
    var ui = browser.securityUI.QueryInterface(Ci.nsISSLStatusProvider);
    var stats = ui.QueryInterface(Ci.nsISSLStatusProvider).SSLStatus;
    
    // Not yet accepted SSL    
    if (!stats)
        return;
    
    var status = stats.QueryInterface(Ci.nsISSLStatus);
    var cert = status.serverCert;
    if (!cert)
        return;
    if (this.getVerify(cert) !== 'Verified_OK') 
        return;
        
    if(CertAlert.checkFingerPrint(cert) == -1) {
        // window.openDialog ("about:certerror", "certerror", "chrome,centerscreen");
        
      this.showNotificationBox (browser, promptStrings.getFormattedString('prompt.unsecure.host', 
        [(cert.issuerCommonName ? cert.issuerCommonName : cert.issuerOrganization)
        + ' > ' +cert.commonName ]),
        promptStrings.getString('prompt.unsecure.more'),
        promptStrings.getString('prompt.unsecure.ignore'),
        "http://bit.ly/9vYAlF");        
    }
  },

  getVerify: function (cert) {  
    switch (cert.verifyForUsage(Ci.nsIX509Cert.CERT_USAGE_SSLServer)) {
      case Ci.nsIX509Cert.VERIFIED_OK: 
        return 'Verified_OK';
      case Ci.nsIX509Cert.NOT_VERIFIED_UNKNOWN:
        return "not verfied/unknown";
      case Ci.nsIX509Cert.CERT_REVOKED:
        return "revoked";
      case Ci.nsIX509Cert.CERT_EXPIRED:
        return "expired";
      case Ci.nsIX509Cert.CERT_NOT_TRUSTED:
        return "not trusted";
      case Ci.nsIX509Cert.ISSUER_NOT_TRUSTED:
        return "issuer not trusted";
      case Ci.nsIX509Cert.ISSUER_UNKNOWN:
        return "issuer unknown";
      case Ci.nsIX509Cert.INVALID_CA:
        return "invalid CA";
      default:
        return "unexpected failure";
    }
  },   
    
  checkFingerPrint: function(cert) {
    this.log(cert.issuerName + ' - ' + cert.sha1Fingerprint);
    
    // FIXME: shoud be a database to handle the keys.
    if(cert.sha1Fingerprint == '68:56:BB:1A:6C:4F:76:DA:CA:36:21:87:CC:2C:CD:48:4E:DD:C2:5D' ||
        cert.sha1Fingerprint == 'AA:CA:FB:20:21:98:0A:D5:7E:55:32:1E:DC:90:41:A2:F1:B3:16:54' ||
        cert.sha1Fingerprint == '8B:AF:4C:9B:1D:F0:2A:92:F7:DA:12:8E:B9:1B:AC:F4:98:60:4B:6F') {
        return -1;
    }
    if(cert.issuer.sha1Fingerprint !== cert.sha1Fingerprint) {
        return CertAlert.checkFingerPrint(cert.issuer);
    }
  },
  
  showNotificationBox: function (browser, text, btnText1, btnText2, infoLink) {
    var box  = gBrowser.getNotificationBox();  
    var icon = null;
    var pr   = box.PRIORITY_CRITICAL_BLOCK;
    var btns = [{
      _store : {  _browser  : browser,
                  _infoLink : infoLink },
      label        : btnText1, 
      callback     : function (box,btn) {        
        btn._store._browser.loadURI(btn._store._infoLink, null, 'UTF-8');}
    },{
      label        : btnText2, 
      callback     : function (box,btn) {box.close();} 
    }];
  	
    box.appendNotification(text, "cert-notify", icon, pr, btns);
  }  
}

window.addEventListener("load", function(e) { CertAlert.onLoad(e); }, false);
})();

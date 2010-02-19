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

if (typeof(Cc) == "undefined")
    var Cc = Components.classes;
if (typeof(Ci) == "undefined")
    var Ci = Components.interfaces;
if (typeof(Cu) == "undefined")
    var Cu = Components.utils;
    
Components.utils.import("resource://gre/modules/XPCOMUtils.jsm");

var CertAlert = {
  classDescription: "CertAlert XPCOM Component",
  classID:          Components.ID("{b34f4fbe-1da5-11df-8c91-001f16155cce}"),
  contractID:       "@github.com/certalert;1",
  _xpcom_categories: [{ category: "app-startup", service: true }],

  getHelperForLanguage: function getHelperForLanguage(aLanguage) {
                            return null;
                        },
                        
  getInterfaces: function getInterfaces(aCount) {
    var interfaces = [Ci.nsIObserver, Ci.nsIClassInfo, Ci.nsSupports, Ci.nsISupportsWeakReference];
    aCount.value = interfaces.length;
    return interfaces;
  },
        
  QueryInterface: XPCOMUtils.generateQI([Ci.nsIObserver, Ci.nsIClassInfo, Ci.nsSupports, Ci.nsISupportsWeakReference]),

  // nsIObserver
  observe: function (aSubject, aTopic, aData) {
    if (aTopic == "app-startup") {
        // this.log('app-startup');
        // monitor every response.
        var observerService = Cc["@mozilla.org/observer-service;1"]
                                .getService(Ci.nsIObserverService);
        observerService.addObserver(CertAlert.httpResonseObserver, "http-on-examine-response", false);    
    }
  },
      
  log: function (s) {
    var _consoleService = Cc["@mozilla.org/consoleservice;1"].getService(Ci.nsIConsoleService);
    _consoleService.logStringMessage(s);
  },
  
  httpResonseObserver: {
    observe: function(aSubject, aTopic, aData) 
    {
        // CertAlert.log('http-on-examine-response');
        if (aTopic == "http-on-examine-response") {
            var httpChannel = aSubject.QueryInterface(Components.interfaces.nsIHttpChannel);
            var uri = httpChannel.URI.asciiSpec;
            
            // This request does not use SSL.
            if(httpChannel.securityInfo === null) 
                return;

            var status = httpChannel.securityInfo.
                QueryInterface(Ci.nsISSLStatusProvider).SSLStatus;
                
            var cert =
                status.QueryInterface(Ci.nsISSLStatus).
                serverCert;

            var notificationCallbacks = null;
            if(httpChannel.notificationCallbacks) 
                notificationCallbacks = httpChannel.notificationCallbacks;
            else 
                notificationCallbacks = httpChannel.loadGroup.notificationCallbacks;
            
            var window = null;
            try {
                // this call throws failure exception when download favicon.
                window = notificationCallbacks.getInterface(Ci.nsIDOMWindow);
            } catch (e) {}
             
            // It seems this is not necessary.    
            // if (CertAlert.getVerify(cert) !== 'Verified_OK') {
            //    return;        
            // }

            if(window === null)
                return;

            if(CertAlert.checkFingerPrint(cert) == -1) {
                var stringbundle = Cc["@mozilla.org/intl/stringbundle;1"]
                    .getService(Ci.nsIStringBundleService)
                    .createBundle("chrome://certalert/locale/prompt.properties");

                CertAlert.showNotificationBox (window.top, stringbundle.formatStringFromName ('prompt.unsecure.host', 
                    [(cert.issuerCommonName ? cert.issuerCommonName : cert.issuerOrganization) + ' > ' + cert.commonName ], 1),
                    stringbundle.GetStringFromName('prompt.unsecure.more'),
                    stringbundle.GetStringFromName('prompt.unsecure.ignore'),
                    "http://bit.ly/9vYAlF");
            }
          
      }
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
    // this.log(cert.issuerName + ' - ' + cert.sha1Fingerprint);
    
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
  
  getNotificationBox: function (aWindow) {
    var notifyBox = null;

    // Given a content DOM window, returns the chrome window it's in.
    function getChromeWindow(aWindow) {
        var chromeWin = aWindow
            .QueryInterface(Ci.nsIInterfaceRequestor)
            .getInterface(Ci.nsIWebNavigation)
            .QueryInterface(Ci.nsIDocShellTreeItem)
            .rootTreeItem
            .QueryInterface(Ci.nsIInterfaceRequestor)
            .getInterface(Ci.nsIDOMWindow)
            .QueryInterface(Ci.nsIDOMChromeWindow);
        return chromeWin;
    }

    var notifyWindow = aWindow;
    if (aWindow.opener) {
        var chromeDoc = getChromeWindow(notifyWindow).document.documentElement;

        var webnav = notifyWindow
                    .QueryInterface(Ci.nsIInterfaceRequestor)
                    .getInterface(Ci.nsIWebNavigation);

        // Check to see if the current window was opened with chrome
        // disabled, and if so use the opener window. But if the window
        // has been used to visit other pages (ie, has a history),
        // assume it'll stick around and *don't* use the opener.
        if (chromeDoc.getAttribute("chromehidden") &&
            webnav.sessionHistory.count == 1) {
            this.log("Using opener window for notification bar.");
            notifyWindow = notifyWindow.opener;
        }
     
    }
 
    var chromeWin = getChromeWindow(notifyWindow).wrappedJSObject;

    if (chromeWin && chromeWin.getNotificationBox)
        notifyBox = chromeWin.getNotificationBox(notifyWindow);
    else
        CertAlert.log("getNotificationBox() not available on window");

     return notifyBox;
  },

  showNotificationBox: function (window, text, btnText1, btnText2, infoLink) {
    // gBrowser.getNotificationBox();  
    var box  = CertAlert.getNotificationBox(window);
    if(!box) return;

    var icon = null;
    var pr   = box.PRIORITY_CRITICAL_BLOCK;
    var btns = [{
            _store: {  
                _window: window,
                _infoLink: infoLink 
            },    
            label: btnText1, 
            accessKey: 'M',
            callback: function (box, btn) {
                btn._store._window.open(btn._store._infoLink);
                // box.close();                
            },
        },{
            label: btnText2, 
            accessKey: 'I',            
            callback: function (box,btn) {
                box.close();
            } 
    }];

    // Only append one notification for one winodw.
    if(box.getNotificationWithValue("cert-notify") === null) 
        box.appendNotification(text, "cert-notify", icon, pr, btns);
  }
}

function CertAlertComponent () {}
CertAlertComponent.prototype = CertAlert;


function NSGetModule(compMgr, fileSpec) {
      // "components" is the array created in the previous section
      // return XPCOMUtils.generateModule(components);
      return XPCOMUtils.generateModule([CertAlertComponent]);
}

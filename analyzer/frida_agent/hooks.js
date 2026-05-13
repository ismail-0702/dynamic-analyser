function emit(etype, edata) {
    try {
        send({ "type": etype, "data": edata, "timestamp": new Date().toISOString() });
    } catch(_) {}
}

function getEntry(instance, idName) {
    try {
        var resId = instance.getResources().getIdentifier(idName, "id", instance.getPackageName());
        var view = instance.findViewById(resId);
        var castView = Java.cast(view, Java.use("android.widget.EditText"));
        return castView.getText().toString();
    } catch(e) { return ""; }
}

var hooksInstalled = false;

function installHooks() {
    if (hooksInstalled) return;
    hooksInstalled = true;

    Java.perform(function() {

        try {
            var Cipher = Java.use("javax.crypto.Cipher");
            Cipher.getInstance.overload('java.lang.String').implementation = function(algo) {
                emit("crypto", { "operation": "Encryption", "algorithm": algo });
                return this.getInstance(algo);
            };
        } catch(e) { emit("hook_error", { hook: "Cipher", error: e.toString() }); }

        try {
            var URL = Java.use("java.net.URL");
            URL.$init.overload('java.lang.String').implementation = function(url) {
                emit("network", { "method": "GET", "url": url });
                return this.$init(url);
            };
        } catch(e) { emit("hook_error", { hook: "URL", error: e.toString() }); }

        try {
            var IDS1 = Java.use("jakhar.aseem.diva.InsecureDataStorage1Activity");
            IDS1.saveCredentials.implementation = function(v) {
                emit("file", {
                    "operation": "WRITE",
                    "path": "/data/user/0/jakhar.aseem.diva/shared_prefs/ids1.xml",
                    "password": getEntry(this, "ids1Pwd")
                });
                return this.saveCredentials(v);
            };
        } catch(e) { emit("hook_error", { hook: "IDS1", error: e.toString() }); }

        try {
            var IDS2 = Java.use("jakhar.aseem.diva.InsecureDataStorage2Activity");
            IDS2.saveCredentials.implementation = function(v) {
                emit("file", {
                    "operation": "WRITE",
                    "path": "/data/user/0/jakhar.aseem.diva/databases/ids2.db",
                    "password": getEntry(this, "ids2Pwd")
                });
                return this.saveCredentials(v);
            };
        } catch(e) { emit("hook_error", { hook: "IDS2", error: e.toString() }); }

        try {
            var IDS3 = Java.use("jakhar.aseem.diva.InsecureDataStorage3Activity");
            IDS3.saveCredentials.implementation = function(v) {
                emit("file", {
                    "operation": "WRITE",
                    "path": "/sdcard/ids3.xml",
                    "password": getEntry(this, "ids3Pwd")
                });
                return this.saveCredentials(v);
            };
        } catch(e) { emit("hook_error", { hook: "IDS3", error: e.toString() }); }

        try {
            var SQL = Java.use("jakhar.aseem.diva.SQLInjectionActivity");
            SQL.search.implementation = function(v) {
                emit("sql", {
                    "operation": "rawQuery",
                    "query": "SELECT * FROM users WHERE name = '" + getEntry(this, "srchSearch") + "'"
                });
                return this.search(v);
            };
        } catch(e) { emit("hook_error", { hook: "SQL", error: e.toString() }); }

        try {
            var SP = Java.use("android.app.SharedPreferencesImpl");
            SP.getString.implementation = function(key, def) {
                var val = this.getString(key, def);
                emit("file", {
                    "operation": "SharedPreferences.READ",
                    "key": key ? key.toString() : "",
                    "value": val ? val.toString().substring(0, 50) : null
                });
                return val;
            };
        } catch(e) { emit("hook_error", { hook: "SharedPrefs", error: e.toString() }); }

        emit("system", { "message": "Tous les hooks DIVA actifs" });
    });
}

// Installer les hooks après 2 secondes automatiquement
setTimeout(function() {
    installHooks();
}, 2000);

emit("system", { "message": "Script chargé" });
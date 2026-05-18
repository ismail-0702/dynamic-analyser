/**
 * Hooks DIVA — installation dynamique quand chaque Activity s'ouvre.
 */
var _lastEmit = {};
var _hookedClasses = {};

function emit(etype, edata) {
    try {
        var now = Date.now();
        var isDiva = (edata.operation || "").indexOf("DIVA.") === 0;
        var minMs = isDiva ? 80 : 250;
        var throttleKey = etype + ":" + (edata.operation || "") + ":" + (edata.key || "") + ":" + (edata.activity || "");
        if (_lastEmit[throttleKey] && now - _lastEmit[throttleKey] < minMs) return;
        _lastEmit[throttleKey] = now;
        send({ type: etype, data: edata, timestamp: new Date().toISOString() });
    } catch (_) {}
}

function isSensitive(text) {
    if (!text) return false;
    var t = String(text).toLowerCase();
    return ["pass", "pwd", "user", "login", "pin", "secret", "token", "cred", "key", "diva"].some(
        function (s) { return t.indexOf(s) !== -1; }
    );
}

function hookDivaClass(className) {
    if (_hookedClasses[className]) return;
    _hookedClasses[className] = true;

    try {
        var Cls = Java.use(className);
        var methods = Cls.class.getDeclaredMethods();
        for (var i = 0; i < methods.length; i++) {
            (function (methodName) {
                var lower = methodName.toLowerCase();
                if (
                    lower.indexOf("save") === -1 &&
                    lower.indexOf("store") === -1 &&
                    lower.indexOf("write") === -1 &&
                    lower.indexOf("log") === -1 &&
                    lower.indexOf("send") === -1
                ) {
                    return;
                }
                try {
                    Cls[methodName].overloads.forEach(function (ovl) {
                        ovl.implementation = function () {
                            emit("file", {
                                operation: "DIVA." + methodName,
                                activity: className,
                                path: "shared_prefs",
                            });
                            return ovl.apply(this, arguments);
                        };
                    });
                } catch (_) {}
            })(methods[i].getName());
        }
        emit("system", { message: "Hooks installés: " + className.split(".").pop() });
    } catch (_) {}
}

Java.perform(function () {
    emit("system", { message: "Hooks DIVA — en attente des activités" });

    // ── Quand l'utilisateur ouvre un écran DIVA → installer les hooks ────────
    try {
        var Activity = Java.use("android.app.Activity");
        Activity.onResume.implementation = function () {
            var name = this.getClass().getName();
            if (name.indexOf("jakhar.aseem.diva") !== -1) {
                hookDivaClass(name);
                emit("system", { message: "Écran ouvert", activity: name });
            }
            return this.onResume();
        };
    } catch (e) {
        emit("hook_error", { hook: "Activity.onResume", error: String(e) });
    }

    // ── 1. INSECURE LOGGING ───────────────────────────────────────────────────
    try {
        var Log = Java.use("android.util.Log");
        ["d", "i", "w", "e"].forEach(function (level) {
            var m = level.toUpperCase();
            Log[level].overload("java.lang.String", "java.lang.String").implementation = function (tag, msg) {
                var s = msg ? String(msg) : "";
                var tg = tag ? String(tag).toLowerCase() : "";
                if (s.length > 0 && (isSensitive(s) || isSensitive(tg) || tg.indexOf("motion") !== -1)) {
                    emit("file", {
                        operation: "Log." + m,
                        tag: tag ? String(tag) : "",
                        message: s.substring(0, 120),
                    });
                }
                return this[level](tag, msg);
            };
        });
    } catch (e) {
        emit("hook_error", { hook: "Log", error: String(e) });
    }

    // ── 3–6. SharedPreferences (toutes clés à l'écriture) ─────────────────────
    try {
        var Editor = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
        Editor.putString.implementation = function (key, value) {
            var k = key ? key.toString() : "";
            var v = value ? String(value) : "";
            emit("file", {
                operation: "SharedPreferences.WRITE",
                key: k,
                value_preview: v.substring(0, 60),
                path: "SharedPreferences",
            });
            return this.putString(key, value);
        };
    } catch (e) {
        emit("hook_error", { hook: "SharedPrefs", error: String(e) });
    }

    // ── Fichiers (stockage externe / interne) ─────────────────────────────────
    try {
        var FOS = Java.use("java.io.FileOutputStream");
        FOS.$init.overload("java.lang.String").implementation = function (path) {
            var p = path ? String(path) : "";
            if (p.indexOf("diva") !== -1 || p.indexOf("jakhar") !== -1 || p.indexOf(".txt") !== -1) {
                emit("file", { operation: "WRITE", path: p });
            }
            return this.$init(path);
        };
    } catch (e) {}

  // ── SQL (parties 3–4 stockage BDD) ──────────────────────────────────────────
    try {
        var DB = Java.use("android.database.sqlite.SQLiteDatabase");
        DB.execSQL.overload("java.lang.String").implementation = function (sql) {
            emit("sql", { operation: "execSQL", query: sql ? String(sql).substring(0, 200) : "" });
            return this.execSQL(sql);
        };
        DB.insert.overload("java.lang.String", "java.lang.String", "android.content.ContentValues").implementation =
            function (table, nullColumnHack, values) {
                emit("sql", { operation: "insert", query: "INSERT INTO " + table });
                return this.insert(table, nullColumnHack, values);
            };
    } catch (e) {}

    // ── Réseau ────────────────────────────────────────────────────────────────
    try {
        var URL = Java.use("java.net.URL");
        URL.$init.overload("java.lang.String").implementation = function (url) {
            emit("network", { method: "GET", url: String(url) });
            return this.$init(url);
        };
    } catch (e) {}

    // ── Crypto ────────────────────────────────────────────────────────────────
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher.getInstance.overload("java.lang.String").implementation = function (algo) {
            emit("crypto", { operation: "getInstance", algorithm: String(algo) });
            return this.getInstance(algo);
        };
    } catch (e) {}

    // ── IPC / Access control (Intents) ────────────────────────────────────────
    try {
        var Activity = Java.use("android.app.Activity");
        Activity.startActivity.overload("android.content.Intent").implementation = function (intent) {
            try {
                var comp = intent.getComponent();
                emit("ipc", {
                    operation: "startActivity",
                    target: comp ? comp.getClassName() : String(intent),
                });
            } catch (_) {}
            return this.startActivity(intent);
        };
    } catch (e) {}

    emit("system", { message: "Prêt — ouvrez chaque exercice DIVA" });
});

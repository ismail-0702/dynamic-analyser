"""
apk_parser.py — Analyse statique de l'APK
Extrait : manifest, permissions, activités, secrets hardcodés, bibliothèques natives
Dépendance : androguard
"""

import re
import logging
from pathlib import Path
from typing import Optional

log = logging.getLogger("apk_parser")

# Niveaux de protection Android
PROTECTION_LEVELS = {
    "0": "normal",
    "1": "dangerous",
    "2": "signature",
    "3": "signatureOrSystem",
}

# Permissions dangereuses connues
DANGEROUS_PERMISSIONS = {
    "READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS",
    "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
    "READ_PHONE_STATE", "READ_PHONE_NUMBERS", "CALL_PHONE",
    "READ_CALL_LOG", "WRITE_CALL_LOG", "PROCESS_OUTGOING_CALLS",
    "RECORD_AUDIO", "CAMERA",
    "READ_SMS", "SEND_SMS", "RECEIVE_SMS", "READ_MMS", "SEND_MMS",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
    "BODY_SENSORS", "ACTIVITY_RECOGNITION",
    "BLUETOOTH_SCAN", "BLUETOOTH_CONNECT",
    "NEARBY_WIFI_DEVICES",
}

CRITICAL_PERMISSIONS = {
    "READ_SMS", "RECORD_AUDIO", "ACCESS_FINE_LOCATION",
    "READ_CONTACTS", "PROCESS_OUTGOING_CALLS", "CAMERA",
    "READ_CALL_LOG", "ACCESS_BACKGROUND_LOCATION",
}

# Patterns pour secrets hardcodés
SECRET_PATTERNS = [
    ("aws_access_key",    r"AKIA[0-9A-Z]{16}",                              "critical"),
    ("aws_secret_key",    r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]", "critical"),
    ("google_api_key",    r"AIza[0-9A-Za-z\-_]{35}",                        "critical"),
    ("firebase_url",      r"https://[a-z0-9-]+\.firebaseio\.com",            "high"),
    ("jwt_token",         r"eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*", "high"),
    ("private_key",       r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",       "critical"),
    ("basic_auth",        r"(?i)authorization:\s*basic\s+[a-z0-9+/=]{20,}", "high"),
    ("http_url",          r"http://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{10,}", "medium"),
    ("github_token",      r"ghp_[0-9a-zA-Z]{36}",                           "critical"),
    ("stripe_key",        r"sk_live_[0-9a-zA-Z]{24}",                       "critical"),
    ("password_hardcoded",r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{6,}['\"]", "high"),
    ("api_key_generic",   r"(?i)(api_key|apikey|api-key)\s*[=:]\s*['\"][a-z0-9\-_]{16,}['\"]", "high"),
]


class APKStaticAnalyzer:
    """Analyse statique d'un APK Android via androguard."""

    def __init__(self, apk_path: str):
        self.apk_path = str(apk_path)
        self._apk = None
        self._dex = None
        self._analysis = None
        self._loaded = False

    def _load(self):
        if self._loaded:
            return
        try:
            from androguard.misc import AnalyzeAPK
            log.info("Chargement de l'APK avec androguard…")
            self._apk, self._dex, self._analysis = AnalyzeAPK(self.apk_path)
            self._loaded = True
            log.info("APK chargé : %s", self._apk.get_package())
        except ImportError:
            raise RuntimeError("androguard non installé. Lancer: pip install androguard")
        except Exception as e:
            raise RuntimeError(f"Erreur chargement APK: {e}")

    # ── Manifest ──────────────────────────────────────────────────────────────

    def get_manifest_info(self) -> dict:
        self._load()
        apk = self._apk
        try:
            debuggable = apk.get_attribute_value("application", "debuggable") == "true"
        except Exception:
            debuggable = False
        try:
            allow_backup = apk.get_attribute_value("application", "allowBackup") != "false"
        except Exception:
            allow_backup = True
        try:
            cleartext = apk.get_attribute_value("application", "usesCleartextTraffic") == "true"
        except Exception:
            cleartext = False
        try:
            nsc = apk.get_attribute_value("application", "networkSecurityConfig") is not None
        except Exception:
            nsc = False

        return {
            "package":                apk.get_package(),
            "version_name":           apk.get_androidversion_name() or "N/A",
            "version_code":           apk.get_androidversion_code() or "N/A",
            "min_sdk":                apk.get_min_sdk_version() or "N/A",
            "target_sdk":             apk.get_target_sdk_version() or "N/A",
            "app_name":               apk.get_app_name() or "N/A",
            "debuggable":             debuggable,
            "allow_backup":           allow_backup,
            "uses_cleartext_traffic": cleartext,
            "network_security_config":nsc,
            "main_activity":          apk.get_main_activity() or "N/A",
            "icon":                   None,  # Base64 optionnel si besoin
        }



    def get_resource_strings(self) -> list:
        """Recherche des secrets dans les fichiers de ressources XML."""
        self._load()
        findings = []
        # Accès aux ressources via androguard
        resources = self._apk.get_android_resources()
        if not resources:
            return []
    
        # Parcours des chaînes de caractères déclarées dans strings.xml
        for string_value in resources.get_strings_resources():
            for secret_type, pattern, severity in SECRET_PATTERNS:
                if re.search(pattern, string_value):
                    findings.append({
                        "type": secret_type,
                        "value": string_value[:30],
                        "location": "resources.arsc",
                        "severity": severity
                    })
        return findings


    # ── Permissions ───────────────────────────────────────────────────────────

    def get_declared_permissions(self) -> list:
        self._load()
        results = []
        for perm in self._apk.get_permissions():
            short = perm.replace("android.permission.", "").replace("com.android.browser.permission.", "")
            if short in CRITICAL_PERMISSIONS:
                severity = "critical"
            elif short in DANGEROUS_PERMISSIONS:
                severity = "high"
            else:
                severity = "medium"

            protection = "dangerous" if short in DANGEROUS_PERMISSIONS else "normal"
            results.append({
                "name":             perm,
                "short_name":       short,
                "protection_level": protection,
                "severity":         severity,
            })
        return sorted(results, key=lambda x: ["critical","high","medium","normal"].index(x["severity"]))

    # ── Composants ────────────────────────────────────────────────────────────

    def get_activities(self) -> list:
        self._load()
        activities = []
        for a in self._apk.get_activities():
            exported = self._apk.get_attribute_value("activity", "exported", name=a)
            activities.append({
                "name":     a,
                "exported": exported == "true",
                "is_main":  a == self._apk.get_main_activity(),
            })
        return activities

    def get_services(self) -> list:
        self._load()
        services = []
        for s in self._apk.get_services():
            exported = self._apk.get_attribute_value("service", "exported", name=s)
            services.append({
                "name":     s,
                "exported": exported == "true",
            })
        return services

    def get_receivers(self) -> list:
        self._load()
        receivers = []
        for r in self._apk.get_receivers():
            exported = self._apk.get_attribute_value("receiver", "exported", name=r)
            receivers.append({
                "name":     r,
                "exported": exported == "true",
            })
        return receivers

    def get_providers(self) -> list:
        self._load()
        providers = []
        for p in self._apk.get_providers():
            exported = self._apk.get_attribute_value("provider", "exported", name=p)
            providers.append({
                "name":     p,
                "exported": exported == "true",
            })
        return providers

    # ── Secrets hardcodés ─────────────────────────────────────────────────────

    def get_hardcoded_secrets(self) -> list:
        self._load()
        findings = []
        seen = set()

        # Scanner toutes les strings du DEX
        for cls in self._analysis.get_classes():
            class_name = cls.name.replace("/", ".").strip("L;")
            try:
                for method in cls.get_methods():
                    for inst in method.get_method().get_instructions():
                        if inst.get_name() in ("const-string", "const-string/jumbo"):
                            val = inst.get_output().split(", ")[-1].strip("'")
                            for secret_type, pattern, severity in SECRET_PATTERNS:
                                if re.search(pattern, val):
                                    key = f"{secret_type}:{val[:20]}"
                                    if key not in seen:
                                        seen.add(key)
                                        # Tronquer pour ne pas exposer la valeur complète
                                        preview = val[:30] + "…" if len(val) > 30 else val
                                        findings.append({
                                            "type":      secret_type,
                                            "value":     preview,
                                            "class":     class_name,
                                            "method":    str(method),
                                            "severity":  severity,
                                        })
            except Exception:
                continue

        return sorted(findings, key=lambda x: ["critical","high","medium"].index(x["severity"]))

    # ── Bibliothèques natives ─────────────────────────────────────────────────

    def get_native_libraries(self) -> list:
        self._load()
        libs = []
        try:
            for f in self._apk.get_files():
                if f.endswith(".so"):
                    libs.append(f)
        except Exception:
            pass
        return libs

    # ── Bibliothèques tierces ─────────────────────────────────────────────────

    def get_third_party_sdks(self) -> list:
        self._load()
        known_sdks = {
            "com.google.firebase":     ("Firebase",         "medium"),
            "com.google.android.gms":  ("Google Play Svcs", "low"),
            "com.facebook":            ("Facebook SDK",      "high"),
            "com.appsflyer":           ("AppsFlyer",         "high"),
            "com.amplitude":           ("Amplitude",         "medium"),
            "com.mixpanel":            ("Mixpanel",          "medium"),
            "io.branch":               ("Branch.io",         "medium"),
            "com.onesignal":           ("OneSignal",         "medium"),
            "com.adjust":              ("Adjust",            "high"),
            "com.crashlytics":         ("Crashlytics",       "low"),
            "io.sentry":               ("Sentry",            "low"),
            "com.squareup.okhttp3":    ("OkHttp3",           "low"),
            "retrofit2":               ("Retrofit",          "low"),
        }
        found = {}
        try:
            for cls in self._analysis.get_classes():
                name = cls.name.replace("/", ".").strip("L;")
                for prefix, (sdk_name, severity) in known_sdks.items():
                    if name.startswith(prefix) and sdk_name not in found:
                        found[sdk_name] = {
                            "name":     sdk_name,
                            "package":  prefix,
                            "severity": severity,
                        }
        except Exception:
            pass
        return list(found.values())

    # ── Rapport complet ───────────────────────────────────────────────────────

    def get_full_report(self) -> dict:
        self._load()
        log.info("Génération du rapport statique complet…")

        manifest   = self.get_manifest_info()
        perms      = self.get_declared_permissions()
        activities = self.get_activities()
        services   = self.get_services()
        receivers  = self.get_receivers()
        providers  = self.get_providers()
        secrets    = self.get_hardcoded_secrets()
        native     = self.get_native_libraries()
        sdks       = self.get_third_party_sdks()

        # Score statique rapide
        static_risk = 0
        if manifest.get("debuggable"):           static_risk += 20
        if manifest.get("uses_cleartext_traffic"):static_risk += 15
        if manifest.get("allow_backup"):         static_risk += 10
        static_risk += sum(10 for p in perms if p["severity"] == "critical")
        static_risk += sum(5  for p in perms if p["severity"] == "high")
        static_risk += sum(20 for s in secrets if s["severity"] == "critical")
        static_risk += sum(10 for s in secrets if s["severity"] == "high")
        static_risk += sum(5  for a in activities if a.get("exported"))

        exported_components = (
            [a for a in activities if a.get("exported")] +
            [s for s in services   if s.get("exported")] +
            [r for r in receivers  if r.get("exported")]
        )

        return {
            "manifest":             manifest,
            "permissions":          perms,
            "activities":           activities,
            "services":             services,
            "receivers":            receivers,
            "providers":            providers,
            "exported_components":  exported_components,
            "hardcoded_secrets":    secrets,
            "native_libraries":     native,
            "third_party_sdks":     sdks,
            "static_risk_score":    min(100, static_risk),
            "summary": {
                "total_permissions":      len(perms),
                "dangerous_permissions":  sum(1 for p in perms if p["severity"] in ("high","critical")),
                "exported_components":    len(exported_components),
                "hardcoded_secrets":      len(secrets),
                "native_libs":            len(native),
                "third_party_sdks":       len(sdks),
            }
        }
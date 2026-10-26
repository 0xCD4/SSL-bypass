/**
 * Universal Android Security Bypass Suite — v3.0 (optimized & fixed)
 *
 * Yalnızca yetkili güvenlik araştırması / sızma testi (pentest) için.
 *
 * Kullanım:
 *   frida -U -f <paket.adı> -l android-bypass-v3.js
 * Burp CA (native katman için):
 *   adb push cacert.der /data/local/tmp/cert-der.crt
 *
 * v3 değişiklikleri (v2'ye göre):
 *  - connect() port kontrolünde byte-order ve sa_family okuma hataları düzeltildi
 *  - /proc/self/maps · status için geçerli, çalışan redirect mekanizması
 *    (eski "new File(fd,...)" kodu Frida'da yoktu, her seferinde exception atıyordu)
 *  - Runtime.exec / ProcessBuilder komut engelleme regex yerine token-bazlı oldu
 *    (eski regex "sh", "id", "su" alt dizgileri yüzünden normal komutları da kırıyordu)
 *  - ProcessBuilder.command(List) artık gerçek java.util.List ile çağrılıyor
 *  - pm list kontrolünde yanlış argüman indeksi (cmdarray[2] "packages") düzeltildi
 *  - getPackageInfo artık gerçekten gizliyor (NameNotFoundException fırlatıyor);
 *    eski kod sadece paketleri sorgulayıp logluyordu, hiç bir şey gizlemiyordu
 *  - SSLContext.init / HostnameVerifier / SystemProperties çift hook'ları tek le birleştirildi
 *  - Çok-overload'lu metotlarda overload'suz .implementation ataması (Runtime Error) düzeltildi
 *  - Java.enumerateLoadedClassesSync() çağrıları (çok pahalı) kaldırıldı
 *  - Her hook kendi try/catch'inde: biri patkayca diğerleri çalışmaya devam ediyor
 *  - "global.fridaStatus" (Frida'da tanımsız → ReferenceError) kaldırıldı
 *  - Etkisiz SSLPeerUnverifiedException mesaj-değiştirme hook'u kaldırıldı
 */

'use strict';

setTimeout(function () {
    if (!Java.available) {
        console.log("[!] Java API yok — bu script yalnızca Android içindir.");
        console.log("[!] iOS için: objection -g <bundle> explore -> ios sslpinning disable");
        return;
    }

    Java.perform(function () {
        console.log("[*] Android Bypass Suite v3.0 başlıyor...");

        // ====================================================================
        // CONFIG
        // ====================================================================

        const VERBOSE = false; // true yapınca her engellenen çağrı loglanır
        const dlog = function (m) { if (VERBOSE) console.log("[D] " + m); };

        const CONFIG = {
            enableSSLBypass: true,
            enableRootBypass: true,
            enableFridaBypass: true,
            enableBurpCheck: true
        };

        const SAFE_FINGERPRINT = "google/crosshatch/crosshatch:10/QQ3A.200805.001/6578210:user/release-keys";

        const ROOT_FILES = Array.from(new Set([
            "/data/local/bin/su", "/data/local/su", "/data/local/xbin/su",
            "/dev/com.koushikdutta.superuser.daemon/", "/sbin/su",
            "/system/app/Superuser.apk", "/system/bin/failsafe/su", "/system/bin/su",
            "/su/bin/su", "/system/etc/init.d/99SuperSUDaemon", "/system/sd/xbin/su",
            "/system/xbin/busybox", "/system/xbin/daemonsu", "/system/xbin/su",
            "/system/sbin/su", "/vendor/bin/su", "/cache/su", "/data/su", "/dev/su",
            "/system/bin/.ext/su", "/system/usr/we-need-root/su",
            "/system/app/Kinguser.apk", "/data/adb/magisk", "/sbin/.magisk",
            "/cache/.disable_magisk", "/dev/.magisk.unblock", "/cache/magisk.log",
            "/data/adb/magisk.img", "/data/adb/magisk.db", "/data/adb/magisk_simple",
            "/init.magisk.rc", "/system/xbin/ku.sud",
            "/data/adb/ksu", "/data/adb/ksud", "/data/adb/ksu.apk", "/data/adb/ksud.apk",
            "/data/adb/magisk.apk", "/data/adb/magisk_simple.apk"
        ]));

        const ROOT_PACKAGES = [
            "com.noshufou.android.su", "com.noshufou.android.su.elite",
            "eu.chainfire.supersu", "com.koushikdutta.superuser",
            "com.thirdparty.superuser", "com.yellowes.su",
            "com.koushikdutta.rommanager", "com.koushikdutta.rommanager.license",
            "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch",
            "com.ramdroid.appquarantine", "com.ramdroid.appquarantinepro",
            "com.topjohnwu.magisk", "me.weishu.kernelsu",
            "com.devadvance.rootcloak", "com.devadvance.rootcloakplus",
            "de.robv.android.xposed.installer", "com.saurik.substrate",
            "com.zachspong.temprootremovejb", "com.amphoras.hidemyroot",
            "com.amphoras.hidemyrootadfree", "com.formyhm.hiderootPremium",
            "com.formyhm.hideroot", "me.phh.superuser",
            "eu.chainfire.supersu.pro", "com.kingouser.com"
        ];

        // Yürütülebilir binary adları (komun ilk token'ı / which argümanı olarak)
        const ROOT_BINARIES = new Set([
            "su", "busybox", "daemonsu", "supersu",
            "magisk", "magisk64", "magiskhide", "magiskboot"
        ]);

        // SystemProperties.get için sahte değerler
        const ROOT_PROPERTIES = new Map([
            ["ro.build.selinux", "1"],
            ["ro.debuggable", "0"],
            ["service.adb.root", "0"],
            ["ro.secure", "1"],
            ["ro.build.tags", "release-keys"],
            ["ro.build.type", "user"]
        ]);

        const SENSITIVE_PROPS = new Set([
            "ro.secure", "ro.debuggable", "ro.build.fingerprint", "service.adb.root"
        ]);

        const FRIDA_STRINGS_RE = /frida|gum-js|gmain|linjector|gadget|cobalt/i;
        const MAPS_FILTER_RE = /frida|gum-js|gmain|linjector|gadget|cobalt|xposed|substrate|magisk/i;

        const reEscape = function (s) { return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); };
        const ROOT_FILES_RE = new RegExp(ROOT_FILES.map(reEscape).join("|"));
        const ROOT_PACKAGES_RE = new RegExp("^(?:" + ROOT_PACKAGES.map(reEscape).join("|") + ")$");

        const isRootPath = function (p) { return !!p && ROOT_FILES_RE.test(p); };
        const isRootPackage = function (p) { return !!p && ROOT_PACKAGES_RE.test(p); };

        // Token-bazlı komut engelleme ("/system/xbin/su" → "su"; "mkdir" artık yanlışlıkla engellenmez)
        function cmdBase(tok) {
            const i = tok.lastIndexOf("/");
            return (i === -1 ? tok : tok.substring(i + 1)).toLowerCase();
        }

        function shouldBlockExec(tokens) {
            if (!tokens || tokens.length === 0) return false;
            const t = tokens.map(function (x) { return cmdBase(String(x)); });
            const base = t[0];
            if (ROOT_BINARIES.has(base)) return true;
            if (base === "mount") return true;
            if (base === "getprop") return tokens.length > 1 && SENSITIVE_PROPS.has(String(tokens[1]));
            if (base === "which") {
                return tokens.length > 1 && (ROOT_BINARIES.has(cmdBase(String(tokens[1]))) || String(tokens[1]) === "su");
            }
            if (base === "pm" && (t[1] === "list" || t[1] === "path" || t[1] === "path-apk")) {
                for (let i = 2; i < tokens.length; i++) {
                    if (isRootPackage(String(tokens[i]))) return true;
                }
            }
            return false;
        }

        // Tek hook'un patlaması tüm süreci düşürmesin
        function tryHook(label, fn) {
            try {
                fn();
                return true;
            } catch (e) {
                const msg = (e && e.message) ? e.message : String(e);
                if (/ClassNotFound|ClassNotFoundException|not found/i.test(msg)) {
                    dlog(label + ": sınıf yok (normal)");
                } else {
                    console.log("[!] " + label + " hooklanamadı: " + msg);
                }
                return false;
            }
        }

        // Bir metodu TÜM overload'larıyla ele al; returnType void ise dönüş değeri yok sayılır
        function hookAll(clazz, methodName, valueFn, label) {
            const method = clazz[methodName];
            if (!method || !method.overloads) throw new Error(methodName + " bulunamadı");
            method.overloads.forEach(function (ov) {
                const isVoid = ov.returnType.name === "void";
                ov.implementation = function () {
                    const v = valueFn ? valueFn.call(this, arguments, ov) : undefined;
                    return isVoid ? undefined : v;
                };
            });
            dlog(label + ": " + method.overloads.length + " overload hook'landı");
        }

        // ====================================================================
        // 1) SSL / CERTIFICATE PINNING BYPASS
        // ====================================================================

        let TrustAllTM = null;
        let NullVerifier = null;

        function registerHelperClasses() {
            tryHook("TrustManager sınıfı", function () {
                TrustAllTM = Java.registerClass({
                    name: "com.pentest.TrustAllManager",
                    implements: [Java.use("javax.net.ssl.X509TrustManager")],
                    methods: {
                        checkClientTrusted: function () {},
                        checkServerTrusted: function () {},
                        getAcceptedIssuers: function () { return []; }
                    }
                });
            });
            tryHook("HostnameVerifier sınıfı", function () {
                NullVerifier = Java.registerClass({
                    name: "com.pentest.NullHostnameVerifier",
                    implements: [Java.use("javax.net.ssl.HostnameVerifier")],
                    methods: {
                        verify: function (hostname, session) {
                            dlog("Hostname verify bypass: " + hostname);
                            return true;
                        }
                    }
                });
            });
        }

        function setupSSLBypass() {
            if (!CONFIG.enableSSLBypass) return false;
            console.log("[+] SSL bypass kuruluyor...");
            registerHelperClasses();
            let ok = 0;

            // SSLContext.init — tek merkezî hook (v2'de iki ayrı yerde çakışıyordu)
            ok += tryHook("SSLContext.init", function () {
                const SSLContext = Java.use("javax.net.ssl.SSLContext");
                const initOv = SSLContext.init.overload(
                    "[Ljavax.net.ssl.KeyManager;",
                    "[Ljavax.net.ssl.TrustManager;",
                    "java.security.SecureRandom"
                );
                initOv.implementation = function (km, tm, sr) {
                    dlog("SSLContext.init → TrustAll");
                    return initOv.call(this, km, [TrustAllTM.$new()], sr);
                };
            }) ? 1 : 0;

            // HttpsURLConnection: app pinning factory/verifier kuramasın
            ok += tryHook("HttpsURLConnection", function () {
                const HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
                HttpsURLConnection.setSSLSocketFactory.implementation = function () { return; };
                HttpsURLConnection.setHostnameVerifier.implementation = function () { return; };
                HttpsURLConnection.setDefaultSSLSocketFactory.implementation = function () { return; };
                HttpsURLConnection.setDefaultHostnameVerifier.implementation = function () { return; };
                if (NullVerifier) {
                    HttpsURLConnection.setDefaultHostnameVerifier(NullVerifier.$new());
                }
            }) ? 1 : 0;

            // OkHttp 3.x ("check") + 4.x ("check$okhttp")
            ok += tryHook("OkHttp3 CertificatePinner", function () {
                hookAll(Java.use("okhttp3.CertificatePinner"), "check", null, "okhttp3.check");
            }) ? 1 : 0;
            ok += tryHook("OkHttp4 CertificatePinner", function () {
                hookAll(Java.use("okhttp3.CertificatePinner"), "check$okhttp", null, "okhttp3.check$okhttp");
            }) ? 1 : 0;

            // Conscrypt TrustManagerImpl (Android 7+)
            ok += tryHook("TrustManagerImpl", function () {
                const TM = Java.use("com.android.org.conscrypt.TrustManagerImpl");
                const ArrayList = Java.use("java.util.ArrayList");
                tryHook("checkTrustedRecursive", function () {
                    hookAll(TM, "checkTrustedRecursive", function () { return ArrayList.$new(); }, "checkTrustedRecursive");
                });
                tryHook("verifyChain", function () {
                    hookAll(TM, "verifyChain", function (args) { return args[0]; }, "verifyChain");
                });
            }) ? 1 : 0;

            // OpenSSL / BoringSSL varyantları
            ok += tryHook("OpenSSLSocketImpl (conscrypt)", function () {
                hookAll(Java.use("com.android.org.conscrypt.OpenSSLSocketImpl"),
                    "verifyCertificateChain", null, "OpenSSLSocketImpl");
            }) ? 1 : 0;
            ok += tryHook("OpenSSLEngineSocketImpl (conscrypt)", function () {
                hookAll(Java.use("com.android.org.conscrypt.OpenSSLEngineSocketImpl"),
                    "verifyCertificateChain", null, "OpenSSLEngineSocketImpl");
            }) ? 1 : 0;
            ok += tryHook("OpenSSLSocketImpl (harmony)", function () {
                hookAll(Java.use("org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl"),
                    "verifyCertificateChain", null, "OpenSSLSocketImplHarmony");
            }) ? 1 : 0;

            // WebView + Cordova
            ok += tryHook("WebViewClient.onReceivedSslError", function () {
                hookAll(Java.use("android.webkit.WebViewClient"), "onReceivedSslError",
                    function (args) { try { args[1].proceed(); } catch (e) {} return undefined; },
                    "WebViewClient");
            }) ? 1 : 0;
            ok += tryHook("Cordova WebViewClient", function () {
                hookAll(Java.use("org.apache.cordova.CordovaWebViewClient"), "onReceivedSslError",
                    function (args) { try { args[1].proceed(); } catch (e) {} return undefined; },
                    "CordovaWebViewClient");
            }) ? 1 : 0;

            // TrustKit — konfigürasyon driven
            ok += tryHook("TrustKit", function () {
                const targets = [
                    ["com.datatheorem.android.trustkit.pinning.OkHostnameVerifier", "verify", function () { return true; }],
                    ["com.datatheorem.android.trustkit.pinning.PinningTrustManager", "checkServerTrusted", null],
                    ["com.datatheorem.android.trustkit.reporting.BackgroundReporter", "reportCertificateError", null]
                ];
                let n = 0;
                targets.forEach(function (t) {
                    if (tryHook("TrustKit " + t[1], function () {
                        hookAll(Java.use(t[0]), t[1], t[2], "TrustKit");
                    })) n++;
                });
                console.log("[+] TrustKit: " + n + " bypass aktif");
            }) ? 1 : 0;

            // Diğer kütüphaneler
            ok += tryHook("PhoneGap sslCertificateChecker", function () {
                hookAll(Java.use("nl.xservices.plugins.sslCertificateChecker"), "execute",
                    function () { return true; }, "PhoneGap");
            }) ? 1 : 0;
            ok += tryHook("IBM MobileFirst", function () {
                const WLClient = Java.use("com.worklight.wlclient.api.WLClient");
                hookAll(WLClient, "pinTrustedCertificatePublicKey", null, "WLClient");
            }) ? 1 : 0;
            ok += tryHook("IBM WorkLight HostNameVerifier", function () {
                hookAll(Java.use("com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning"),
                    "verify", function () { return true; }, "WorkLight");
            }) ? 1 : 0;
            ok += tryHook("Appcelerator", function () {
                hookAll(Java.use("appcelerator.https.PinningTrustManager"),
                    "checkServerTrusted", null, "Appcelerator");
            }) ? 1 : 0;
            ok += tryHook("Appmattus CT Interceptor", function () {
                hookAll(Java.use("com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyInterceptor"),
                    "intercept",
                    function (args) { const c = args[0]; return c.proceed(c.request()); },
                    "CertTransInterceptor");
            }) ? 1 : 0;
            ok += tryHook("Appmattus CT TrustManager", function () {
                hookAll(Java.use("com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyTrustManager"),
                    "checkServerTrusted",
                    function () { return Java.use("java.util.ArrayList").$new(); },
                    "CertTransTrustManager");
            }) ? 1 : 0;
            ok += tryHook("Boye AbstractVerifier", function () {
                hookAll(Java.use("ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier"),
                    "verify", null, "Boye");
            }) ? 1 : 0;

            console.log("[+] SSL bypass tamam (" + ok + " modül)");
            return true;
        }

        // ====================================================================
        // 2) ROOT DETECTION BYPASS
        // ====================================================================

        function setupRootBypass() {
            if (!CONFIG.enableRootBypass) return false;
            console.log("[+] Root detection bypass kuruluyor...");
            let ok = 0;

            // Build prop'ları — her alan kendi try'ında (biri başarısızsa diğerleri yazılsın)
            ok += tryHook("Build props", function () {
                const Build = Java.use("android.os.Build");
                const props = {
                    PRODUCT: "gracerltexx", MANUFACTURER: "samsung", BRAND: "samsung",
                    DEVICE: "gracerlte", MODEL: "SM-N935F", HARDWARE: "samsungexynos8890",
                    FINGERPRINT: "samsung/gracerltexx/gracerlte:8.0.0/R16NW/N935FXXS4BRK2:user/release-keys",
                    BOARD: "universal8890", HOST: "SWHE", ID: "R16NW",
                    TYPE: "user", TAGS: "release-keys"
                };
                Object.keys(props).forEach(function (k) {
                    tryHook("Build." + k, function () { Build[k].value = props[k]; });
                });
            }) ? 1 : 0;

            // SystemProperties — tek birleşik hook (v2'de iki ayrı yerde, çakışan şekilde)
            ok += tryHook("SystemProperties.get(String)", function () {
                const SP = Java.use("android.os.SystemProperties");
                const getOv = SP.get.overload("java.lang.String");
                getOv.implementation = function (key) {
                    const k = String(key);
                    if (ROOT_PROPERTIES.has(k)) return ROOT_PROPERTIES.get(k);
                    if (/qemu|goldfish|sdk|generic|test-keys|magisk|xposed|substrate/i.test(k)) {
                        return k.indexOf("fingerprint") !== -1 ? SAFE_FINGERPRINT : "";
                    }
                    return getOv.call(this, key);
                };
                tryHook("SystemProperties.get(String,String)", function () {
                    const getOv2 = SP.get.overload("java.lang.String", "java.lang.String");
                    getOv2.implementation = function (key, def) {
                        const k = String(key);
                        if (ROOT_PROPERTIES.has(k)) return ROOT_PROPERTIES.get(k);
                        return getOv2.call(this, key, def);
                    };
                });
            }) ? 1 : 0;

            // GERÇEK paket gizleme — root paketi sorulursa NameNotFoundException fırlat
            ok += tryHook("PackageManager.getPackageInfo", function () {
                const PM = Java.use("android.app.ApplicationPackageManager");
                const NNF = Java.use("android.content.pm.PackageManager$NameNotFoundException");
                PM.getPackageInfo.overloads.forEach(function (ov) {
                    ov.implementation = function (name, flags) {
                        if (isRootPackage(String(name))) {
                            dlog("getPackageInfo gizlendi: " + name);
                            throw NNF.$new(name);
                        }
                        return ov.call(this, name, flags);
                    };
                });
            }) ? 1 : 0;

            // File.exists()/canRead() → UnixFileSystem.checkAccess
            ok += tryHook("UnixFileSystem.checkAccess", function () {
                const UFS = Java.use("java.io.UnixFileSystem");
                UFS.checkAccess.overloads.forEach(function (ov) {
                    ov.implementation = function () {
                        try {
                            const p = arguments[0].getAbsolutePath();
                            if (isRootPath(p)) { dlog("checkAccess engellendi: " + p); return false; }
                        } catch (e) {}
                        return ov.apply(this, arguments);
                    };
                });
            }) ? 1 : 0;

            // Runtime.exec — token-bazlı, gerçek orijinal overload ile devam
            ok += tryHook("Runtime.exec", function () {
                const Runtime = Java.use("java.lang.Runtime");
                const execStr = Runtime.exec.overload("java.lang.String");
                Runtime.exec.overloads.forEach(function (ov) {
                    ov.implementation = function () {
                        const tokens = [];
                        try {
                            const first = arguments[0];
                            if (first === null || first === undefined || typeof first === "string") {
                                tokens.push.apply(tokens, String(first).trim().split(/\s+/));
                            } else {
                                for (let i = 0; i < first.length; i++) tokens.push(String(first[i]));
                            }
                        } catch (e) {}
                        if (shouldBlockExec(tokens)) {
                            dlog("Runtime.exec engellendi: " + tokens.join(" "));
                            return execStr.call(this, "true");
                        }
                        return ov.apply(this, arguments);
                    };
                });
            }) ? 1 : 0;

            // ProcessBuilder.start — komut List olarak değiştirilir (v2 JS array'i List'e çeviremiyordu)
            ok += tryHook("ProcessBuilder.start", function () {
                const PB = Java.use("java.lang.ProcessBuilder");
                const startOv = PB.start.overload();
                startOv.implementation = function () {
                    try {
                        const list = this.command();
                        const it = list.iterator();
                        const tokens = [];
                        while (it.hasNext()) tokens.push(String(it.next()));
                        if (shouldBlockExec(tokens)) {
                            dlog("ProcessBuilder engellendi: " + tokens.join(" "));
                            const nl = Java.use("java.util.ArrayList").$new();
                            nl.add("true");
                            this.command(nl);
                        }
                    } catch (e) {}
                    return startOv.call(this);
                };
            }) ? 1 : 0;

            // ProcessImpl.start — pm list <rootpkg> argüman indeksi düzeltildi
            ok += tryHook("ProcessImpl.start", function () {
                const PI = Java.use("java.lang.ProcessImpl");
                const startOv = PI.start.overload(
                    "[Ljava.lang.String;", "java.util.Map",
                    "java.io.File", "[Ljava.lang.ProcessBuilder$Redirect;", "boolean"
                );
                startOv.implementation = function (cmdarray, env, dir, redirects, res) {
                    try {
                        const tokens = [];
                        for (let i = 0; i < cmdarray.length; i++) tokens.push(String(cmdarray[i]));
                        if (shouldBlockExec(tokens)) {
                            dlog("ProcessImpl engellendi: " + tokens.join(" "));
                            return startOv.call(this,
                                Java.array("java.lang.String", ["true"]), env, dir, redirects, res);
                        }
                    } catch (e) {}
                    return startOv.call(this, cmdarray, env, dir, redirects, res);
                };
            }) ? 1 : 0;

            // getprop çıktısı okuyan uygulamalar için
            ok += tryHook("BufferedReader.readLine", function () {
                const BR = Java.use("java.io.BufferedReader");
                const rl = BR.readLine.overload("boolean");
                rl.implementation = function () {
                    const text = rl.call(this);
                    if (text !== null && text.indexOf("ro.build.tags=test-keys") !== -1) {
                        return Java.use("java.lang.String").$new(
                            String(text).replace("ro.build.tags=test-keys", "ro.build.tags=release-keys"));
                    }
                    return text;
                };
            }) ? 1 : 0;

            // KeyInfo — enumerateLoadedClassesSync GEREKMEZ, Java.use yeter
            ok += tryHook("KeyInfo.isInsideSecureHardware", function () {
                Java.use("android.security.keystore.KeyInfo").isInsideSecureHardware.implementation =
                    function () { return true; };
            }) ? 1 : 0;

            console.log("[+] Root bypass tamam (" + ok + " modül)");
            return true;
        }

        // ====================================================================
        // 3) NATIVE HOOKS + /proc REDIRECT (frida & root)
        // ====================================================================

        function resolveExport(mod, name) {
            try { if (Module.getExportByName) return Module.getExportByName(mod, name); } catch (e) {}
            try { const a = Module.findExportByName(mod, name); if (a) return a; } catch (e2) {}
            return null;
        }

        const REDIRECTS = new Map(); // "/proc/<pid>/maps" -> fake dosya path pointer

        function bytesToString(u8) {
            let s = "";
            const CH = 0x8000;
            for (let i = 0; i < u8.length; i += CH) {
                s += String.fromCharCode.apply(null, u8.subarray(i, Math.min(i + CH, u8.length)));
            }
            return s;
        }

        function stringToBytes(s) {
            const u8 = new Uint8Array(s.length);
            for (let i = 0; i < s.length; i++) u8[i] = s.charCodeAt(i) & 0xff;
            return u8;
        }

        // /proc dosyaları lseek ile boyut vermez → fread döngüsü
        function readFileViaLibc(path) {
            const fopenP = resolveExport("libc.so", "fopen");
            const freadP = resolveExport("libc.so", "fread");
            const fcloseP = resolveExport("libc.so", "fclose");
            if (!fopenP || !freadP || !fcloseP) return null;
            const fopen = new NativeFunction(fopenP, "pointer", ["pointer", "pointer"]);
            const fread = new NativeFunction(freadP, "ulong", ["pointer", "ulong", "ulong", "pointer"]);
            const fclose = new NativeFunction(fcloseP, "int", ["pointer"]);
            const fh = fopen(Memory.allocUtf8String(path), Memory.allocUtf8String("r"));
            if (fh.isNull()) return null;
            const chunks = [];
            const buf = Memory.alloc(8192);
            try {
                for (;;) {
                    const r = fread(buf, 1, 8192, fh);
                    const n = (typeof r === "number") ? r : r.toNumber();
                    if (n <= 0) break;
                    chunks.push(buf.readByteArray(n));
                }
            } finally {
                fclose(fh);
            }
            let total = 0;
            chunks.forEach(function (c) { total += c.byteLength; });
            const out = new Uint8Array(total);
            let off = 0;
            chunks.forEach(function (c) { out.set(new Uint8Array(c), off); off += c.byteLength; });
            return out;
        }

        function writeBytesViaJava(path, u8) {
            try {
                const signed = [];
                for (let i = 0; i < u8.length; i++) {
                    let b = u8[i]; if (b > 127) b -= 256; signed.push(b);
                }
                const jstr = Java.use("java.lang.String").$new(Java.array("byte", signed), "UTF-8");
                const fos = Java.use("java.io.FileOutputStream").$new(path);
                try { fos.write(jstr.getBytes("UTF-8")); } finally { fos.close(); }
                return true;
            } catch (e) {
                dlog("fake dosya yazılamadı (" + path + "): " + e);
                return false;
            }
        }

        function registerRedirectFor(kind, fakePath) {
            const fakePtr = Memory.allocUtf8String(fakePath); // Map referansı canlı tutar
            ["self", String(Process.id)].forEach(function (pid) {
                REDIRECTS.set("/proc/" + pid + "/" + kind, fakePtr);
            });
            dlog("redirect: /proc/<pid>/" + kind + " -> " + fakePath);
        }

        function buildProcRedirects() {
            try {
                const app = Java.use("android.app.ActivityThread").currentApplication();
                const ctx = app ? app.getApplicationContext() : null;
                if (!ctx) {
                    console.log("[.] Context hazır değil — /proc redirect atlandı (spawn modunda normal)");
                    return;
                }
                const cacheDir = String(ctx.getCacheDir().getAbsolutePath());

                const maps = readFileViaLibc("/proc/self/maps");
                if (maps) {
                    const lines = bytesToString(maps).split("\n")
                        .filter(function (l) { return !MAPS_FILTER_RE.test(l); });
                    if (writeBytesViaJava(cacheDir + "/.c", stringToBytes(lines.join("\n")))) {
                        registerRedirectFor("maps", cacheDir + "/.c");
                    }
                }

                const status = readFileViaLibc("/proc/self/status");
                if (status) {
                    const clean = bytesToString(status)
                        .replace(/TracerPid:\s+\d+/g, "TracerPid:\t0");
                    if (writeBytesViaJava(cacheDir + "/.s", stringToBytes(clean))) {
                        registerRedirectFor("status", cacheDir + "/.s");
                    }
                }
            } catch (e) {
                console.log("[!] /proc redirect kurulamadı: " + e);
            }
        }

        function setupNativeHooks() {
            // --- fopen: /proc redirect + root dosya engelleme ---
            const fopenP = resolveExport("libc.so", "fopen");
            if (fopenP) {
                Interceptor.attach(fopenP, {
                    onEnter: function (args) {
                        this.path = null;
                        try {
                            const p = args[0].readUtf8String();
                            if (!p) return;
                            const fake = REDIRECTS.get(p);
                            if (fake) { args[0] = fake; return; }
                            this.path = p;
                        } catch (e) {}
                    },
                    onLeave: function (retval) {
                        if (this.path && !retval.isNull() && isRootPath(this.path)) {
                            dlog("fopen engellendi: " + this.path);
                            retval.replace(ptr(0));
                        }
                    }
                });
            }

            // --- open / openat: redirect + root engelleme ---
            [["libc.so", "open", 0], ["libc.so", "openat", 1]].forEach(function (spec) {
                const p = resolveExport(spec[0], spec[1]);
                if (!p) return;
                const idx = spec[2];
                Interceptor.attach(p, {
                    onEnter: function (args) {
                        this.path = null;
                        try {
                            const path = args[idx].readUtf8String();
                            if (!path) return;
                            const fake = REDIRECTS.get(path);
                            if (fake) { args[idx] = fake; return; }
                            this.path = path;
                        } catch (e) {}
                    },
                    onLeave: function (retval) {
                        if (this.path && retval.toInt32() !== -1 && isRootPath(this.path)) {
                            dlog(spec[1] + " engellendi: " + this.path);
                            retval.replace(-1);
                        }
                    }
                });
            });

            // --- access(): root dosya varlık kontrolü ---
            const accessP = resolveExport("libc.so", "access");
            if (accessP) {
                Interceptor.attach(accessP, {
                    onEnter: function (args) {
                        this.path = null;
                        try { this.path = args[0].readUtf8String(); } catch (e) {}
                    },
                    onLeave: function (retval) {
                        if (this.path && retval.toInt32() === 0 && isRootPath(this.path)) {
                            dlog("access engellendi: " + this.path);
                            retval.replace(-1);
                        }
                    }
                });
            }

            // --- __system_property_get: sahte değer + doğru dönüş uzunluğu ---
            const propGetP = resolveExport("libc.so", "__system_property_get");
            if (propGetP) {
                Interceptor.attach(propGetP, {
                    onEnter: function (args) {
                        this.key = null; this.buf = null;
                        try {
                            this.key = args[0].readCString();
                            this.buf = args[1];
                        } catch (e) {}
                    },
                    onLeave: function (retval) {
                        if (!this.key || !SENSITIVE_PROPS.has(this.key)) return;
                        const safe = this.key.indexOf("fingerprint") !== -1 ? SAFE_FINGERPRINT : "0";
                        const src = Memory.allocUtf8String(safe);
                        Memory.copy(this.buf, src, safe.length + 1);
                        retval.replace(safe.length);
                    }
                });
            }
        }

        // ====================================================================
        // 4) FRIDA DETECTION BYPASS
        // ====================================================================

        function setupFridaBypass() {
            if (!CONFIG.enableFridaBypass) return false;
            console.log("[+] Frida detection bypass kuruluyor...");
            let ok = 0;

            // ptrace → her zaman 0 (başarılı)
            const ptraceP = resolveExport("libc.so", "ptrace");
            if (ptraceP) {
                Interceptor.attach(ptraceP, {
                    onLeave: function (retval) { retval.replace(0); }
                });
                ok++;
            }

            // strstr: yalnızca NEEDLE frida-mı diye bakılır.
            // (v2 haystack'i de okuyordu: ikili veride readUtf8String patlayabilir
            //  ve alakasız "frida" geçen aramaları bozuyordu)
            const strstrP = resolveExport("libc.so", "strstr");
            if (strstrP) {
                Interceptor.attach(strstrP, {
                    onEnter: function (args) {
                        this.hit = false;
                        try {
                            const needle = args[1].readCString();
                            this.hit = needle !== null && FRIDA_STRINGS_RE.test(needle);
                        } catch (e) {}
                    },
                    onLeave: function (retval) {
                        if (this.hit) retval.replace(ptr(0));
                    }
                });
                ok++;
            }

            // connect(): bilinen frida portlarına bağlantıyı başarısız kıl.
            // DÜZELTME: sin_family 2 bayt (offset+1 tek bayt değil), port network
            // byte order'da (readU16 little-endian okur, hiçbir zaman eşleşmezdi)
            const connectP = resolveExport("libc.so", "connect");
            if (connectP) {
                const FRIDA_PORTS = new Set([27042, 27043, 23946, 27047]);
                Interceptor.attach(connectP, {
                    onEnter: function (args) {
                        this.block = false;
                        try {
                            const sa = args[1];
                            if (sa.isNull()) return;
                            if (sa.readU16() === 2) { // AF_INET
                                const port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
                                if (FRIDA_PORTS.has(port)) {
                                    dlog("connect engellendi, port: " + port);
                                    this.block = true;
                                }
                            }
                        } catch (e) {}
                    },
                    onLeave: function (retval) {
                        if (this.block) retval.replace(-1);
                    }
                });
                ok++;
            }

            // /proc redirect sayısı
            if (REDIRECTS.size > 0) ok++;

            console.log("[+] Frida bypass tamam (" + ok + " modül)");
            return true;
        }

        // ====================================================================
        // 5) BURP SERTİFİKA KONTROLÜ
        // ====================================================================

        function setupBurpCheck() {
            if (!CONFIG.enableBurpCheck) return false;
            console.log("[.] Burp sertifikası kontrol ediliyor...");

            const certPaths = [
                "/data/local/tmp/cert-der.crt",
                "/data/local/tmp/burp.der",
                "/data/local/tmp/burp.crt",
                "/data/local/tmp/cacert.der",
                "/data/local/tmp/cacert.crt"
            ];

            let found = null;
            let fis = null;
            for (let i = 0; i < certPaths.length; i++) {
                try {
                    fis = Java.use("java.io.FileInputStream").$new(certPaths[i]);
                    found = certPaths[i];
                    break;
                } catch (e) {}
            }

            if (!found) {
                console.log("[.] Burp sertifikası bulunamadı. Java katmanı zaten trust-all;");
                console.log("    native TLS için şu konumlardan birine push edin:");
                console.log("    " + certPaths.join(" | "));
                return false;
            }

            try {
                const cf = Java.use("java.security.cert.CertificateFactory").getInstance("X.509");
                const bis = Java.use("java.io.BufferedInputStream").$new(fis);
                const ca = cf.generateCertificate(bis);
                bis.close();
                console.log("[+] Burp CA bulundu (" + found + "): " +
                    Java.cast(ca, Java.use("java.security.cert.X509Certificate")).getSubjectDN());
            } catch (e) {
                try { fis.close(); } catch (e2) {}
                console.log("[!] Sertifika okunamadı: " + e);
                return false;
            }
            return true;
        }

        // ====================================================================
        // MAIN
        // ====================================================================

        try {
            // fake /proc dosyaları ÖNCE oluşturulur, sonra native hook'lar bağlanır
            if (CONFIG.enableFridaBypass) buildProcRedirects();

            const results = {
                ssl: setupSSLBypass(),
                root: setupRootBypass(),
                frida: (function () {
                    setupNativeHooks(); // root native hook'ları da burada bağlanır
                    return setupFridaBypass();
                })(),
                burp: setupBurpCheck()
            };

            console.log("\n[*] Durum: " + Object.keys(results).map(function (k) {
                return k + ": " + (results[k] ? "OK" : "-");
            }).join(", "));
        } catch (err) {
            console.error("[!] Kritik hata: " + (err && err.stack ? err.stack : err));
        }
    });
}, 0);

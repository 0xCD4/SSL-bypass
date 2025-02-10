setTimeout(function() {
    Java.perform(function() {
        console.log("[*] Starting SSL Bypass Suite");

        const bypassStatus = {
            ssl: false,
            root: false,
        };

        const ROOT_FILES = [
           "/data/local/bin/su",
           "/data/local/su",
           "/data/local/xbin/su",
           "/dev/com.koushikdutta.superuser.daemon/",
           "/sbin/su",
           "/system/app/Superuser.apk",
           "/system/bin/failsafe/su",
           "/system/bin/su",
           "/su/bin/su",
           "/system/etc/init.d/99SuperSUDaemon",
           "/system/sd/xbin/su",
           "/system/xbin/busybox",
           "/system/xbin/daemonsu",
           "/system/xbin/su",
           "/system/sbin/su",
           "/vendor/bin/su",
           "/cache/su",
           "/data/su",
           "/dev/su",
           "/system/bin/.ext/su",
           "/system/usr/we-need-root/su",
           "/system/app/Kinguser.apk",
           "/data/adb/magisk",
           "/sbin/.magisk",
           "/cache/.disable_magisk",
           "/dev/.magisk.unblock",
           "/cache/magisk.log",
           "/data/adb/magisk.img",
           "/data/adb/magisk.db",
           "/data/adb/magisk_simple",
           "/init.magisk.rc",
           "/system/xbin/ku.sud",
           "/data/adb/ksu",
           "/data/adb/ksud",
           "/data/adb/ksu.apk",
           "/data/adb/ksud.apk",
           "/data/adb/magisk.apk",
           "/data/adb/magisk_simple.apk",
           "/data/adb/magisk.img",
           "/data/adb/magisk.db",
           "/data/adb/zygisksu",
           "/data/adb/rezygisk",
           "/data/adb/modules",
        ];

        const ROOT_PACKAGES = [
            "com.noshufou.android.su",
            "com.noshufou.android.su.elite",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser",
            "com.yellowes.su",
            "com.koushikdutta.rommanager",
            "com.koushikdutta.rommanager.license",
            "com.dimonvideo.luckypatcher",
            "com.chelpus.lackypatch",
            "com.ramdroid.appquarantine",
            "com.ramdroid.appquarantinepro",
            "com.topjohnwu.magisk",
            "me.weishu.kernelsu",
            "com.devadvance.rootcloak",
            "com.devadvance.rootcloakplus",
            "de.robv.android.xposed.installer",
            "com.saurik.substrate",
            "com.zachspong.temprootremovejb",
            "com.amphoras.hidemyroot",
            "com.amphoras.hidemyrootadfree",
            "com.formyhm.hiderootPremium",
            "com.formyhm.hideroot",
            "me.phh.superuser",
            "eu.chainfire.supersu.pro",
            "com.kingouser.com",
            "catch.me.if.you.can.",
            "moe.shizuku.privileged.api",
            "org.lsposed.daemon",
            "org.lsposed.manager",
        ];

        const ROOT_BINARIES = new Set([
            "su", "busybox", "supersu", "Superuser.apk", "KingoUser.apk",
            "SuperSu.apk", "magisk", "magisk64", "magiskhide", "magiskboot"
        ]);

        const ROOT_PROPERTIES = new Map([
            ["ro.build.selinux", "1"],
            ["ro.debuggable", "0"],
            ["service.adb.root", "0"],
            ["ro.secure", "1"],
            ["ro.build.tags", "release-keys"],
            ["ro.build.type", "user"]
        ]);

        const SENSITIVE_PROPS = new Set([
            "ro.secure",
            "ro.debuggable",
            "ro.build.fingerprint",
            "service.adb.root"
        ]);

        const JavaClasses = {
            SSLContext: Java.use("javax.net.ssl.SSLContext"),
            Runtime: Java.use("java.lang.Runtime"),
            File: Java.use("java.io.File"),
            PackageManager: Java.use("android.app.ApplicationPackageManager"),
            ProcessBuilder: Java.use("java.lang.ProcessBuilder")
        };

        const LOG_LEVEL = {
            DEBUG: 0,
            INFO: 1,
            WARN: 2,
            ERROR: 3
        };

        const CURRENT_LOG_LEVEL = LOG_LEVEL.INFO;

        const CONFIG = {
            enableSSLBypass: true,
            enableRootBypass: true,
            enableDetailedLogs: false,
            blockAllRootCommands: true,
            allowedRootCommands: new Set(["getprop"]), // Whitelist certain commands
        };

        function log(level, message, error) {
            if (level >= CURRENT_LOG_LEVEL) {
                switch(level) {
                    case LOG_LEVEL.DEBUG:
                        console.log("[D] " + message);
                        break;
                    case LOG_LEVEL.INFO:
                        console.log("[*] " + message);
                        break;
                    case LOG_LEVEL.WARN:
                        console.log("[!] " + message);
                        break;
                    case LOG_LEVEL.ERROR:
                        console.error("[E] " + message);
                        if (error) console.error(error.stack || error);
                        break;
                }
            }
        }

        function setupSSLBypass() {
            console.log("[+] Setting up SSL bypass...");
            try {
                bypassCertificateValidation();
                bypassOkHttp();
                bypassTrustKit();
                bypassWebViewClient();
                bypassCertificatePinning();
                
                bypassStatus.ssl = true;
                return true;
            } catch(e) {
                console.log("[-] SSL Bypass failed:", e);
                return false;
            }
        }

        function bypassCertificateValidation() {
            try {
                const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
                const CustomTrustManager = Java.registerClass({
                    name: "com.custom.TrustManager",
                    implements: [X509TrustManager],
                    methods: {
                        checkClientTrusted: function() {},
                        checkServerTrusted: function() {},
                        getAcceptedIssuers: function() { return []; }
                    }
                });

                const SSLContext_init = JavaClasses.SSLContext.init.overload(
                    "[Ljavax.net.ssl.KeyManager;", 
                    "[Ljavax.net.ssl.TrustManager;", 
                    "java.security.SecureRandom"
                );

                SSLContext_init.implementation = function(keyManager, trustManager, secureRandom) {
                    SSLContext_init.call(this, keyManager, [CustomTrustManager.$new()], secureRandom);
                };
            } catch(e) {
                console.log("[-] Certificate validation bypass failed");
            }
        }

        function bypassOkHttp() {
            try {
                const CertificatePinner = Java.use("okhttp3.CertificatePinner");
                
                CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, certificates) {
                    return;
                };

                CertificatePinner.check$okhttp.implementation = function(hostname, certificates) {
                    return;
                };
            } catch(e) {
                console.log("[-] OkHttp bypass failed:", e);
            }
        }

        function bypassTrustKit() {
            console.log("[*] Setting up TrustKit bypass...");
            let bypassCount = 0;

            // Helper function to handle TrustKit class hooks
            const hookTrustKitClass = (className, methodName, overloadTypes = null) => {
                try {
                    const targetClass = Java.use(className);
                    const method = overloadTypes ? 
                        targetClass[methodName].overload(...overloadTypes) :
                        targetClass[methodName];

                    method.implementation = function(...args) {
                        const hostname = args[0] || "unknown";
                        console.log(`[+] Bypassing ${className}.${methodName} for: ${hostname}`);
                        return methodName.includes("verify") ? true : undefined;
                    };
                    bypassCount++;
                    return true;
                } catch(e) {
                    if (!e.toString().includes("ClassNotFoundException")) {
                        console.log(`[-] Failed to hook ${className}.${methodName}:`, e);
                    }
                    return false;
                }
            };

            // TrustKit hostname verifier bypasses
            hookTrustKitClass(
                "com.datatheorem.android.trustkit.pinning.OkHostnameVerifier",
                "verify", 
                ["java.lang.String", "javax.net.ssl.SSLSession"]
            );

            hookTrustKitClass(
                "com.datatheorem.android.trustkit.pinning.OkHostnameVerifier",
                "verify",
                ["java.lang.String", "java.security.cert.X509Certificate"]
            );

            // TrustKit certificate pinning bypass
            hookTrustKitClass(
                "com.datatheorem.android.trustkit.pinning.PinningTrustManager",
                "checkServerTrusted"
            );

            // Additional TrustKit bypasses
            hookTrustKitClass(
                "com.datatheorem.android.trustkit.TrustKit",
                "initializeWithNetworkSecurityConfiguration"
            );

            hookTrustKitClass(
                "com.datatheorem.android.trustkit.reporting.BackgroundReporter",
                "reportCertificateError"
            );

            if (bypassCount > 0) {
                console.log(`[+] Successfully set up ${bypassCount} TrustKit bypasses`);
            } else {
                console.log("[*] TrustKit not found in app (this is normal)");
            }
        }

        function bypassWebViewClient() {
            try {
                const WebViewClient = Java.use("android.webkit.WebViewClient");
                
                WebViewClient.onReceivedSslError.overload(
                    "android.webkit.WebView",
                    "android.webkit.SslErrorHandler",
                    "android.net.http.SslError"
                ).implementation = function(webView, handler, error) {
                    handler.proceed();
                };
            } catch(e) {
                console.log("[-] WebViewClient bypass failed:", e);
            }
        }

        function bypassCertificatePinning() {
            try {
                const UnverifiedCertError = Java.use("javax.net.ssl.SSLPeerUnverifiedException");
                UnverifiedCertError.$init.implementation = function(message) {
                    try {
                        const stackTrace = Java.use("java.lang.Thread").currentThread().getStackTrace();
                        const exceptionStack = stackTrace.findIndex(stack => 
                            stack.getClassName() === "javax.net.ssl.SSLPeerUnverifiedException"
                        );
                        
                        if (exceptionStack >= 0) {
                            const callingStack = stackTrace[exceptionStack + 1];
                            const className = callingStack.getClassName();
                            const methodName = callingStack.getMethodName();
                            
                            return this.$init("SSL verification bypassed");
                        }
                    } catch(e) {
                        console.log("[-] Stack trace analysis failed:", e);
                    }
                    
                    return this.$init(message);
                };
            } catch(e) {
                console.log("[-] Certificate pinning bypass failed:", e);
            }
        }

        // *** NEW FUNCTION ADDED TO FIX ROOT BYPASS FAILURE ***
        function bypassBuildProps() {
            try {
                const Build = Java.use("android.os.Build");
                Build.PRODUCT.value = "gracerltexx";
                Build.MANUFACTURER.value = "samsung";
                Build.BRAND.value = "samsung";
                Build.DEVICE.value = "gracerlte";
                Build.MODEL.value = "SM-N935F";
                Build.HARDWARE.value = "samsungexynos8890";
                Build.FINGERPRINT.value = "samsung/gracerltexx/gracerlte:8.0.0/R16NW/N935FXXS4BRK2:user/release-keys";
                Build.BOARD.value = "universal8890";
                Build.HOST.value = "SWHE";
                Build.ID.value = "R16NW";
                Build.TYPE.value = "user";
                Build.TAGS.value = "release-keys";
                
                Java.use("android.os.SystemProperties").get.overload('java.lang.String').implementation = function(key) {
                    if (key.includes("qemu") || key.includes("goldfish") || key.includes("sdk") || key.includes("generic")) {
                        return "";
                    }
                    return this.get(key);
                };
            } catch (e) {
                console.log("[-] Build properties hook failed:", e);
            }
        }

        function setupRootBypass() {
            console.log("[+] Initializing Enhanced Root Detection Bypass...");
            try {
                // Wrap package manager check in a try-catch
                try {
                    const currentApplication = Java.use("android.app.ActivityThread").currentApplication();
                    if (currentApplication) {
                        const context = currentApplication.getApplicationContext();
                        if (context) {
                            const pm = context.getPackageManager();
                            if (pm) {
                                ROOT_PACKAGES.forEach(pkg => {
                                    try {
                                        pm.getPackageInfo(pkg, 0);
                                        log(LOG_LEVEL.DEBUG, `Found root package: ${pkg}`);
                                    } catch(e) {
                                        // Package not found - good
                                    }
                                });
                            }
                        }
                    }
                } catch(e) {
                    console.log("[-] Package manager check failed - app context not ready");
                }

                // Continue with other bypasses even if package manager check fails
                bypassNativeFileOperations();
                bypassBuildProps();  // <-- Now defined!
                bypassShellCommands();
                bypassRuntimeExec();
                enhancedFileBypass();
                bypassSystemProperties();
                bypassProcessBuilder();
                bypassBufferedReader();
                bypassSecureHardware();
                
                bypassStatus.root = true;
                return true;
            } catch(e) {
                console.error("[!] Root Bypass Error:", e);
                return false;
            }
        }

        function bypassNativeFileOperations() {
            try {
                const fopen = Module.findExportByName("libc.so", "fopen");
                if (fopen) {
                    Interceptor.attach(fopen, {
                        onEnter(args) {
                            this.filePath = args[0].readUtf8String();
                        },
                        onLeave(retval) {
                            if (retval.toInt32() !== 0 && ROOT_FILES.some(path => this.filePath.includes(path))) {
                                retval.replace(ptr(0x0));
                            }
                        }
                    });
                }

                const access = Module.findExportByName("libc.so", "access");
                if (access) {
                    Interceptor.attach(access, {
                        onEnter(args) {
                            this.filePath = args[0].readUtf8String();
                        },
                        onLeave(retval) {
                            if (retval.toInt32() === 0 && ROOT_FILES.some(path => this.filePath.includes(path))) {
                                retval.replace(ptr(-1));
                            }
                        }
                    });
                }

                const sysPropGet = Module.findExportByName("libc.so", "__system_property_get");
                if (sysPropGet) {
                    Interceptor.attach(sysPropGet, {
                        onEnter(args) {
                            this.key = args[0].readCString();
                            this.ret = args[1];
                        },
                        onLeave(retval) {
                            if (SENSITIVE_PROPS.has(this.key)) {
                                const safeValue = this.key.includes("fingerprint") ? 
                                    "google/crosshatch/crosshatch:10/QQ3A.200805.001/6578210:user/release-keys" : "0";
                                const ptrSafe = Memory.allocUtf8String(safeValue);
                                Memory.copy(this.ret, ptrSafe, safeValue.length + 1);
                            }
                        }
                    });
                }
            } catch (e) {
                console.log("[-] Native hooks partial failure:", e);
            }
        }

        function enhancedFileBypass() {
            try {
                const UnixFileSystem = Java.use("java.io.UnixFileSystem");
                UnixFileSystem.checkAccess.implementation = function(file, access) {
                    const filename = file.getAbsolutePath();
                    if (ROOT_FILES.some(path => filename.includes(path))) {
                        return false;
                    }
                    return this.checkAccess(file, access);
                };
            } catch (e) {
                console.log("[-] UnixFileSystem hook failed:", e);
            }
        }

        function bypassShellCommands() {
            try {
                const ProcessImpl = Java.use("java.lang.ProcessImpl");
                ProcessImpl.start.implementation = function(cmdarray, env, dir, redirects, redirectErrorStream) {
                    const cmd = cmdarray[0].toString();
                    const arg = cmdarray.length > 1 ? cmdarray[1].toString() : "";
                    
                    // Add package check
                    if (cmd === "pm" && arg === "list" && cmdarray.length > 2) {
                        if (ROOT_PACKAGES.some(pkg => cmdarray[2].toString().includes(pkg))) {
                            cmdarray[0] = Java.use("java.lang.String").$new("");
                        }
                    }
                    
                    if ((cmd === "mount") || 
                        (cmd === "getprop" && SENSITIVE_PROPS.has(arg)) ||
                        (cmd.includes("which") && arg === "su")) {
                        cmdarray[0] = Java.use("java.lang.String").$new("");
                    }
                    
                    return this.start.call(this, cmdarray, env, dir, redirects, redirectErrorStream);
                };
            } catch (e) {
                console.log("[-] Shell command hook failed:", e);
            }
        }

        function bypassRuntimeExec() {
            try {
                const Runtime = Java.use("java.lang.Runtime");
                
                function shouldBlockCommand(cmd) {
                    cmd = cmd.toLowerCase();
                    return ROOT_BINARIES.has(cmd) || 
                           ROOT_PACKAGES.some(pkg => cmd.includes(pkg.toLowerCase())) ||
                           ["getprop", "mount", "build.prop", "id", "sh", "su", "which"].some(
                               blocked => cmd.includes(blocked)
                           );
                }

                const execOverloads = [
                    ["[Ljava.lang.String;"],
                    ["java.lang.String"],
                    ["java.lang.String", "[Ljava.lang.String;"],
                    ["[Ljava.lang.String;", "[Ljava.lang.String;"],
                    ["[Ljava.lang.String;", "[Ljava.lang.String;", "java.io.File"],
                    ["java.lang.String", "[Ljava.lang.String;", "java.io.File"]
                ];

                execOverloads.forEach(overload => {
                    Runtime.exec.overload(...overload).implementation = function() {
                        let cmd = arguments[0];
                        if (Array.isArray(cmd)) {
                            cmd = cmd[0];
                        }
                        
                        if (shouldBlockCommand(cmd.toString())) {
                            return this.exec.call(this, "echo");
                        }
                        return this.exec.apply(this, arguments);
                    };
                });
            } catch(e) {
                console.log("[-] Runtime.exec hooks failed:", e);
            }
        }

        function bypassSystemProperties() {
            try {
                const SystemProperties = Java.use("android.os.SystemProperties");
                
                SystemProperties.get.overload('java.lang.String').implementation = function(key) {
                    if (ROOT_PROPERTIES.has(key)) {
                        return ROOT_PROPERTIES.get(key);
                    }
                    if (key.includes("qemu") || key.includes("goldfish") || key.includes("sdk")) {
                        return "";
                    }
                    return this.get(key);
                };
            } catch(e) {
                console.log("[-] System properties hook failed:", e);
            }
        }

        function bypassBufferedReader() {
            try {
                Java.use("java.io.BufferedReader").readLine.overload("boolean").implementation = function() {
                    const text = this.readLine.overload("boolean").call(this);
                    if (text && text.indexOf("ro.build.tags=test-keys") > -1) {
                        return text.replace("ro.build.tags=test-keys", "ro.build.tags=release-keys");
                    }
                    return text;
                };
            } catch(e) {
                console.log("[-] BufferedReader hook failed:", e);
            }
        }

        function bypassProcessBuilder() {
            try {
                const blockedCommands = new Set(["getprop", "mount", "build.prop", "id", "su"]);
                
                JavaClasses.ProcessBuilder.start.implementation = function() {
                    const cmd = this.command.call(this);
                    
                    const hasBlockedCmd = Array.from(cmd).some(c => 
                        blockedCommands.has(c.toString()) || 
                        Array.from(blockedCommands).some(blocked => c.toString().includes(blocked))
                    );

                    if (hasBlockedCmd) {
                        this.command.call(this, ["echo"]);
                        return this.start.call(this);
                    }

                    return this.start.call(this);
                };

                Java.perform(function() {
                    try {
                        if (Java.available) {
                            const loadedClasses = Java.enumerateLoadedClassesSync();
                            if (loadedClasses.includes("java.lang.ProcessManager")) {
                                const ProcessManager = Java.use("java.lang.ProcessManager");
                                bypassProcessManager();
                            }
                        }
                    } catch(e) {
                        console.log("[-] ProcessManager not available");
                    }
                });

            } catch(e) {
                console.log("[-] ProcessBuilder hook failed:", e);
            }
        }

        function bypassProcessManager() {
            if (!JavaClasses.ProcessManager) return;

            try {
                const variants = [
                    {
                        params: ["[Ljava.lang.String;", "[Ljava.lang.String;", "java.io.File", "boolean"],
                        method: "exec"
                    },
                    {
                        params: ["[Ljava.lang.String;", "[Ljava.lang.String;", "java.lang.String", 
                                "java.io.FileDescriptor", "java.io.FileDescriptor", 
                                "java.io.FileDescriptor", "boolean"],
                        method: "exec"
                    }
                ];

                variants.forEach(variant => {
                    if (JavaClasses.ProcessManager[variant.method]) {
                        JavaClasses.ProcessManager[variant.method].overload(...variant.params)
                        .implementation = function() {
                            const cmd = arguments[0];
                            if (Array.isArray(cmd) && cmd.some(c => 
                                c.indexOf("getprop") !== -1 || 
                                c === "mount" || 
                                c.indexOf("build.prop") !== -1 || 
                                c === "id" || 
                                c === "su")) {
                                arguments[0] = ["echo"];
                            }
                            return this[variant.method].apply(this, arguments);
                        };
                    }
                });
            } catch(e) {
                console.log("[-] ProcessManager hooks failed:", e);
            }
        }

        function bypassSecureHardware() {
            Java.perform(function() {
                try {
                    if (Java.available) {
                        const loadedClasses = Java.enumerateLoadedClassesSync();
                        if (loadedClasses.includes("android.security.keystore.KeyInfo")) {
                            const KeyInfo = Java.use("android.security.keystore.KeyInfo");
                            KeyInfo.isInsideSecureHardware.implementation = function() {
                                return true;
                            };
                        }
                    }
                } catch(e) {
                    console.log("[-] SecureHardware hook not available");
                }
            });
        }

        function setupBurpInterceptor() {
            console.log("");
            console.log("[.] Setting up Burp Certificate Interceptor");

            try {
                const CertificateFactory = Java.use("java.security.cert.CertificateFactory");
                const FileInputStream = Java.use("java.io.FileInputStream");
                const BufferedInputStream = Java.use("java.io.BufferedInputStream");
                const X509Certificate = Java.use("java.security.cert.X509Certificate");
                const KeyStore = Java.use("java.security.KeyStore");
                const TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");
                const SSLContext = Java.use("javax.net.ssl.SSLContext");

                // Try multiple certificate file paths
                const certPaths = [
                    "/data/local/tmp/cert-der.crt",
                    "/data/local/tmp/burp.der",
                    "/data/local/tmp/burp.crt",
                    "/data/local/tmp/cacert.der",
                    "/data/local/tmp/cacert.crt"
                ];

                let fileInputStream = null;
                let certPath = null;

                // Try each certificate path
                for (const path of certPaths) {
                    try {
                        fileInputStream = FileInputStream.$new(path);
                        certPath = path;
                        console.log("[+] Found certificate at: " + path);
                        break;
                    } catch(err) {
                        console.log("[o] Certificate not found at: " + path);
                    }
                }

                if (!fileInputStream) {
                    console.log("[-] No certificate found. Please push the Burp certificate to one of these locations:");
                    console.log(certPaths.join("\n"));
                    return false;
                }

                console.log("[+] Loading Burp CA from: " + certPath);
                const cf = CertificateFactory.getInstance("X.509");
                const bufferedInputStream = BufferedInputStream.$new(fileInputStream);
                const ca = cf.generateCertificate(bufferedInputStream);
                bufferedInputStream.close();

                const certInfo = Java.cast(ca, X509Certificate);
                console.log("[o] Burp CA Info: " + certInfo.getSubjectDN());

                // Create a KeyStore containing our trusted CAs
                console.log("[+] Creating KeyStore for Burp CA...");
                const keyStoreType = KeyStore.getDefaultType();
                const keyStore = KeyStore.getInstance(keyStoreType);
                keyStore.load(null, null);
                keyStore.setCertificateEntry("ca", ca);
                
                // Create a TrustManager that trusts the CAs in our KeyStore
                console.log("[+] Creating TrustManager for Burp CA...");
                const tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
                const tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
                tmf.init(keyStore);
                console.log("[+] TrustManager ready");

                // Force accept all hostnames
                const NullHostnameVerifier = Java.registerClass({
                    name: 'org.webkit.android.NullHostnameVerifier',
                    implements: [Java.use('javax.net.ssl.HostnameVerifier')],
                    methods: {
                        verify: function (hostname, session) {
                            console.log('[+] Bypassing hostname verification: ' + hostname);
                            return true;
                        }
                    }
                });

                // Prepare the custom TrustManager
                const TrustAllCerts = Java.registerClass({
                    name: 'org.webkit.android.TrustAllCerts',
                    implements: [Java.use('javax.net.ssl.X509TrustManager')],
                    methods: {
                        checkClientTrusted: function(chain, authType) {},
                        checkServerTrusted: function(chain, authType) {},
                        getAcceptedIssuers: function() { return []; }
                    }
                });

                console.log("[+] Setting up SSL context and hostname verifier...");
                
                // Override SSL context
                SSLContext.init.overload(
                    "[Ljavax.net.ssl.KeyManager;", 
                    "[Ljavax.net.ssl.TrustManager;", 
                    "java.security.SecureRandom"
                ).implementation = function(keyManager, trustManager, secureRandom) {
                    console.log("[+] Intercepting SSLContext.init...");
                    SSLContext.init.overload(
                        "[Ljavax.net.ssl.KeyManager;", 
                        "[Ljavax.net.ssl.TrustManager;", 
                        "java.security.SecureRandom"
                    ).call(this, keyManager, [TrustAllCerts.$new()], secureRandom);
                    console.log("[+] Custom TrustManager installed");
                };

                // Set hostname verifier
                const HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
                HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(hostnameVerifier) {
                    console.log("[+] Setting NullHostnameVerifier...");
                    return this.setDefaultHostnameVerifier(NullHostnameVerifier.$new());
                };

                console.log("[+] Burp certificate installation completed");
                return true;
            } catch(e) {
                console.log("[-] Burp certificate setup failed:", e);
                return false;
            }
        }

        function hookFrida() {
            try {
                console.log("[*] Setting up Frida detection bypasses...");
                let bypassSuccess = true;

                // Ptrace bypass
                try {
                    const ptracePtr = Module.findExportByName("libc.so", "ptrace");
                    if (ptracePtr) {
                        Interceptor.attach(ptracePtr, {
                            onEnter(args) {
                                this.returnSuccess = true;
                            },
                            onLeave(retval) {
                                if (this.returnSuccess) {
                                    retval.replace(0);  // Success return value
                                }
                            }
                        });
                        console.log("[+] Ptrace bypass installed");
                    }
                } catch(e) {
                    console.log("[-] Ptrace bypass failed:", e);
                    bypassSuccess = false;
                }

                // Process name detection bypass
                try {
                    const openPtr = Module.findExportByName("libc.so", "open");
                    if (openPtr) {
                        Interceptor.attach(openPtr, {
                            onEnter(args) {
                                const path = args[0].readUtf8String();
                                if (path.includes("/proc/") && path.includes("/maps")) {
                                    this.shouldModify = true;
                                }
                            },
                            onLeave(retval) {
                                if (this.shouldModify && retval != -1) {
                                    // Filter out Frida-related memory maps
                                    const sensitivePatterns = [
                                        "frida",
                                        "gum-js-loop",
                                        "gmain",
                                        "linjector",
                                        "frida-agent",
                                        "frida-helper",
                                        "magisk",
                                        "xposed",
                                        "substrate"
                                    ];

                                    const fd = retval.toInt32();
                                    const originalMap = new File(fd, "r").readAll().toString();
                                    
                                    // Filter out lines containing sensitive patterns
                                    const filteredMap = originalMap.split('\n')
                                        .filter(line => !sensitivePatterns.some(pattern => 
                                            line.toLowerCase().includes(pattern)))
                                            .join('\n');

                                    // Replace the original file descriptor with filtered content
                                    new File(fd, "w").write(filteredMap);
                                }
                            }
                        });
                        console.log("[+] Process maps bypass installed");
                    }
                } catch(e) {
                    console.log("[-] Process maps bypass failed:", e);
                    bypassSuccess = false;
                }

                // String pattern detection bypass
                try {
                    const patterns = ["frida", "gum-js-loop", "gmain", "linjector"];
                    const strstr = Module.findExportByName("libc.so", "strstr");
                    if (strstr) {
                        Interceptor.attach(strstr, {
                            onEnter(args) {
                                const haystack = args[0].readUtf8String();
                                const needle = args[1].readUtf8String();
                                if (patterns.some(pattern => 
                                    needle.toLowerCase().includes(pattern) || 
                                    haystack.toLowerCase().includes(pattern))) {
                                    this.shouldModify = true;
                                }
                            },
                            onLeave(retval) {
                                if (this.shouldModify) {
                                    retval.replace(ptr(0));  // Return null for matches
                                }
                            }
                        });
                        console.log("[+] String pattern bypass installed");
                    }
                } catch(e) {
                    console.log("[-] String pattern bypass failed:", e);
                    bypassSuccess = false;
                }

                // Port scanning detection bypass
                try {
                    const connect = Module.findExportByName("libc.so", "connect");
                    if (connect) {
                        Interceptor.attach(connect, {
                            onEnter(args) {
                                const sockAddr = args[1];
                                if (sockAddr) {
                                    const sa_family = sockAddr.add(1).readU8();
                                    if (sa_family === 2) { // AF_INET
                                        const port = sockAddr.add(2).readU16();
                                        // Known Frida ports
                                        const suspiciousPorts = new Set([
                                            27042, // Default Frida
                                            27043, // Frida
                                            23946, // Frida server
                                            27047  // Frida helper
                                        ]);

                                        if (suspiciousPorts.has(port)) {
                                            console.log(`[!] Blocked connection to suspicious port: ${port}`);
                                            this.shouldBlock = true;
                                        }
                                    }
                                }
                            },
                            onLeave(retval) {
                                if (this.shouldBlock) {
                                    retval.replace(-1); // Connection failed
                                }
                            }
                        });
                        console.log("[+] Port scanning bypass installed");
                    }
                } catch(e) {
                    console.log("[-] Port scanning bypass failed:", e);
                    bypassSuccess = false;
                }

                global.fridaStatus = bypassSuccess;
                return bypassSuccess;

            } catch(e) {
                console.log("[-] Fatal error in Frida bypass:", e);
                global.fridaStatus = false;
                return false;
            }
        }

        function setupBypass() {
            try {
                const results = {
                    ssl: setupSSLBypass(),
                    root: setupRootBypass(),
                    burp: setupBurpInterceptor(),
                    frida: hookFrida()
                };
                
                if (CONFIG.enableDetailedLogs) {
                    log(LOG_LEVEL.DEBUG, "Detailed bypass results:", results);
                }

                return results;
            } catch(e) {
                log(LOG_LEVEL.ERROR, "Bypass setup failed", e);
                return {};
            }
        }

        try {
            const results = setupBypass();

            // Add detailed error reporting
            Object.entries(results).forEach(([type, success]) => {
                if (!success) {
                    console.log(`[-] ${type.toUpperCase()} bypass failed`);
                }
            });

            console.log("\n[*] Status:", Object.entries(results)
                .map(([k, v]) => `${k}: ${v ? "✓" : "✗"}`)
                .join(", "));

        } catch(err) {
            console.error("[!] Critical Error:", err.stack || err);
        }

        // Continue HttpsURLConnection bypasses
        try {
            const HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
            HttpsURLConnection.setSSLSocketFactory.implementation = function(
                SSLSocketFactory
            ) {
                console.log("  --> Bypassing HttpsURLConnection (setSSLSocketFactory)");
                return;
            };
            console.log("[+] HttpsURLConnection (setSSLSocketFactory)");
        } catch (err) {
            console.log("[ ] HttpsURLConnection (setSSLSocketFactory)");
        }

        try {
            const HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
            HttpsURLConnection.setHostnameVerifier.implementation = function(
                hostnameVerifier
            ) {
                console.log("  --> Bypassing HttpsURLConnection (setHostnameVerifier)");
                return;
            };
            console.log("[+] HttpsURLConnection (setHostnameVerifier)");
        } catch (err) {
            console.log("[ ] HttpsURLConnection (setHostnameVerifier)");
        }

        // SSLContext bypass
        try {
            const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
            const SSLContext = Java.use("javax.net.ssl.SSLContext");

            const TrustManager = Java.registerClass({
                name: "dev.asd.test.TrustManager",
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function(chain, authType) {},
                    checkServerTrusted: function(chain, authType) {},
                    getAcceptedIssuers: function() {
                        return [];
                    },
                },
            });

            const TrustManagers = [TrustManager.$new()];
            const SSLContext_init = SSLContext.init.overload(
                "[Ljavax.net.ssl.KeyManager;",
                "[Ljavax.net.ssl.TrustManager;",
                "java.security.SecureRandom"
            );

            SSLContext_init.implementation = function(
                keyManager,
                trustManager,
                secureRandom
            ) {
                console.log("  --> Bypassing Trustmanager (Android < 7) request");
                SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
            };
            console.log("[+] SSLContext");
        } catch (err) {
            console.log("[ ] SSLContext");
        }

        // TrustManagerImpl (Android > 7)
        try {
            const array_list = Java.use("java.util.ArrayList");
            const TrustManagerImpl = Java.use(
                "com.android.org.conscrypt.TrustManagerImpl"
            );

            TrustManagerImpl.checkTrustedRecursive.implementation = function(
                a1, a2, a3, a4, a5, a6
            ) {
                console.log("  --> Bypassing TrustManagerImpl checkTrusted ");
                return array_list.$new();
            };

            TrustManagerImpl.verifyChain.implementation = function(
                untrustedChain,
                trustAnchorChain,
                host,
                clientAuth,
                ocspData,
                tlsSctData
            ) {
                console.log("  --> Bypassing TrustManagerImpl verifyChain: " + host);
                return untrustedChain;
            };
            console.log("[+] TrustManagerImpl");
        } catch (err) {
            console.log("[ ] TrustManagerImpl");
        }

        // OkHTTPv3 bypasses
        try {
            const okhttp3_Activity_1 = Java.use("okhttp3.CertificatePinner");
            okhttp3_Activity_1.check.overload(
                "java.lang.String",
                "java.util.List"
            ).implementation = function(a, b) {
                console.log("  --> Bypassing OkHTTPv3 (list): " + a);
                return;
            };
            console.log("[+] OkHTTPv3 (list)");
        } catch (err) {
            console.log("[ ] OkHTTPv3 (list)");
        }

        // Trustkit bypasses
        try {
            // Bypass Trustkit {1}
            const trustkit_Activity_1 = Java.use(
                "com.datatheorem.android.trustkit.pinning.OkHostnameVerifier"
            );
            trustkit_Activity_1.verify.overload(
                "java.lang.String",
                "javax.net.ssl.SSLSession"
            ).implementation = function(a, b) {
                console.log(
                    "  --> Bypassing Trustkit OkHostnameVerifier(SSLSession): " + a
                );
                return true;
            };
            console.log("[+] Trustkit OkHostnameVerifier(SSLSession)");
        } catch (err) {
            console.log("[ ] Trustkit OkHostnameVerifier(SSLSession)");
        }

        try {
            // Bypass Trustkit {2}
            const trustkit_Activity_2 = Java.use(
                "com.datatheorem.android.trustkit.pinning.OkHostnameVerifier"
            );
            trustkit_Activity_2.verify.overload(
                "java.lang.String",
                "java.security.cert.X509Certificate"
            ).implementation = function(a, b) {
                console.log("  --> Bypassing Trustkit OkHostnameVerifier(cert): " + a);
                return true;
            };
            console.log("[+] Trustkit OkHostnameVerifier(cert)");
        } catch (err) {
            console.log("[ ] Trustkit OkHostnameVerifier(cert)");
        }

        try {
            // Bypass Trustkit {3}
            const trustkit_PinningTrustManager = Java.use(
                "com.datatheorem.android.trustkit.pinning.PinningTrustManager"
            );
            trustkit_PinningTrustManager.checkServerTrusted.implementation =
                function() {
                    console.log("  --> Bypassing Trustkit PinningTrustManager");
                };
            console.log("[+] Trustkit PinningTrustManager");
        } catch (err) {
            console.log("[ ] Trustkit PinningTrustManager");
        }

        // Appcelerator Titanium
        try {
            const appcelerator_PinningTrustManager = Java.use(
                "appcelerator.https.PinningTrustManager"
            );
            appcelerator_PinningTrustManager.checkServerTrusted.implementation =
                function() {
                    console.log("  --> Bypassing Appcelerator PinningTrustManager");
                };
            console.log("[+] Appcelerator PinningTrustManager");
        } catch (err) {
            console.log("[ ] Appcelerator PinningTrustManager");
        }

        // OpenSSLSocketImpl Conscrypt
        try {
            const OpenSSLSocketImpl = Java.use(
                "com.android.org.conscrypt.OpenSSLSocketImpl"
            );
            OpenSSLSocketImpl.verifyCertificateChain.implementation = function(
                certRefs,
                JavaObject,
                authMethod
            ) {
                console.log("  --> Bypassing OpenSSLSocketImpl Conscrypt");
            };
            console.log("[+] OpenSSLSocketImpl Conscrypt");
        } catch (err) {
            console.log("[ ] OpenSSLSocketImpl Conscrypt");
        }

        // OpenSSLEngineSocketImpl Conscrypt
        try {
            const OpenSSLEngineSocketImpl_Activity = Java.use(
                "com.android.org.conscrypt.OpenSSLEngineSocketImpl"
            );
            OpenSSLEngineSocketImpl_Activity.verifyCertificateChain.overload(
                "[Ljava.lang.Long;",
                "java.lang.String"
            ).implementation = function(a, b) {
                console.log("  --> Bypassing OpenSSLEngineSocketImpl Conscrypt: " + b);
            };
            console.log("[+] OpenSSLEngineSocketImpl Conscrypt");
        } catch (err) {
            console.log("[ ] OpenSSLEngineSocketImpl Conscrypt");
        }

        // OpenSSLSocketImpl Apache Harmony
        try {
            const OpenSSLSocketImpl_Harmony = Java.use(
                "org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl"
            );
            OpenSSLSocketImpl_Harmony.verifyCertificateChain.implementation =
                function(asn1DerEncodedCertificateChain, authMethod) {
                    console.log("  --> Bypassing OpenSSLSocketImpl Apache Harmony");
                };
            console.log("[+] OpenSSLSocketImpl Apache Harmony");
        } catch (err) {
            console.log("[ ] OpenSSLSocketImpl Apache Harmony");
        }

        // PhoneGap sslCertificateChecker
        try {
            const phonegap_Activity = Java.use(
                "nl.xservices.plugins.sslCertificateChecker"
            );
            phonegap_Activity.execute.overload(
                "java.lang.String",
                "org.json.JSONArray",
                "org.apache.cordova.CallbackContext"
            ).implementation = function(a, b, c) {
                console.log("  --> Bypassing PhoneGap sslCertificateChecker: " + a);
                return true;
            };
            console.log("[+] PhoneGap sslCertificateChecker");
        } catch (err) {
            console.log("[ ] PhoneGap sslCertificateChecker");
        }

        // IBM MobileFirst pinTrustedCertificatePublicKey (double bypass)
        try {
            // Bypass IBM MobileFirst {1}
            const WLClient_Activity_1 = Java.use(
                "com.worklight.wlclient.api.WLClient"
            );
            WLClient_Activity_1.getInstance().pinTrustedCertificatePublicKey.overload(
                "java.lang.String"
            ).implementation = function(cert) {
                console.log(
                    "  --> Bypassing IBM MobileFirst pinTrustedCertificatePublicKey (string): " +
                    cert
                );
                return;
            };
            console.log("[+] IBM MobileFirst pinTrustedCertificatePublicKey (string)");
        } catch (err) {
            console.log("[ ] IBM MobileFirst pinTrustedCertificatePublicKey (string)");
        }

        try {
            // Bypass IBM MobileFirst {2}
            const WLClient_Activity_2 = Java.use(
                "com.worklight.wlclient.api.WLClient"
            );
            WLClient_Activity_2.getInstance().pinTrustedCertificatePublicKey.overload(
                "[Ljava.lang.String;"
            ).implementation = function(cert) {
                console.log(
                    "  --> Bypassing IBM MobileFirst pinTrustedCertificatePublicKey (string array): " +
                    cert
                );
                return;
            };
            console.log("[+] IBM MobileFirst pinTrustedCertificatePublicKey (string array)");
        } catch (err) {
            console.log("[ ] IBM MobileFirst pinTrustedCertificatePublicKey (string array)");
        }

        // IBM WorkLight (ancestor of MobileFirst) HostNameVerifierWithCertificatePinning
        try {
            // Bypass IBM WorkLight {1}
            const worklight_Activity_1 = Java.use(
                "com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning"
            );
            worklight_Activity_1.verify.overload(
                "java.lang.String",
                "javax.net.ssl.SSLSocket"
            ).implementation = function(a, b) {
                console.log(
                    "  --> Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSocket): " +
                    a
                );
                return;
            };
            console.log("[+] IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSocket)");
        } catch (err) {
            console.log("[ ] IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSocket)");
        }

        try {
            // Bypass IBM WorkLight {2}
            const worklight_Activity_2 = Java.use(
                "com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning"
            );
            worklight_Activity_2.verify.overload(
                "java.lang.String",
                "java.security.cert.X509Certificate"
            ).implementation = function(a, b) {
                console.log(
                    "  --> Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning (cert): " +
                    a
                );
                return;
            };
            console.log("[+] IBM WorkLight HostNameVerifierWithCertificatePinning (cert)");
        } catch (err) {
            console.log("[ ] IBM WorkLight HostNameVerifierWithCertificatePinning (cert)");
        }

        try {
            // Bypass IBM WorkLight {3}
            const worklight_Activity_3 = Java.use(
                "com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning"
            );
            worklight_Activity_3.verify.overload(
                "java.lang.String",
                "[Ljava.lang.String;",
                "[Ljava.lang.String;"
            ).implementation = function(a, b) {
                console.log(
                    "  --> Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning (string string): " +
                    a
                );
                return;
            };
            console.log("[+] IBM WorkLight HostNameVerifierWithCertificatePinning (string string)");
        } catch (err) {
            console.log("[ ] IBM WorkLight HostNameVerifierWithCertificatePinning (string string)");
        }

        try {
            // Bypass IBM WorkLight {4}
            const worklight_Activity_4 = Java.use(
                "com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning"
            );
            worklight_Activity_4.verify.overload(
                "java.lang.String",
                "javax.net.ssl.SSLSession"
            ).implementation = function(a, b) {
                console.log(
                    "  --> Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSession): " +
                    a
                );
                return true;
            };
            console.log("[+] IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSession)");
        } catch (err) {
            console.log("[ ] IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSession)");
        }

        // Android WebViewClient (double bypass)
        try {
            // Bypass WebViewClient {1} (deprecated from Android 6)
            const AndroidWebViewClient_Activity_1 = Java.use(
                "android.webkit.WebViewClient"
            );
            AndroidWebViewClient_Activity_1.onReceivedSslError.overload(
                "android.webkit.WebView",
                "android.webkit.SslErrorHandler",
                "android.net.http.SslError"
            ).implementation = function(obj1, obj2, obj3) {
                console.log("  --> Bypassing Android WebViewClient (SslErrorHandler)");
                obj2.proceed();
            };
            console.log("[+] Android WebViewClient (SslErrorHandler)");
        } catch (err) {
            console.log("[ ] Android WebViewClient (SslErrorHandler)");
        }

        try {
            // Bypass WebViewClient {2}
            const AndroidWebViewClient_Activity_2 = Java.use(
                "android.webkit.WebViewClient"
            );
            AndroidWebViewClient_Activity_2.onReceivedError.overload(
                "android.webkit.WebView",
                "android.webkit.WebResourceRequest",
                "android.webkit.WebResourceError"
            ).implementation = function(obj1, obj2, obj3) {
                console.log("  --> Bypassing Android WebViewClient (WebResourceError)");
            };
            console.log("[+] Android WebViewClient (WebResourceError)");
        } catch (err) {
            console.log("[ ] Android WebViewClient (WebResourceError)");
        }

        // Apache Cordova WebViewClient
        try {
            const CordovaWebViewClient_Activity = Java.use(
                "org.apache.cordova.CordovaWebViewClient"
            );
            CordovaWebViewClient_Activity.onReceivedSslError.overload(
                "android.webkit.WebView",
                "android.webkit.SslErrorHandler",
                "android.net.http.SslError"
            ).implementation = function(obj1, obj2, obj3) {
                console.log("  --> Bypassing Apache Cordova WebViewClient");
                obj3.proceed();
            };
            console.log("[+] Apache Cordova WebViewClient");
        } catch (err) {
            console.log("[ ] Apache Cordova WebViewClient");
        }

        // Boye AbstractVerifier
        try {
            const boye_AbstractVerifier = Java.use(
                "ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier"
            );
            boye_AbstractVerifier.verify.implementation = function(host, ssl) {
                console.log("  --> Bypassing Boye AbstractVerifier: " + host);
            };
            console.log("[+] Boye AbstractVerifier");
        } catch (err) {
            console.log("[ ] Boye AbstractVerifier");
        }

        // Appmattus
        try {
            const appmatus_Activity = Java.use(
                "com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyInterceptor"
            );
            appmatus_Activity["intercept"].implementation = function(a) {
                console.log("  --> Bypassing Appmattus (Transparency)");
                return a.proceed(a.request());
            };
            console.log("[+] Appmattus (CertificateTransparencyInterceptor)");
        } catch (err) {
            console.log("[ ] Appmattus (CertificateTransparencyInterceptor)");
        }

        try {
            const CertificateTransparencyTrustManager = Java.use(
                "com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyTrustManager"
            );
            CertificateTransparencyTrustManager["checkServerTrusted"].overload(
                "[Ljava.security.cert.X509Certificate;",
                "java.lang.String"
            ).implementation = function(x509CertificateArr, str) {
                console.log("  --> Bypassing Appmattus (CertificateTransparencyTrustManager)");
            };
            CertificateTransparencyTrustManager["checkServerTrusted"].overload(
                "[Ljava.security.cert.X509Certificate;",
                "java.lang.String",
                "java.lang.String"
            ).implementation = function(x509CertificateArr, str, str2) {
                console.log("  --> Bypassing Appmattus (CertificateTransparencyTrustManager)");
                return Java.use("java.util.ArrayList").$new();
            };
            console.log("[+] Appmattus (CertificateTransparencyTrustManager)");
        } catch (err) {
            console.log("[ ] Appmattus (CertificateTransparencyTrustManager)");
        }

        console.log("[+] SSL pinning bypass completed");
        return true;

    });
    
}, 0);  
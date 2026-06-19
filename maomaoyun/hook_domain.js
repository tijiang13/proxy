// frida -U -f com.mt.maomao -l hook_domain.js
// Prints the live panel domain that the native core resolves at runtime.
Java.perform(function () {
    var Core = Java.use("com.mt.Core");
    ["queryConfiguration", "queryDomain", "queryPath"].forEach(function (m) {
        Core[m].implementation = function (arg) {
            var out = this[m](arg);
            console.log("[Core." + m + "]  in=" + arg + "\n              out=" + out);
            return out;
        };
    });
});

/*
 * Copyright © 2026 NikKuz99. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.activity

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.Uri
import android.net.http.SslError
import android.os.Bundle
import android.os.StrictMode
import android.util.Log
import android.webkit.JavascriptInterface
import android.webkit.SslErrorHandler
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.appcompat.app.AppCompatActivity
import java.io.InputStream
import java.net.URL
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager

class CaptchaActivity : AppCompatActivity() {

    private var previousNetwork: Network? = null
    private var didBindNetwork = false

    companion object {
        private const val TAG = "WireGuard/CaptchaActivity"
        private const val EXTRA_REDIRECT_URI = "redirect_uri"
        private const val CAPTCHA_TIMEOUT_SECONDS = 120L

        @Volatile
        private var pendingResult: CompletableFuture<String>? = null

        // Baseline IPs for VK domains (when DNS is unavailable)
        private val vkDomainToIp = mapOf(
            "id.vk.ru" to "93.186.237.1",
            "id.vk.com" to "93.186.237.1",
            "login.vk.ru" to "93.186.237.1",
            "login.vk.com" to "93.186.237.1",
            "api.vk.ru" to "87.240.129.140",
            "api.vk.com" to "87.240.129.140",
            "calls.okcdn.ru" to "155.212.204.12",
            "static.vk.ru" to "87.240.129.133",
            "static.vk.com" to "87.240.129.133"
        )

        fun solveCaptcha(context: Context, redirectUri: String): String {
            pendingResult = CompletableFuture<String>()
            val intent = Intent(context, CaptchaActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                putExtra(EXTRA_REDIRECT_URI, redirectUri)
            }
            context.startActivity(intent)
            return try {
                pendingResult?.get(CAPTCHA_TIMEOUT_SECONDS, TimeUnit.SECONDS) ?: ""
            } catch (_: Throwable) {
                ""
            }
        }

        /**
         * JS body (without IIFE wrapper) that intercepts fetch() and XMLHttpRequest
         * to rewrite absolute VK URLs to relative URLs.
         * Injected into HTML head before any other script runs.
         */
        private const val FETCH_INTERCEPT_SCRIPT_BODY = """(function(){
            var vkDomains = ["api.vk.ru","api.vk.com","login.vk.ru","login.vk.com","id.vk.ru","id.vk.com","calls.okcdn.ru","static.vk.ru","static.vk.com","oauth.vk.com"];
            function rewriteUrl(url){
                if(typeof url!=="string")return url;
                for(var i=0;i<vkDomains.length;i++){
                    var d=vkDomains[i];
                    if(url.indexOf("https://"+d)===0){return url.substring(8+d.length);}
                    if(url.indexOf("http://"+d)===0){return url.substring(7+d.length);}
                }
                return url;
            }
            function bodyToQuery(body){
                if(!body)return "";
                if(typeof body==="string")return body;
                try{
                    if(body instanceof URLSearchParams)return body.toString();
                    if(body instanceof FormData){
                        var parts=[];
                        var entries=body.entries();
                        for(var p=entries.next();!p.done;p=entries.next()){
                            parts.push(encodeURIComponent(p.value[0])+"="+encodeURIComponent(p.value[1]));
                        }
                        return parts.join("&");
                    }
                }catch(e){}
                try{return String(body);}catch(e){return "";}
            }
            function appendQuery(url,query){
                if(!query)return url;
                var sep=url.indexOf("?")>=0?"&":"?";
                return url+sep+query;
            }
            var origFetch=window.fetch;
            if(origFetch){window.fetch=function(input,init){
                if(typeof input==="string"){input=rewriteUrl(input);}
                else if(input&&input.url){input.url=rewriteUrl(input.url);}
                if(init&&(init.method==="POST"||init.method==="PUT")){
                    var bodyQ=bodyToQuery(init.body);
                    if(bodyQ){
                        if(typeof input==="string"){input=appendQuery(input,bodyQ);}
                        else if(input&&input.url){input.url=appendQuery(input.url,bodyQ);}
                    }
                    init.method="GET";
                    try{delete init.body;}catch(e){init.body=undefined;}
                    console.log("[FW] fetch POST->GET: "+(typeof input==="string"?input:input.url)+" body="+bodyQ.substring(0,200));
                }
                return origFetch.call(this,input,init);
            };}
            var origOpen=XMLHttpRequest.prototype.open;
            var origSend=XMLHttpRequest.prototype.send;
            XMLHttpRequest.prototype.open=function(method,url){
                this._capMethod=method;
                this._capUrl=typeof url==="string"?rewriteUrl(url):url;
                if(typeof url==="string"){arguments[1]=this._capUrl;}
                return origOpen.apply(this,arguments);
            };
            XMLHttpRequest.prototype.send=function(body){
                if(this._capMethod==="POST"||this._capMethod==="PUT"){
                    var bodyQ=bodyToQuery(body);
                    if(bodyQ){
                        var newUrl=appendQuery(this._capUrl,bodyQ);
                        console.log("[FW] XHR POST->GET: "+newUrl+" body="+bodyQ.substring(0,200));
                        try{
                            origOpen.call(this,"GET",newUrl,true);
                        }catch(e){console.error("[FW] XHR reopen failed: "+e.message);}
                    }
                }
                return origSend.call(this,null);
            };
            console.log("[FW] Fetch/XHR interceptor installed");
        })();"""

        private val FETCH_INTERCEPT_SCRIPT = FETCH_INTERCEPT_SCRIPT_BODY

        private val INTERCEPT_SCRIPT = """
            (function() {
                var origOpen = XMLHttpRequest.prototype.open;
                var origSend = XMLHttpRequest.prototype.send;
                XMLHttpRequest.prototype.open = function() {
                    this._captchaUrl = arguments[1];
                    return origOpen.apply(this, arguments);
                };
                XMLHttpRequest.prototype.send = function() {
                    var xhr = this;
                    if (xhr._captchaUrl && xhr._captchaUrl.indexOf('captchaNotRobot.check') !== -1) {
                        xhr.addEventListener('load', function() {
                            try {
                                var data = JSON.parse(xhr.responseText);
                                if (data.response && data.response.success_token) {
                                    AndroidCaptcha.onResult(data.response.success_token);
                                }
                            } catch(e) {}
                        });
                    }
                    return origSend.apply(this, arguments);
                };
                var origFetch = window.fetch;
                if (origFetch) {
                    window.fetch = function() {
                        var url = arguments[0];
                        if (typeof url === 'string' && url.indexOf('captchaNotRobot.check') !== -1) {
                            return origFetch.apply(this, arguments).then(function(resp) {
                                resp.clone().text().then(function(text) {
                                    try {
                                        var data = JSON.parse(text);
                                        if (data.response && data.response.success_token) {
                                            AndroidCaptcha.onResult(data.response.success_token);
                                        }
                                    } catch(e) {}
                                });
                                return resp;
                            });
                        }
                        return origFetch.apply(this, arguments);
                    };
                }
                window.addEventListener('message', function(event) {
                    try {
                        var data = typeof event.data === 'string' ? JSON.parse(event.data) : event.data;
                        if (data && data.response && data.response.success_token) {
                            AndroidCaptcha.onResult(data.response.success_token);
                        }
                    } catch(e) {}
                });
            })();
        """
    }

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Disable StrictMode network detection — shouldInterceptRequest may run on main thread
        // on Android 7 for some requests (initial HTML load), and we do network I/O there.
        val oldThreadPolicy = StrictMode.getThreadPolicy()
        StrictMode.setThreadPolicy(
            StrictMode.ThreadPolicy.Builder(oldThreadPolicy)
                .permitNetwork()
                .build()
        )

        val redirectUri = intent.getStringExtra(EXTRA_REDIRECT_URI)
        if (redirectUri.isNullOrEmpty()) {
            Log.e(TAG, "No redirect URI provided")
            deliverResult("")
            finish()
            return
        }

        bindToPhysicalNetwork()
        Log.d(TAG, "Loading captcha page...")

        val webView = WebView(this).apply {
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = true
            settings.userAgentString = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Mobile Safari/537.36"

            addJavascriptInterface(CaptchaBridge(), "AndroidCaptcha")
            webChromeClient = object : WebChromeClient() {
                override fun onConsoleMessage(consoleMessage: android.webkit.ConsoleMessage?): Boolean {
                    val cm = consoleMessage ?: return super.onConsoleMessage(consoleMessage)
                    val level = cm.messageLevel()
                    val lvlStr = when (level) {
                        android.webkit.ConsoleMessage.MessageLevel.ERROR -> "ERR"
                        android.webkit.ConsoleMessage.MessageLevel.WARNING -> "WRN"
                        android.webkit.ConsoleMessage.MessageLevel.DEBUG -> "DBG"
                        else -> "LOG"
                    }
                    Log.d(TAG, "JS[$lvlStr] ${cm.sourceId()}:${cm.lineNumber()}: ${cm.message()}")
                    return true
                }
            }

            webViewClient = object : WebViewClient() {
                override fun onPageFinished(view: WebView?, url: String?) {
                    super.onPageFinished(view, url)
                    Log.d(TAG, "onPageFinished: " + url)
                    view?.evaluateJavascript(FETCH_INTERCEPT_SCRIPT, null)
                    view?.evaluateJavascript(INTERCEPT_SCRIPT, null)
                }

                override fun onReceivedSslError(view: WebView?, handler: SslErrorHandler?, error: SslError?) {
                    handler?.proceed()
                }

                override fun shouldInterceptRequest(view: WebView?, request: WebResourceRequest?): WebResourceResponse? {
                    val uri = request?.url ?: return null
                    val host = uri.host ?: return null
                    val reqPath = uri.path ?: "/"
                    val method = request.method ?: "GET"

                    // Log EVERY request to see what WebView is asking for
                    Log.d(TAG, "REQ " + method + " host=" + host + " path=" + reqPath + (if (uri.query != null) "?" + uri.query else ""))

                    // Check path FIRST — rewritten relative URLs go to id.vk.ru
                    // but content is on static.vk.ru or api.vk.ru
                    if (reqPath.startsWith("/vkid/")) {
                        val staticIp = vkDomainToIp["static.vk.ru"] ?: "87.240.129.133"
                        Log.d(TAG, "Routing /vkid/ to static.vk.ru: " + reqPath)
                        return proxyRequest(uri, staticIp, "static.vk.ru", request)
                    }
                    if (reqPath.startsWith("/method/")) {
                        val apiIp = vkDomainToIp["api.vk.ru"] ?: "87.240.129.140"
                        Log.d(TAG, "Routing /method/ to api.vk.ru: " + reqPath)
                        return proxyRequest(uri, apiIp, "api.vk.ru", request)
                    }

                    // Direct VK domain match
                    val targetIp = vkDomainToIp[host]
                    if (targetIp != null) {
                        return proxyRequest(uri, targetIp, host, request)
                    }

                    Log.d(TAG, "NOT INTERCEPTED (no VK domain match): " + host + reqPath)
                    return null
                }

                override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean {
                    return false
                }
            }
        }

        setContentView(webView)
        webView.loadUrl(redirectUri)
    }

    /**
     * Proxies a WebView request through HttpsURLConnection using IP instead of domain.
     * Sets correct Host header so VK server routes the request properly.
     */
    private fun proxyRequest(
        uri: Uri,
        ip: String,
        originalHost: String,
        request: WebResourceRequest
    ): WebResourceResponse {
        val scheme = uri.scheme ?: "https"
        val port = if (uri.port != -1) ":${uri.port}" else ""
        val path = uri.path ?: "/"
        val query = if (uri.query != null) "?${uri.query}" else ""
        val urlStr = "$scheme://$ip$port$path$query"

        Log.d(TAG, "Proxying: $originalHost -> $ip ($path)")

        try {
            val conn = (URL(urlStr).openConnection() as HttpsURLConnection).apply {
                requestMethod = request.method ?: "GET"
                setRequestProperty("Host", originalHost)
                setRequestProperty("User-Agent", "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Mobile Safari/537.36")
                for ((key, value) in request.requestHeaders) {
                    if (key.lowercase() != "host") {
                        setRequestProperty(key, value)
                    }
                }

                // Trust all certs (IP-based access causes cert mismatch)
                val sslContext = SSLContext.getInstance("TLS").apply {
                    init(null, arrayOf(object : X509TrustManager {
                        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
                        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
                        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
                    }), SecureRandom())
                }
                setSSLSocketFactory(sslContext.socketFactory)
                setHostnameVerifier { _, _ -> true }

                connectTimeout = 15000
                readTimeout = 15000
                instanceFollowRedirects = true
            }

            val statusCode = conn.responseCode
            val rawContentType = conn.contentType ?: "text/html; charset=utf-8"
            val mimeType = rawContentType.split(";")[0].trim()
            val encoding = if (rawContentType.contains("charset=")) {
                rawContentType.substringAfter("charset=").trim()
            } else {
                conn.contentEncoding ?: "utf-8"
            }
            val inputStream: InputStream = if (statusCode >= 400) {
                conn.errorStream ?: conn.inputStream
            } else {
                conn.inputStream
            }

            val baos = java.io.ByteArrayOutputStream()
            inputStream.copyTo(baos)
            val bodyBytes = baos.toByteArray()

            Log.d(TAG, "Proxied response: $statusCode ($mimeType, $encoding, ${bodyBytes.size} bytes)")

            val responseHeaders = mutableMapOf<String, String>()
            for ((key, values) in conn.headerFields ?: emptyMap()) {
                if (key != null && key.lowercase() != "content-type" && values.isNotEmpty()) {
                    responseHeaders[key] = values.joinToString(", ")
                }
            }
            // Add CORS headers so fetch() with mode:cors works in WebView
            responseHeaders["Access-Control-Allow-Origin"] = "*"
            responseHeaders["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
            responseHeaders["Access-Control-Allow-Headers"] = "*"

            // Process HTML: rewrite URLs, inline external JS/CSS, inject interceptors
            var finalBytes = bodyBytes
            if (statusCode == 200 && (mimeType == "text/html" || mimeType == "application/xhtml+xml")) {
                val body = String(bodyBytes, Charsets.UTF_8)
                // Log first 3000 chars of HTML for debugging
                val preview = if (body.length > 3000) body.substring(0, 3000) + "...[truncated]" else body
                Log.d(TAG, "HTML preview:\n" + preview)

                val inlined = inlineExternalResources(body)
                val modified = rewriteVkUrls(inlined)
                if (modified != body) {
                    finalBytes = modified.toByteArray(Charsets.UTF_8)
                    Log.d(TAG, "Modified HTML: " + bodyBytes.size + " -> " + finalBytes.size + " bytes")
                }
            } else if (statusCode == 200 && (mimeType == "application/json" || mimeType == "text/json")) {
                // Log small JSON responses for debugging
                if (bodyBytes.size < 500) {
                    Log.d(TAG, "JSON response (" + path + "): " + String(bodyBytes, Charsets.UTF_8))
                }
            }

            return WebResourceResponse(mimeType, encoding, statusCode, conn.responseMessage ?: "OK", responseHeaders, java.io.ByteArrayInputStream(finalBytes))
        } catch (e: Exception) {
            Log.e(TAG, "Proxy failed for $originalHost: ${e.message}")
            return WebResourceResponse("text/plain", "utf-8", 502, "Bad Gateway", emptyMap(), e.message?.byteInputStream() ?: "".byteInputStream())
        }
    }

    /**
     * Inlines all external <script src="..."> and <link rel="stylesheet" href="..."> tags
     * that reference VK domains (paths starting with /vkid/, /method/, or matching VK host).
     * Downloads the resource via HttpURLConnection to the IP address and embeds the content inline.
     *
     * This is needed because Android 7 WebView does not call shouldInterceptRequest
     * for <script src> tags, so JS files would fail to load when DNS is blocked.
     */
    private fun inlineExternalResources(html: String): String {
        var result = html
        val staticIp = vkDomainToIp["static.vk.ru"] ?: "87.240.129.133"

        // Remove ad.mail.ru script (blocks page load when DNS is blocked, not needed for captcha)
        val adPattern = Regex("""<script\b[^>]*\bsrc\s*=\s*["']https?://ad\.mail\.ru[^"']*["'][^>]*>\s*</script>""", RegexOption.IGNORE_CASE)
        val adCount = adPattern.findAll(result).count()
        if (adCount > 0) {
            result = adPattern.replace(result) { "" }
            Log.d(TAG, "Removed " + adCount + " ad.mail.ru script tags")
        }

        // Collect inlined scripts and CSS to move them to end of body (preserve defer semantics)
        val inlinedResources = StringBuilder()

        // Pattern 1: <script src="..."></script>
        val scriptPattern = Regex("""<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>\s*</script>""", RegexOption.IGNORE_CASE)
        var scriptCount = 0
        result = scriptPattern.replace(result) { match ->
            val src = match.groupValues[1]
            val resourcePath = extractVkPath(src)
            if (resourcePath == null) {
                Log.d(TAG, "Skipping non-VK script src: " + src)
                return@replace match.value
            }
            scriptCount++
            Log.d(TAG, "Inlining script: " + src + " -> path=" + resourcePath)
            val content = downloadResource(staticIp, "static.vk.ru", resourcePath)
            if (content != null) {
                Log.d(TAG, "Inlined script OK: " + content.length + " chars")
                // Wrap in DOMContentLoaded listener to emulate defer behavior
                inlinedResources.append("<script>\n")
                inlinedResources.append("(function(){var origOnLoad=document.readyState!==\'loading\'?null:document.addEventListener.bind(document,\'DOMContentLoaded\',null);")
                inlinedResources.append("function runScript(){try{\n")
                inlinedResources.append(content)
                inlinedResources.append("\n}catch(e){console.error(\'Inlined script error: \'+e.message+\'\\n\'+e.stack);}}")
                inlinedResources.append("if(document.readyState===\'loading\'){document.addEventListener(\'DOMContentLoaded\',runScript);}else{runScript();}})();")
                inlinedResources.append("\n</script>\n")
                ""
            } else {
                Log.e(TAG, "Failed to inline script: " + src)
                match.value
            }
        }
        if (scriptCount > 0) {
            Log.d(TAG, "Inlined " + scriptCount + " external script tags (will be moved to end of body)")
        }

        // Pattern 2: <link rel="stylesheet" href="...">
        val linkPattern = Regex("""<link\b[^>]*\brel\s*=\s*["']stylesheet["'][^>]*\bhref\s*=\s*["']([^"']+)["'][^>]*>""", RegexOption.IGNORE_CASE)
        val linkPattern2 = Regex("""<link\b[^>]*\bhref\s*=\s*["']([^"']+)["'][^>]*\brel\s*=\s*["']stylesheet["'][^>]*>""", RegexOption.IGNORE_CASE)
        var cssCount = 0
        for (pat in listOf(linkPattern, linkPattern2)) {
            result = pat.replace(result) { match ->
                val href = match.groupValues[1]
                val resourcePath = extractVkPath(href)
                if (resourcePath == null) {
                    Log.d(TAG, "Skipping non-VK link href: " + href)
                    return@replace match.value
                }
                cssCount++
                Log.d(TAG, "Inlining CSS: " + href + " -> path=" + resourcePath)
                val content = downloadResource(staticIp, "static.vk.ru", resourcePath)
                if (content != null) {
                    Log.d(TAG, "Inlined CSS OK: " + content.length + " chars")
                    // CSS can stay in head — doesn't need defer
                    "<style>\n" + content + "\n</style>"
                } else {
                    Log.e(TAG, "Failed to inline CSS: " + href)
                    match.value
                }
            }
        }
        if (cssCount > 0) {
            Log.d(TAG, "Inlined " + cssCount + " external CSS links")
        }

        // Move inlined scripts to end of body (after window.init is set)
        if (inlinedResources.isNotEmpty()) {
            if (result.contains("</body>")) {
                result = result.replaceFirst("</body>", inlinedResources.toString() + "</body>")
                Log.d(TAG, "Moved " + scriptCount + " inlined scripts to end of body")
            } else {
                result += inlinedResources.toString()
                Log.d(TAG, "Appended " + scriptCount + " inlined scripts to end of HTML")
            }
        }

        return result
    }

    /**
     * Extracts the path portion from a URL if it points to a VK domain.
     * Returns null for non-VK URLs.
     * Examples:
     *   "https://static.vk.ru/vkid/1.1.1387/not_robot_captcha.js" -> "/vkid/1.1.1387/not_robot_captcha.js"
     *   "/vkid/1.1.1387/not_robot_captcha.js" -> "/vkid/1.1.1387/not_robot_captcha.js"
     *   "https://example.com/foo.js" -> null
     */
    private fun extractVkPath(url: String): String? {
        if (url.startsWith("/") && !url.startsWith("//")) {
            // Already a relative path
            return url
        }
        for (domain in vkDomainToIp.keys) {
            val https = "https://" + domain
            val http = "http://" + domain
            if (url.startsWith(https)) {
                return url.substring(https.length)
            }
            if (url.startsWith(http)) {
                return url.substring(http.length)
            }
        }
        return null
    }

    /**
     * Downloads a resource from VK server via IP address with correct Host header.
     * Returns the content as a String, or null on failure.
     */
    private fun downloadResource(ip: String, host: String, path: String): String? {
        val urlStr = "https://" + ip + path
        Log.d(TAG, "Downloading resource: " + host + " -> " + ip + " (" + path + ")")
        try {
            val conn = (URL(urlStr).openConnection() as HttpsURLConnection).apply {
                requestMethod = "GET"
                setRequestProperty("Host", host)
                setRequestProperty("User-Agent", "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Mobile Safari/537.36")
                setRequestProperty("Referer", "https://" + host + "/")
                setRequestProperty("Accept", "*/*")

                val sslContext = SSLContext.getInstance("TLS").apply {
                    init(null, arrayOf(object : X509TrustManager {
                        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
                        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
                        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
                    }), SecureRandom())
                }
                setSSLSocketFactory(sslContext.socketFactory)
                setHostnameVerifier { _, _ -> true }

                connectTimeout = 15000
                readTimeout = 15000
                instanceFollowRedirects = true
            }

            val statusCode = conn.responseCode
            val inputStream: InputStream = if (statusCode >= 400) {
                conn.errorStream ?: conn.inputStream
            } else {
                conn.inputStream
            }
            val baos = java.io.ByteArrayOutputStream()
            inputStream.copyTo(baos)
            val bytes = baos.toByteArray()
            conn.disconnect()

            if (statusCode != 200) {
                Log.e(TAG, "Resource download failed: " + statusCode + " for " + path)
                return null
            }
            Log.d(TAG, "Resource downloaded: " + path + " (" + bytes.size + " bytes, " + conn.contentType + ")")
            return String(bytes, Charsets.UTF_8)
        } catch (e: Exception) {
            Log.e(TAG, "Resource download exception for " + path + ": " + e.message)
            return null
        }
    }

    private fun deliverResult(token: String) {
        pendingResult?.complete(token)
    }

    private inner class CaptchaBridge {
        @JavascriptInterface
        fun onResult(successToken: String) {
            Log.d(TAG, "Captcha solved, got success_token (length=${successToken.length})")
            runOnUiThread {
                deliverResult(successToken)
                finish()
            }
        }
    }

    private fun bindToPhysicalNetwork() {
        try {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            previousNetwork = cm.boundNetworkForProcess
            val networks = cm.allNetworks
            for (network in networks) {
                val caps = cm.getNetworkCapabilities(network) ?: continue
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue
                if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue
                cm.bindProcessToNetwork(network)
                didBindNetwork = true
                val type = when {
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "WiFi"
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "Cellular"
                    else -> "Other"
                }
                Log.d(TAG, "Bound process to physical network: $network ($type)")
                return
            }
            Log.w(TAG, "No physical network found to bind to!")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to bind to physical network", e)
        }
    }

    /**
     * Rewrites all absolute VK URLs to relative URLs in any text content.
     * Also injects the fetch/XHR interceptor into HTML head BEFORE any other script runs.
     */
    private fun rewriteVkUrls(content: String): String {
        var result = content

        // Inject fetch/XHR interceptor into HTML head BEFORE any other script runs.
        val interceptor = "<script>" + FETCH_INTERCEPT_SCRIPT_BODY + "</script>"
        if (result.contains("<head>")) {
            result = result.replaceFirst("<head>", "<head>" + interceptor)
            Log.d(TAG, "Injected fetch interceptor into HTML head")
        } else if (result.contains("<html>")) {
            result = result.replaceFirst("<html>", "<html>" + interceptor)
            Log.d(TAG, "Injected fetch interceptor after <html>")
        } else {
            // Prepend before any script
            if (result.contains("<script")) {
                result = interceptor + result
                Log.d(TAG, "Prepended fetch interceptor before first script")
            }
        }

        for ((domain, _) in vkDomainToIp) {
            val https = "https://" + domain
            val http = "http://" + domain
            val countHttps = result.split(https).size - 1
            val countHttp = result.split(http).size - 1
            if (countHttps > 0) {
                result = result.replace(https, "")
                Log.d(TAG, "Rewrote " + countHttps + " URLs: " + domain + " (https) -> relative")
            }
            if (countHttp > 0) {
                result = result.replace(http, "")
                Log.d(TAG, "Rewrote " + countHttp + " URLs: " + domain + " (http) -> relative")
            }
        }
        return result
    }

    private fun restoreNetworkBinding() {
        if (!didBindNetwork) return
        try {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            cm.bindProcessToNetwork(previousNetwork)
            Log.d(TAG, "Restored previous network binding")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to restore network binding", e)
        }
    }

    override fun onDestroy() {
        restoreNetworkBinding()
        super.onDestroy()
        deliverResult("")
    }
}

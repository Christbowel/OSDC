<div align="center">
<h1>🎣 Open Source Daily Catch</h1>
<p><b>Automated Patch Intelligence for Security Engineers</b></p>
<p>
<a href="https://github.com/christbowel/osdc/actions/workflows/daily.yml"><img src="https://github.com/christbowel/osdc/actions/workflows/daily.yml/badge.svg" alt="Analysis"></a>
<a href="https://github.com/christbowel/osdc/actions/workflows/render.yml"><img src="https://github.com/christbowel/osdc/actions/workflows/render.yml/badge.svg" alt="Render"></a>
<a href="https://christbowel.github.io/OSDC"><img src="https://img.shields.io/badge/advisories-867-blue" alt="Advisories"></a>
<a href="https://christbowel.github.io/OSDC"><img src="https://img.shields.io/badge/patterns-49-purple" alt="Patterns"></a>
</p>
<p>
<a href="https://christbowel.github.io/OSDC">Live dashboard</a> · <a href="#how-it-works">How it works</a>
</p>
</div>
<hr>
<h3>GHSA-73cv-556c-w3g6</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-06-26 · Python<br>
<code>mcp-pinot-server</code> · Pattern: <code>UNSANITIZED_INPUT→SQL</code> · 16x across ecosystem
</p>
<p><b>Root cause</b> : The application allowed unauthenticated users to execute arbitrary SQL queries against the Pinot database. The `oauth_enabled=False` default configuration combined with binding to `0.0.0.0` made the Pinot server publicly accessible without authentication, enabling attackers to send malicious SQL.</p>
<p><b>Impact</b> : An attacker could execute arbitrary SQL commands, potentially leading to data exfiltration, modification, or deletion, and could also invoke administrative functions or other tools if the underlying database permissions allowed.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/mcp_pinot/pinot_client.py
+++ b/mcp_pinot/pinot_client.py
@@ -46,6 +49,289 @@ class PinotEndpoints:
     TABLE_CONFIG = &#34;tableConfigs/{}&#34;
 
 
+_READ_QUERY_START_KEYWORDS = {&#34;SELECT&#34;, &#34;WITH&#34;}
+_PROHIBITED_READ_QUERY_KEYWORDS = {
+    &#34;ALTER&#34;,
+    &#34;CALL&#34;,
+    &#34;COPY&#34;,
+    &#34;CREATE&#34;,
+    &#34;DELETE&#34;,
+    &#34;DESCRIBE&#34;,
+    &#34;DROP&#34;,
+    &#34;EXEC&#34;,
+    &#34;EXECUTE&#34;,
+    &#34;EXPLAIN&#34;,
+    &#34;EXPORT&#34;,
+    &#34;GRANT&#34;,
+    &#34;IMPORT&#34;,
+    &#34;INSERT&#34;,
+    &#34;INTO&#34;,
+    &#34;LOAD&#34;,
+    &#34;MERGE&#34;,
+    &#34;REFRESH&#34;,
+    &#34;REPLACE&#34;,
+    &#34;RESET&#34;,
+    &#34;REVOKE&#34;,
+    &#34;SET&#34;,
+    &#34;SHOW&#34;,
+    &#34;TRUNCATE&#34;,
+    &#34;UPDATE&#34;,
+    &#34;UPSERT&#34;,
+    &#34;USE&#34;,
+}
+
+
+def _strip_sql_comments(query: str) -&gt; str:
+    &#34;&#34;&#34;Remove SQL comments while preserving quoted strings and identifiers.&#34;&#34;&#34;
+    result: list[str] = []
+    quote: str | None = None
+    i = 0</pre>
</details>
<p><b>Fix</b> : The patch introduces extensive SQL parsing and validation logic. It defines a set of allowed starting keywords for read queries and a comprehensive list of prohibited keywords for write/administrative operations. It also includes functions to strip comments and split statements, ensuring that only safe read queries are processed.</p>
<p>
<a href="https://github.com/advisories/GHSA-73cv-556c-w3g6">Advisory</a> · <a href="https://github.com/startreedata/mcp-pinot/commit/1c7d3f9cd384854bf72c127d230bdb32299475ad">Commit</a>
</p>
<hr>
<h3>GHSA-c39w-43gm-34h5</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-06-23 · Go<br>
<code>gogs.io/gogs</code> · Pattern: <code>UNCLASSIFIED</code> · 192x across ecosystem
</p>
<p><b>Root cause</b> : </p>
<p><b>Impact</b> : </p>
<p><b>Fix</b> : </p>
<p>
<a href="https://github.com/advisories/GHSA-c39w-43gm-34h5">Advisory</a> · <a href="https://github.com/gogs/gogs/commit/f6acd467305943aae8403cbac81f0118dd1235d7">Commit</a>
</p>
<hr>
<h3>GHSA-76w7-j9cq-rx2j</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-05-29 · JavaScript<br>
<code>vm2</code> · Pattern: <code>UNCLASSIFIED</code> · 192x across ecosystem
</p>
<p><b>Root cause</b> : </p>
<p><b>Impact</b> : </p>
<p><b>Fix</b> : </p>
<p>
<a href="https://github.com/advisories/GHSA-76w7-j9cq-rx2j">Advisory</a> · <a href="https://github.com/patriksimek/vm2/commit/a462655009669c3124ee39498121651597529ea8">Commit</a>
</p>
<hr>
<h3>GHSA-m4wx-m65x-ghrr</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-05-29 · JavaScript<br>
<code>vm2</code> · Pattern: <code>UNCLASSIFIED</code> · 192x across ecosystem
</p>
<p><b>Root cause</b> : </p>
<p><b>Impact</b> : </p>
<p><b>Fix</b> : </p>
<p>
<a href="https://github.com/advisories/GHSA-m4wx-m65x-ghrr">Advisory</a> · <a href="https://github.com/patriksimek/vm2/commit/01a7552add345d5a6862623884e6b79a85bf0568">Commit</a>
</p>
<hr>
<h3>GHSA-rp36-8xq3-r6c4</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-05-29 · JavaScript<br>
<code>vm2</code> · Pattern: <code>UNCLASSIFIED</code> · 192x across ecosystem
</p>
<p><b>Root cause</b> : The vm2 sandbox failed to properly denylist certain Node.js built-in modules and their subpaths, specifically &#39;process&#39; and &#39;inspector/promises&#39;. This allowed an attacker to bypass the sandbox&#39;s security mechanisms by requiring these modules, which provide direct access to host system capabilities.</p>
<p><b>Impact</b> : An attacker could execute arbitrary code on the host system, completely escaping the sandbox environment and gaining full control over the application running the vm2 instance.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/lib/builtin.js
+++ b/lib/builtin.js
@@ -69,6 +87,7 @@ const DANGEROUS_BUILTINS = new Set([
 	&#39;vm&#39;,
 	&#39;repl&#39;,
 	&#39;inspector&#39;,
+	&#39;process&#39;,
 	// Host-process abort DoS: `trace_events.createTracing({categories: [...]})`
 	// asserts `args[0]-&gt;IsArray()` in C++; the array crosses the bridge as a
 	// Proxy, which fails the assertion and aborts the entire host process.
@@ -83,8 +102,21 @@ const DANGEROUS_BUILTINS = new Set([
 	&#39;wasi&#39;
 ]);
 
+// SECURITY (GHSA-rp36-8xq3-r6c4): Family-prefix denylist check. `inspector` and
+// `inspector/promises` must share fate; same for any future subpath under a
+// dangerous family. Also strips the `node:` URL-style prefix so
+// `node:process` and `node:inspector/promises` cannot bypass via spelling.
+function isDangerousBuiltin(key) {
+	if (typeof key !== &#39;string&#39;) return false;
+	if (key.startsWith(&#39;node:&#39;)) key = key.slice(5);
+	if (DANGEROUS_BUILTINS.has(key)) return true;
+	const slash = key.indexOf(&#39;/&#39;);
+	if (slash &gt; 0 &amp;&amp; DANGEROUS_BUILTINS.has(key.slice(0, slash))) return true;
+	return false;
+}
+
 const BUILTIN_MODULES = (nmod.builtinModules || Object.getOwnPropertyNames(process.binding(&#39;natives&#39;)))
-	.filter(s=&gt;!s.startsWith(&#39;internal/&#39;) &amp;&amp; !DANGEROUS_BUILTINS.has(s));
+	.filter(s=&gt;!s.startsWith(&#39;internal/&#39;) &amp;&amp; !isDangerousBuiltin(s));</pre>
</details>
<p><b>Fix</b> : The patch expands the denylist of dangerous built-in modules to include &#39;process&#39; and implements a family-based matching function, `isDangerousBuiltin`, to block subpaths like &#39;inspector/promises&#39;. It also strips the &#39;node:&#39; prefix from module names to prevent bypasses via alternative spellings, ensuring that these critical modules are never accessible from within the sandbox.</p>
<p>
<a href="https://github.com/advisories/GHSA-rp36-8xq3-r6c4">Advisory</a> · <a href="https://github.com/patriksimek/vm2/commit/a1ed47a98d1cc36cb48c0d566d55889688e0b59b">Commit</a>
</p>
<hr>
<h3>GHSA-v6mx-mf47-r5wg</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-05-29 · JavaScript<br>
<code>vm2</code> · Pattern: <code>UNCLASSIFIED</code> · 192x across ecosystem
</p>
<p><b>Root cause</b> : </p>
<p><b>Impact</b> : </p>
<p><b>Fix</b> : </p>
<p>
<a href="https://github.com/advisories/GHSA-v6mx-mf47-r5wg">Advisory</a> · <a href="https://github.com/patriksimek/vm2/commit/27c525f4615e2b983f122e2bed327d810126f5c8">Commit</a>
</p>
<hr>
<h3>GHSA-g8f2-4f4f-5jqw</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-05-11 · JavaScript<br>
<code>@nyariv/sandboxjs</code> · Pattern: <code>TYPE_CONFUSION→BYPASS</code> · 3x across ecosystem
</p>
<p><b>Root cause</b> : The sandbox environment in SandboxJS failed to restrict access to sensitive JavaScript properties like &#39;caller&#39;, &#39;callee&#39;, and &#39;arguments&#39;. These properties, when accessed from within a sandboxed function, could leak references to the internal execution context or global objects, effectively allowing an attacker to break out of the sandbox.</p>
<p><b>Impact</b> : An attacker could escape the JavaScript sandbox, gaining access to the host environment and potentially executing arbitrary code or accessing sensitive resources outside the intended sandboxed scope.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/src/executor/ops/prop.ts
+++ b/src/executor/ops/prop.ts
@@ -93,12 +93,15 @@ addOps&lt;unknown, PropertyKey&gt;(LispType.Prop, ({ done, a, b, obj, context, scope,
     }
   }
 
-  const val = a[b as keyof typeof a] as unknown;
   if (typeof a === &#39;function&#39;) {
     if (b === &#39;prototype&#39; &amp;&amp; !context.ctx.sandboxedFunctions.has(a)) {
       throw new SandboxAccessError(`Access to prototype of global object is not permitted`);
     }
+    if ([&#39;caller&#39;, &#39;callee&#39;, &#39;arguments&#39;].includes(b as string)) {
+      throw new SandboxAccessError(`Access to &#39;${b as string}&#39; property is not permitted`);
+    }
   }
+  const val = a[b as keyof typeof a] as unknown;
 
   if (b === &#39;__proto__&#39; &amp;&amp; !context.ctx.sandboxedFunctions.has(val?.constructor as any)) {
     throw new SandboxAccessError(`Access to prototype of global object is not permitted`);</pre>
</details>
<p><b>Fix</b> : The patch explicitly disallows access to the &#39;caller&#39;, &#39;callee&#39;, and &#39;arguments&#39; properties when a property is accessed on a function within the sandboxed environment. It introduces a check that throws a SandboxAccessError if an attempt is made to access these forbidden properties.</p>
<p>
<a href="https://github.com/advisories/GHSA-g8f2-4f4f-5jqw">Advisory</a> · <a href="https://github.com/nyariv/SandboxJS/commit/826865251232611ec94078bab5a18ec875dad4a5">Commit</a>
</p>
<hr>
<h3>GHSA-3258-qmv8-frp3</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-05-08 · Go<br>
<code>github.com/free5gc/smf</code> · Pattern: <code>MISSING_AUTH→ENDPOINT</code> · 32x across ecosystem
</p>
<p><b>Root cause</b> : The free5GC SMF&#39;s UPI management interface was not protected by any authentication middleware. This allowed unauthenticated requests to reach the underlying handlers for reading and writing topology information.</p>
<p><b>Impact</b> : An unauthenticated attacker could perform read and write operations on the SMF&#39;s UPI topology, potentially disrupting network operations or gaining unauthorized access to sensitive network configuration.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/internal/sbi/server.go
+++ b/internal/sbi/server.go
@@ -74,6 +74,10 @@ func newRouter(s *Server) *gin.Engine {
 
 	upiGroup := router.Group(factory.UpiUriPrefix)
+	upiAuthCheck := util_oauth.NewRouterAuthorizationCheck(models.ServiceName_NSMF_OAM)
+	upiGroup.Use(func(c *gin.Context) {
+		upiAuthCheck.Check(c, smf_context.GetSelf())
+	})
 	upiRoutes := s.getUPIRoutes()
 	applyRoutes(upiGroup, upiRoutes)</pre>
</details>
<p><b>Fix</b> : The patch introduces an authentication check for the UPI management interface. It adds a new router authorization check using `util_oauth.NewRouterAuthorizationCheck` and applies it as middleware to the `upiGroup` router, ensuring all requests to this interface are authenticated.</p>
<p>
<a href="https://github.com/advisories/GHSA-3258-qmv8-frp3">Advisory</a> · <a href="https://github.com/free5gc/smf/commit/e23ce97565f285eb99eed153743c62bf4c767c6e">Commit</a>
</p>
<hr>
<h3>GHSA-q6mh-rqwh-g786</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-05-07 · Go<br>
<code>github.com/enchant97/note-mark/backend</code> · Pattern: <code>INSECURE_DEFAULT→CONFIG</code> · 15x across ecosystem
</p>
<p><b>Root cause</b> : The application allowed a JWT secret to be configured without a minimum length validation. This meant that a short, easily guessable secret could be used, making JWT tokens vulnerable to brute-force attacks.</p>
<p><b>Impact</b> : An attacker could brute-force the weak JWT secret, forge valid authentication tokens, and achieve full account takeover for any user, including administrative accounts.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">-	JWTSecret                 Base64Decoded `env:&#34;JWT_SECRET,notEmpty&#34;`
+	JWTSecret                 Base64Decoded `env:&#34;JWT_SECRET,notEmpty&#34; validate:&#34;gte=32&#34;`</pre>
</details>
<p><b>Fix</b> : The patch adds a validation rule to the `JWTSecret` configuration field, ensuring that the secret must have a minimum length of 32 characters. This significantly increases the entropy and makes brute-forcing infeasible.</p>
<p>
<a href="https://github.com/advisories/GHSA-q6mh-rqwh-g786">Advisory</a> · <a href="https://github.com/enchant97/note-mark/commit/18b58775866776ed400c403dd0ccad68c1fa4802">Commit</a>
</p>
<hr>
<h3>GHSA-246w-jgmq-88fg</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-04-22 · Go<br>
<code>github.com/jkroepke/openvpn-auth-oauth2</code> · Pattern: <code>MISSING_AUTH→ENDPOINT</code> · 32x across ecosystem
</p>
<p><b>Root cause</b> : The application incorrectly returned &#39;FUNC_SUCCESS&#39; even when a client&#39;s authentication was explicitly denied or an error occurred during the authentication process. This misinterpretation of the return code by OpenVPN led to clients being granted access despite failing authentication.</p>
<p><b>Impact</b> : An attacker could gain unauthorized access to the VPN without providing valid credentials, effectively bypassing the entire authentication mechanism.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/lib/openvpn-auth-oauth2/openvpn/handle.go
+++ b/lib/openvpn-auth-oauth2/openvpn/handle.go
@@ -144,7 +144,7 @@ func (p *PluginHandle) handleAuthUserPassVerify(clientEnvList **c.Char, perClien
 					slog.Any(&#34;err&#34;, err),
 			)
-			return c.OpenVPNPluginFuncSuccess
+			return c.OpenVPNPluginFuncError
 	case management.ClientAuthPending:
 		pendingRespCh, err := p.managementClient.RegisterPendingPoller(currentClientID)</pre>
</details>
<p><b>Fix</b> : The patch changes the return value from &#39;c.OpenVPNPluginFuncSuccess&#39; to &#39;c.OpenVPNPluginFuncError&#39; when a client&#39;s authentication is denied or an error occurs during the process. This ensures that OpenVPN correctly interprets the authentication failure and denies access.</p>
<p>
<a href="https://github.com/advisories/GHSA-246w-jgmq-88fg">Advisory</a> · <a href="https://github.com/jkroepke/openvpn-auth-oauth2/commit/36f69a6c67c1054da7cbfa04ced3f0555127c8f2">Commit</a>
</p>
<hr>
<h3>GHSA-gph2-j4c9-vhhr</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-04-14 · PHP<br>
<code>wwbn/avideo</code> · Pattern: <code>UNSANITIZED_INPUT→XSS</code> · 61x across ecosystem
</p>
<p><b>Root cause</b> : The application&#39;s WebSocket broadcast relay allowed unauthenticated users to inject arbitrary JavaScript code into messages. Specifically, the &#39;autoEvalCodeOnHTML&#39; field and the &#39;callback&#39; field in WebSocket messages were not properly sanitized or validated before being relayed to other clients, which would then execute the injected code via client-side eval() sinks.</p>
<p><b>Impact</b> : An attacker could achieve unauthenticated cross-user JavaScript execution, leading to session hijacking, data theft, defacement, or other malicious activities on the client-side for any user connected to the WebSocket.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">-                //_log_message(&#34;onMessage:msgObj: &#34; . json_encode($json));
+                //_log_message(&#34;onMessage:msgObj: &#34; . json_encode($json));
+                // Strip eval-able fields from browser/guest messages.
+                if (empty($msgObj-&gt;isCommandLineInterface) &amp;&amp; ($msgObj-&gt;sentFrom ?? &#39;&#39;) !== &#39;php&#39;) {
+                    if (is_array($json[&#39;msg&#39;] ?? null)) {
+                        unset($json[&#39;msg&#39;][&#39;autoEvalCodeOnHTML&#39;]);
+                    }
+                    if (isset($json[&#39;callback&#39;]) &amp;&amp; !preg_match(&#39;/^[a-zA-Z_][a-zA-Z0-9_]*$/&#39;, (string)$json[&#39;callback&#39;])) {
+                        unset($json[&#39;callback&#39;]);
+                    }
+                }
                 if (!empty($msgObj-&gt;send_to_uri_pattern)) {
                     $this-&gt;msgToSelfURI($json, $msgObj-&gt;send_to_uri_pattern);
                 } else if (!empty($json[&#39;resourceId&#39;])) {</pre>
</details>
<p><b>Fix</b> : The patch introduces input validation and sanitization for WebSocket messages. It specifically removes the &#39;autoEvalCodeOnHTML&#39; field from messages originating from browsers or guests and ensures that the &#39;callback&#39; field, if present, adheres to a strict alphanumeric and underscore pattern, effectively preventing arbitrary JavaScript injection.</p>
<p>
<a href="https://github.com/advisories/GHSA-gph2-j4c9-vhhr">Advisory</a> · <a href="https://github.com/WWBN/AVideo/commit/c08694bf6264eb4decceb78c711baee2609b4efd">Commit</a>
</p>
<hr>
<h3>GHSA-9cp7-j3f8-p5jx</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-04-10 · Go<br>
<code>github.com/daptin/daptin</code> · Pattern: <code>PATH_TRAVERSAL→FILE_WRITE</code> · 26x across ecosystem
</p>
<p><b>Root cause</b> : The application allowed user-supplied filenames and archive entry names to be used directly in file system operations (e.g., `filepath.Join`, `os.OpenFile`, `os.MkdirAll`) without sufficient sanitization. This enabled attackers to manipulate file paths using `../` sequences or absolute paths.</p>
<p><b>Impact</b> : An unauthenticated attacker could write arbitrary files to arbitrary locations on the server&#39;s file system, potentially leading to remote code execution, data corruption, or denial of service. In the case of Zip Slip, files within an uploaded archive could be extracted outside the intended directory.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/server/asset_upload_handler.go
+++ b/server/asset_upload_handler.go
@@ -67,6 +67,13 @@ func AssetUploadHandler(cruds map[string]*resource.DbResource) func(c *gin.Conte
 			c.AbortWithError(400, errors.New(&#34;filename query parameter is required&#34;))
 			return
 		}
+		// Strip path traversal from filename
+		if fileName != &#34;&#34; {
+			fileName = filepath.Clean(fileName)
+			for strings.HasPrefix(fileName, &#34;..&#34;) {
+				fileName = strings.TrimPrefix(strings.TrimPrefix(fileName, &#34;..&#34;), string(filepath.Separator))
+			}
+		}
 		// Validate table and column
 		dbResource, ok := cruds[typeName]
 		if !ok || dbResource == nil {</pre>
</details>
<p><b>Fix</b> : The patch introduces robust path sanitization by using `filepath.Clean` and then iteratively stripping any leading `..` components from user-supplied filenames and archive entry names. This ensures that all file system operations are constrained to the intended directories.</p>
<p>
<a href="https://github.com/advisories/GHSA-9cp7-j3f8-p5jx">Advisory</a> · <a href="https://github.com/daptin/daptin/commit/8d626bbb14f82160a08cbca53e0749f475f5742c">Commit</a>
</p>
<hr>
<h3>GHSA-fvcv-3m26-pcqx</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-04-10 · JavaScript<br>
<code>axios</code> · Pattern: <code>UNSANITIZED_INPUT→HEADER</code> · 9x across ecosystem
</p>
<p><b>Root cause</b> : The Axios library did not properly sanitize header values, allowing newline characters (CRLF) to be injected. This meant that an attacker could append arbitrary headers or even inject a new HTTP request body by including these characters in a user-controlled header value.</p>
<p><b>Impact</b> : An attacker could inject arbitrary HTTP headers, potentially leading to SSRF (Server-Side Request Forgery) against cloud metadata endpoints or other internal services, and could also manipulate the request body.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/lib/core/AxiosHeaders.js
+++ b/lib/core/AxiosHeaders.js
@@ -5,18 +5,49 @@ import parseHeaders from &#39;../helpers/parseHeaders.js&#39;;
 
 const $internals = Symbol(&#39;internals&#39;);
 
+const isValidHeaderValue = (value) =&gt; !/[
]/.test(value);
+
+function assertValidHeaderValue(value, header) {
+  if (value === false || value == null) {
+    return;
+  }
+
+  if (utils.isArray(value)) {
+    value.forEach((v) =&gt; assertValidHeaderValue(v, header));
+    return;
+  }
+
+  if (!isValidHeaderValue(String(value))) {
+    throw new Error(`Invalid character in header content [&#34;${header}&#34;]`);
+  }
+}
 
 function normalizeValue(value) {
   if (value === false || value == null) {
     return value;
   }
 
-  return utils.isArray(value)
-    ? value.map(normalizeValue)
-    : String(value).replace(/[
]+$/, &#39;&#39;);
+  return utils.isArray(value) ? value.map(normalizeValue) : stripTrailingCRLF(String(value));
 }
 
 function parseTokens(str) {
@@ -98,6 +129,7 @@ class AxiosHeaders {
         _rewrite === true ||
         (_rewrite === undefined &amp;&amp; self[key] !== false)
       ) {
+        assertValidHeaderValue(_value, _header);
         self[key || _header] = normalizeValue(_value);
       }
     }</pre>
</details>
<p><b>Fix</b> : The patch introduces a `isValidHeaderValue` function to explicitly check for and disallow newline characters (CRLF) in header values. It also adds an `assertValidHeaderValue` function to enforce this validation before header values are set, preventing header injection.</p>
<p>
<a href="https://github.com/advisories/GHSA-fvcv-3m26-pcqx">Advisory</a> · <a href="https://github.com/axios/axios/commit/363185461b90b1b78845dc8a99a1f103d9b122a1">Commit</a>
</p>
<hr>
<h3>GHSA-gx55-f84r-v3r7</h3>
<p>
<code>CRITICAL 9.9</code> · 2026-06-30 · Go<br>
<code>github.com/fission/fission</code> · Pattern: <code>UNCLASSIFIED</code> · 192x across ecosystem
</p>
<p><b>Root cause</b> : </p>
<p><b>Impact</b> : </p>
<p><b>Fix</b> : </p>
<p>
<a href="https://github.com/advisories/GHSA-gx55-f84r-v3r7">Advisory</a> · <a href="https://github.com/fission/fission/commit/e484df8460bb4e8026e24210120602aa7f181f64">Commit</a>
</p>
<hr>
<h3>GHSA-m63v-2g9w-2w6v</h3>
<p>
<code>CRITICAL 9.9</code> · 2026-06-30 · Go<br>
<code>github.com/fission/fission</code> · Pattern: <code>PRIVILEGE_ESCALATION→ROLE</code> · 25x across ecosystem
</p>
<p><b>Root cause</b> : The Fission platform allowed users to specify container configurations for environments (Runtime.Container and Builder.Container) that were not subject to the same security context validation as standard PodSpecs. This oversight meant that dangerous security settings like &#39;privileged=true&#39; or &#39;allowPrivilegeEscalation=true&#39; could be set in these specific container fields, bypassing existing security checks.</p>
<p><b>Impact</b> : An attacker could create privileged pods within the Kubernetes cluster, effectively escaping the container sandbox and gaining root-level access to the host or other cluster resources, leading to full cluster compromise.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/pkg/apis/core/v1/validation.go
+++ b/pkg/apis/core/v1/validation.go
 	errs = errors.Join(errs, ValidatePodSpecSafety(&#34;Environment.spec.runtime.podspec&#34;, e.Spec.Runtime.PodSpec))
 	errs = errors.Join(errs, ValidatePodSpecSafety(&#34;Environment.spec.builder.podspec&#34;, e.Spec.Builder.PodSpec))
+	errs = errors.Join(errs, ValidateContainerSafety(&#34;Environment.spec.runtime.container&#34;, e.Spec.Runtime.Container))
+	errs = errors.Join(errs, ValidateContainerSafety(&#34;Environment.spec.builder.container&#34;, e.Spec.Builder.Container))
 	return errs</pre>
</details>
<p><b>Fix</b> : The patch introduces a new `ValidateContainerSafety` function to explicitly check the security context of individual containers, specifically applying it to the previously unchecked `Runtime.Container` and `Builder.Container` fields in the Environment CRD. Additionally, a sanitization step is added during container merging to strip dangerous security context settings, providing a defense-in-depth measure even if admission webhooks are bypassed.</p>
<p>
<a href="https://github.com/advisories/GHSA-m63v-2g9w-2w6v">Advisory</a> · <a href="https://github.com/fission/fission/commit/695d3e97e3a20463ab7c8c081843e69e65e952e5">Commit</a>
</p>
<hr>
<h3>GHSA-v455-mv2v-5g92</h3>
<p>
<code>CRITICAL 9.9</code> · 2026-06-30 · Go<br>
<code>github.com/fission/fission</code> · Pattern: <code>UNCLASSIFIED</code> · 192x across ecosystem
</p>
<p><b>Root cause</b> : </p>
<p><b>Impact</b> : </p>
<p><b>Fix</b> : </p>
<p>
<a href="https://github.com/advisories/GHSA-v455-mv2v-5g92">Advisory</a> · <a href="https://github.com/fission/fission/commit/e484df8460bb4e8026e24210120602aa7f181f64">Commit</a>
</p>
<hr>
<h3>GHSA-wmgg-3p4h-48x7</h3>
<p>
<code>CRITICAL 9.9</code> · 2026-06-30 · Go<br>
<code>github.com/fission/fission</code> · Pattern: <code>UNCLASSIFIED</code> · 192x across ecosystem
</p>
<p><b>Root cause</b> : </p>
<p><b>Impact</b> : </p>
<p><b>Fix</b> : </p>
<p>
<a href="https://github.com/advisories/GHSA-wmgg-3p4h-48x7">Advisory</a> · <a href="https://github.com/fission/fission/commit/8fa799417c77ce8a0189d9858bfe11ece29b84a6">Commit</a>
</p>
<hr>
<h3>GHSA-9v98-6g37-x9g6</h3>
<p>
<code>CRITICAL 9.9</code> · 2026-06-26 · JavaScript<br>
<code>@deepstream/server</code> · Pattern: <code>UNCLASSIFIED</code> · 192x across ecosystem
</p>
<p><b>Root cause</b> : </p>
<p><b>Impact</b> : </p>
<p><b>Fix</b> : </p>
<p>
<a href="https://github.com/advisories/GHSA-9v98-6g37-x9g6">Advisory</a> · <a href="https://github.com/deepstreamIO/deepstream.io/commit/54b8e2958a98df444b5b5d9a66e22872afd84e44">Commit</a>
</p>
<hr>
<h3>GHSA-qf6p-p7ww-cwr9</h3>
<p>
<code>CRITICAL 9.9</code> · 2026-06-23 · Go<br>
<code>gogs.io/gogs</code> · Pattern: <code>UNCLASSIFIED</code> · 192x across ecosystem
</p>
<p><b>Root cause</b> : </p>
<p><b>Impact</b> : </p>
<p><b>Fix</b> : </p>
<p>
<a href="https://github.com/advisories/GHSA-qf6p-p7ww-cwr9">Advisory</a> · <a href="https://github.com/gogs/gogs/commit/a9dbafbfd8e1020bacc626420238c01d75d03364">Commit</a>
</p>
<hr>
<h3>GHSA-5pm9-r2m8-rcmj</h3>
<p>
<code>CRITICAL 9.9</code> · 2026-06-22 · PHP<br>
<code>paymenter/paymenter</code> · Pattern: <code>UNCLASSIFIED</code> · 192x across ecosystem
</p>
<p><b>Root cause</b> : The application allowed users to upload files via the EasyMDE editor in ticket creation and viewing forms. The `completeUpload` method in Livewire components directly stored these uploaded files without sufficient validation of their content or type, allowing an attacker to upload malicious executable files.</p>
<p><b>Impact</b> : An attacker could upload a malicious file (e.g., a PHP script) to the server and then execute it, leading to full compromise of the server.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/themes/default/views/components/easymde-editor.blade.php
+++ b/themes/default/views/components/easymde-editor.blade.php
@@ -8,7 +8,7 @@
             element: document.getElementById(&#39;editor&#39;),
             spellChecker: false,
             previewImagesInEditor: true,
-            uploadImage: true,
+            uploadImage: false,
             autoDownloadFontAwesome: false,
             status: [{
                 className: &#39;upload-image&#39;,
@@ -45,11 +45,6 @@ className: &#39;upload-image&#39;,
                     name: &#39;ordered-list&#39;,
                     action: EasyMDE.toggleOrderedList,
                 }, &#39;|&#39;,
-                {
-                    name: &#39;upload-image&#39;,
-                    action: EasyMDE.drawUploadedImage,
-                    title: &#39;Upload Image&#39;,
-                }, &#39;|&#39;,
                 {
                     name: &#39;undo&#39;,
                     action: EasyMDE.undo,
@@ -59,13 +54,6 @@ className: &#39;upload-image&#39;,
                 },
 
             ],
-            imageUploadFunction: async (file, onSuccess, onError) =&gt; {
-                @this.upload(&#39;attachments&#39;, file, (url) =&gt; {
-                    @this.completeUpload(url).then((url) =&gt; {
-                        onSuccess(url);
-                    });
-                });
-            },
         });</pre>
</details>
<p><b>Fix</b> : The patch removes the file upload functionality from the EasyMDE editor in ticket forms by disabling the `uploadImage` option and removing the associated `imageUploadFunction`. It also removes the `WithFileUploads` trait and related attachment handling logic from the Livewire components, effectively preventing any file uploads through these interfaces.</p>
<p>
<a href="https://github.com/advisories/GHSA-5pm9-r2m8-rcmj">Advisory</a> · <a href="https://github.com/Paymenter/Paymenter/commit/87c3db42282ada1e3cda54b9a01f846926c0669b">Commit</a>
</p>
<hr>
<h3>GHSA-jvc5-6g7q-c843</h3>
<p>
<code>CRITICAL 9.9</code> · 2026-06-09 · PHP<br>
<code>pheditor/pheditor</code> · Pattern: <code>UNSANITIZED_INPUT→COMMAND</code> · 43x across ecosystem
</p>
<p><b>Root cause</b> : The application was directly embedding user-supplied input from the &#39;dir&#39; parameter into a shell command without proper sanitization. This allowed an attacker to inject arbitrary shell commands by manipulating the &#39;dir&#39; value.</p>
<p><b>Impact</b> : An attacker could execute arbitrary operating system commands on the server, leading to full system compromise, data exfiltration, or denial of service.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">-                $output = shell_exec((empty($dir) ? null : &#39;cd &#39; . $dir . &#39; &amp;&amp; &#39;) . $command . &#39; &amp;&amp; echo \ ; pwd&#39;);
+                $output = shell_exec((empty($dir) ? null : &#39;cd &#39; . escapeshellarg($dir) . &#39; &amp;&amp; &#39;) . $command . &#39; &amp;&amp; echo \ ; pwd&#39;);</pre>
</details>
<p><b>Fix</b> : The patch addresses the vulnerability by wrapping the user-supplied &#39;dir&#39; parameter with `escapeshellarg()` before it is used in the `shell_exec()` function. This ensures that any special characters in the &#39;dir&#39; value are properly escaped, preventing command injection.</p>
<p>
<a href="https://github.com/advisories/GHSA-jvc5-6g7q-c843">Advisory</a> · <a href="https://github.com/pheditor/pheditor/commit/62b43df7cb8956a9b0deb9bec278ca8676c890c5">Commit</a>
</p>
<hr>
<h3>GHSA-598g-h2vc-h5vg</h3>
<p>
<code>CRITICAL 9.9</code> · 2026-06-08 · Go<br>
<code>github.com/juev/nebula-mesh</code> · Pattern: <code>PRIVILEGE_ESCALATION→ROLE</code> · 25x across ecosystem
</p>
<p><b>Root cause</b> : The application used a cached context value for `actorIsAdmin` checks, which meant that if an operator&#39;s role was downgraded from &#39;admin&#39; to a regular user, their active session would still incorrectly reflect them as an administrator. This allowed them to bypass authorization checks on various API endpoints.</p>
<p><b>Impact</b> : An attacker could maintain administrative privileges even after their role was revoked, enabling them to perform actions such as managing other operators, accessing audit logs, listing all CAs, and other sensitive operations that should be restricted to active administrators.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/internal/api/authz.go
+++ b/internal/api/authz.go
@@ -8,10 +8,29 @@ import (
 	&#34;github.com/juev/nebula-mesh/internal/store&#34;
 )
 
+// isActiveAdmin re-fetches the captured-ctx actor and reports whether
+// they are still an active admin.
+func (s *Server) isActiveAdmin(ctx context.Context) bool {
+	captured := ActorOf(ctx)
+	if captured == nil {
+		return false
+	}
+	fresh, err := s.store.GetOperator(ctx, captured.ID)
+	if err != nil {
+		if !errors.Is(err, store.ErrNotFound) {
+			s.logger.Error(&#34;isActiveAdmin: store lookup&#34;, &#34;operator&#34;, captured.ID, &#34;error&#34;, err)
+		}
+		return false
+	}
+	return fresh.Status == models.OperatorStatusActive &amp;&amp; fresh.Role == &#34;admin&#34;
+}
+
 // actorOwnsCA returns true if the actor in ctx is admin, or owns the CA with caID.
 // Returns (false, nil) for empty caID or ErrNotFound. Errors only for unexpected DB errors.
 func (s *Server) actorOwnsCA(ctx context.Context, caID string) (bool, error) {
-	if actorIsAdmin(ctx) {
+	if s.isActiveAdmin(ctx) {
 		return true, nil
 	}
 	if caID == &#34;&#34;,</pre>
</details>
<p><b>Fix</b> : A new function `isActiveAdmin` was introduced to re-fetch the operator&#39;s status and role directly from the database for each authorization check. All calls to the old `actorIsAdmin` function were replaced with `s.isActiveAdmin(ctx)` to ensure that administrative checks are always based on the most current operator status.</p>
<p>
<a href="https://github.com/advisories/GHSA-598g-h2vc-h5vg">Advisory</a> · <a href="https://github.com/forgekeep/nebula-mesh/commit/9d8bcd7667ecd0c2975cc71fb35a02fe131f76f2">Commit</a>
</p>
<hr>
<h3>GHSA-fqvv-jvhr-g5jc</h3>
<p>
<code>CRITICAL 9.9</code> · 2026-05-05 · Python<br>
<code>firefighter-incident</code> · Pattern: <code>SSRF→CLOUD_METADATA</code> · 1x across ecosystem
</p>
<p><b>Root cause</b> : The application&#39;s `jira_bot` endpoint allowed unauthenticated users to provide arbitrary URLs for attachments. These URLs were then fetched by the server without proper validation, enabling an attacker to direct the server to make requests to internal network resources or cloud metadata endpoints.</p>
<p><b>Impact</b> : An attacker could perform Server-Side Request Forgery (SSRF) attacks, leading to the theft of IAM credentials or access to other sensitive internal services and data.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/src/firefighter/raid/serializers.py
+++ b/src/firefighter/raid/serializers.py
@@ -56,6 +59,58 @@
 logger = logging.getLogger(__name__)
 
 
+ATTACHMENT_MAX_COUNT = 10
+ATTACHMENT_URL_MAX_LENGTH = 2048
+ATTACHMENT_ALLOWED_SCHEMES = frozenset({&#34;http&#34;, &#34;https&#34;})
+
+
+def parse_attachment_urls(raw: str | None) -&gt; list[str]:
+    &#34;&#34;&#34;Normalise the attachments payload sent by Landbot into a list of URLs.
+
+    Landbot historically sends a Python-stringified list (e.g. ``&#34;[&#39;https://a&#39;, &#39;https://b&#39;]&#34;``)
+    rather than a JSON array. This helper tolerates that legacy format along with
+    a plain comma-separated string or a single URL.
+    &#34;&#34;&#34;
+    if not raw:
+        return []
+    stripped = raw.replace(&#34;[&#34;, &#34;&#34;).replace(&#34;]&#34;, &#34;&#34;).replace(&#34;&#39;&#34;, &#34;&#34;).replace(&#39;&#34;&#39;, &#34;&#34;)
+    return [item.strip() for item in stripped.split(&#34;,&#34;) if item.strip()]
+
+
+def _validate_attachment_url(url: str) -&gt; None:
+    if len(url) &gt; ATTACHMENT_URL_MAX_LENGTH:
+        msg = f&#34;Attachment URL exceeds {ATTACHMENT_URL_MAX_LENGTH} characters.&#34;
+        raise serializers.ValidationError(msg)
+    parsed = urlparse(url)
+    if parsed.scheme not in ATTACHMENT_ALLOWED_SCHEMES:
+        msg = f&#34;Attachment URL scheme &#39;{parsed.scheme}&#39; is not allowed.&#34;
+        raise serializers.ValidationError(msg)
+    host = parsed.hostname
+    if not host:
+        raise serializers.ValidationError(&#34;Attachment URL is missing a host.&#34;)
+    try:
+        addr_infos = socket.getaddrinfo(host, None)
+    except socket.gaierror as err:
+        msg = f&#34;Attachment URL host &#39;{host}&#39; could not be resolved.&#34;
+        raise serializers.ValidationError(msg) from err
+    # SSRF guard: reject any host resolving to a non-routable address so the
+    # fetch in add_attachments_to_issue can never reach internal services
+    # (cloud metadata endpoint, RFC1918 networks, loopback).
+    for info in addr_infos:
+        ip = ipaddress.ip_address(info[4][0])
+        if (
+            ip.is_private
+            or ip.is_loopback
+            or ip.is_link_local
+            or ip.is_reserved
+            or ip.is_multicast
+            or ip.is_unspecified
+        ):
+            raise serializers.ValidationError(
+                &#34;Attachment URL host resolves to a private, loopback or link-local address.&#34;
+            )
+
+
 class IgnoreEmptyStringListField(serializers.ListField):
     def to_internal_value(self, data: list[Any] | Any) -&gt; list[str]:
         # Check if data is a list</pre>
</details>
<p><b>Fix</b> : The patch introduces authentication for the `jira_bot` endpoint, requiring a bearer token. Additionally, it implements robust URL validation for attachments, including scheme checks, host resolution, and a critical SSRF guard that rejects URLs resolving to private, loopback, link-local, reserved, multicast, or unspecified IP addresses.</p>
<p>
<a href="https://github.com/advisories/GHSA-fqvv-jvhr-g5jc">Advisory</a> · <a href="https://github.com/ManoManoTech/firefighter-incident/commit/2586679e6f32c12d223668b73e98f4c4de7b771f">Commit</a>
</p>
<hr>
<h3>GHSA-2gr4-ppc7-7mhx</h3>
<p>
<code>CRITICAL 9.8</code> · 2026-06-11 · PHP<br>
<code>codeigniter4/framework</code> · Pattern: <code>UNCLASSIFIED</code> · 192x across ecosystem
</p>
<p><b>Root cause</b> : The vulnerability existed because the `ext_in` validation rule only checked the guessed file extension, which could be manipulated by an attacker. The `guessExtension()` method might return an empty string or an incorrect extension if the file&#39;s MIME type or content was malformed, allowing a malicious file with a dangerous extension (e.g., .php) to bypass the intended extension whitelist.</p>
<p><b>Impact</b> : An attacker could upload files with disallowed extensions, potentially leading to remote code execution if the server is configured to execute scripts based on their extension, or other forms of system compromise.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">-            if (! in_array($file-&gt;guessExtension(), $params, true)) {
+            $clientExtension = strtolower($file-&gt;getClientExtension());
+
+            if ($clientExtension === &#39;&#39; || ! in_array($clientExtension, $params, true)) {
+                return false;
+            }
+
+            if ($file-&gt;guessExtension() !== $clientExtension) {
                 return false;
             }</pre>
</details>
<p><b>Fix</b> : The patch enhances the `ext_in` validation rule by explicitly checking both the client-provided file extension (`getClientExtension()`) and comparing it with the guessed extension (`guessExtension()`). It ensures that the client extension is not empty and is part of the allowed list, and that the guessed extension matches the client extension, preventing bypasses through manipulated file types.</p>
<p>
<a href="https://github.com/advisories/GHSA-2gr4-ppc7-7mhx">Advisory</a> · <a href="https://github.com/codeigniter4/CodeIgniter4/commit/29299349e7d232e9532767c7cefaed30957309be">Commit</a>
</p>
<hr>
<h3>GHSA-6j2x-vhqr-qr7q</h3>
<p>
<code>CRITICAL 9.8</code> · 2026-05-29 · JavaScript<br>
<code>vm2</code> · Pattern: <code>TYPE_CONFUSION→BYPASS</code> · 3x across ecosystem
</p>
<p><b>Root cause</b> : The vm2 sandbox failed to properly isolate WebAssembly JavaScript Promise Integration (JSPI) Promises. These Promises, when created within the sandbox, had their prototype chain directly linked to the host realm&#39;s `Promise.prototype`, bypassing the sandbox&#39;s proxy mechanisms and overrides. This allowed an attacker to manipulate the `constructor` property of a JSPI Promise, leading to the creation of host-realm Promise resolution/rejection functions that executed attacker-controlled code in the host context.</p>
<p><b>Impact</b> : An attacker could execute arbitrary code in the host environment, effectively escaping the vm2 sandbox and gaining full control over the system running the sandboxed code.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/lib/setup-sandbox.js
+++ b/lib/setup-sandbox.js
@@ -473,6 +473,57 @@ if (typeof WebAssembly !== &#39;undefined&#39; &amp;&amp; WebAssembly.JSTag !== undefined) {
 	localReflectDeleteProperty(WebAssembly, &#39;JSTag&#39;);
 }
 
+if (typeof WebAssembly !== &#39;undefined&#39;) {
+	// SECURITY (GHSA-6j2x-vhqr-qr7q): WebAssembly.promising returns Promises with
+	// host-realm Promise.prototype in their [[Prototype]] chain. No sandbox-side
+	// override and no bridge proxy can intercept method dispatch on such objects.
+	if (typeof WebAssembly.promising !== &#39;undefined&#39;) {
+		localReflectDeleteProperty(WebAssembly, &#39;promising&#39;);
+	}
+	// SECURITY (GHSA-6j2x-vhqr-qr7q): WebAssembly.Suspending is required to satisfy
+	// the suspending-import slot in any JSPI module. Removing it alone closes the
+	// instantiation half of the chain; removing `.promising` closes the export half.
+	if (typeof WebAssembly.Suspending !== &#39;undefined&#39;) {
+		localReflectDeleteProperty(WebAssembly, &#39;Suspending&#39;);
+	}
+}
 
 if (
 	!localReflectDefineProperty(global, &#39;VMError&#39;, {</pre>
</details>
<p><b>Fix</b> : The patch removes `WebAssembly.promising` and `WebAssembly.Suspending` from the sandbox environment. By deleting these properties, the sandbox prevents the creation of JSPI Promises that exhibit the problematic cross-realm prototype behavior, thereby eliminating the attack vector.</p>
<p>
<a href="https://github.com/advisories/GHSA-6j2x-vhqr-qr7q">Advisory</a> · <a href="https://github.com/patriksimek/vm2/commit/6915fa4d9bcebd47b9a4f39a1adc1aa94ef6ffc6">Commit</a>
</p>
<hr>
<h3>GHSA-x7m9-mwc2-g6w2</h3>
<p>
<code>CRITICAL 9.8</code> · 2026-05-18 · PHP<br>
<code>verbb/formie</code> · Pattern: <code>UNSANITIZED_INPUT→TEMPLATE</code> · 3x across ecosystem
</p>
<p><b>Root cause</b> : The application was parsing the &#39;defaultValue&#39; of a hidden field as a Twig template even when the value was directly provided by the user. This allowed an attacker to inject malicious Twig template code into the &#39;defaultValue&#39; which would then be executed by the server.</p>
<p><b>Impact</b> : An unauthenticated attacker could achieve remote code execution on the server by injecting arbitrary Twig template code, leading to full system compromise.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/src/fields/formfields/Hidden.php
+++ b/src/fields/formfields/Hidden.php
@@ -111,11 +111,9 @@ public function serializeValue(mixed $value, ?ElementInterface $element = null):
 
             // Check if there&#39;s no value been added on the front-end, and use the default value
             if ($value === &#39;&#39;) {
-                $value = $this-&gt;defaultValue;
+                $value = Variables::getParsedValue($this-&gt;defaultValue, $element);
             }
 
-            $value = Variables::getParsedValue($value, $element);
-
             // Immediately update the value for the element, so integrations use the up-to-date value
             if ($element) {</pre>
</details>
<p><b>Fix</b> : The patch modifies the logic to ensure that the &#39;defaultValue&#39; is only parsed as a Twig template if the front-end value is empty. If a value is provided from the front-end, it is no longer passed through the template parser, preventing injection.</p>
<p>
<a href="https://github.com/advisories/GHSA-x7m9-mwc2-g6w2">Advisory</a> · <a href="https://github.com/verbb/formie/commit/f690d5623163ce2a95da305238d6367575486ee3">Commit</a>
</p>
<hr>
<h3>GHSA-248r-7h7q-cr24</h3>
<p>
<code>CRITICAL 9.8</code> · 2026-05-14 · JavaScript<br>
<code>vm2</code> · Pattern: <code>UNCLASSIFIED</code> · 192x across ecosystem
</p>
<p><b>Root cause</b> : The vm2 sandbox failed to properly sanitize values returned from async generator functions, specifically when an async generator&#39;s `yield*` delegates to an inner async iterator and a thenable&#39;s `.then` callback throws synchronously. V8&#39;s internal PromiseResolveThenableJob would capture this exception and deliver it to sandbox code as an iterator result, bypassing existing sanitization mechanisms for exceptions and promise rejections.</p>
<p><b>Impact</b> : An attacker could escape the vm2 sandbox, allowing them to execute arbitrary code in the host environment with the privileges of the Node.js process running the sandbox.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/lib/setup-sandbox.js
+++ b/lib/setup-sandbox.js
@@ -983,6 +983,381 @@ if (typeof bridge.setHostPromiseSanitizers === &#39;function&#39;) {
 	bridge.setHostPromiseSanitizers(e =&gt; handleException(from(e)), from);
 }
 
+// SECURITY (GHSA-248r-7h7q-cr24): Async generator yield*-return thenable
+// exception capture. When sandbox code calls `i.return(thenable)` on an
+// async generator that delegates via `yield*` to an inner async iterator
+// without a `return` method, V8&#39;s PromiseResolveThenableJob captures any
+// synchronous throw from the thenable&#39;s `.then` callback and the yield*
+// machinery delivers it to sandbox code as an iterator result
+// (`{ value: thrown, done: false }`). This bypasses (a) the transformer&#39;s
+// `catch`-block instrumentation (the catch is implicit in V8 internals)
+// and (b) the `globalPromise.prototype.then` rejection sanitizer above,
+// because internal `Await` uses `PerformPromiseThen` directly and never
+// invokes the user-visible `.then` override. Wrap
+// `%AsyncGeneratorPrototype%.next` / `.return` / `.throw` so every value
+// flowing out of an async generator into sandbox code is routed through
+// `handleException` — restoring the invariant that no host-realm value
+// can reach sandbox code without sanitization.
+let localAsyncGeneratorPrototype = null;</pre>
</details>
<p><b>Fix</b> : The patch wraps the `%AsyncGeneratorPrototype%.next`, `.return`, and `.throw` methods. This ensures that all values flowing out of an async generator into sandbox code are routed through `handleException` for sanitization. It also introduces robust handling for thenables passed to these methods, preventing various bypasses related to synchronous throws, nested thenables, and Time-of-Check to Time-of-Use (TOCTOU) attacks on `.then` getters.</p>
<p>
<a href="https://github.com/advisories/GHSA-248r-7h7q-cr24">Advisory</a> · <a href="https://github.com/patriksimek/vm2/commit/093494c0c3ef2390d2e56909f9d56e290e6f18b0">Commit</a>
</p>
<hr>
<h3>GHSA-vmw2-qwm8-x84c</h3>
<p>
<code>CRITICAL 9.8</code> · 2026-05-14 · C#<br>
<code>Marten</code> · Pattern: <code>UNSANITIZED_INPUT→SQL</code> · 16x across ecosystem
</p>
<p><b>Root cause</b> : The application directly interpolated the &#39;regConfig&#39; parameter into a SQL query without proper validation or sanitization. This allowed an attacker to inject arbitrary SQL commands by manipulating the &#39;regConfig&#39; value.</p>
<p><b>Impact</b> : An attacker could execute arbitrary SQL commands on the PostgreSQL database, potentially leading to data exfiltration, modification, or deletion, and even remote code execution depending on database privileges.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/src/Marten/Linq/SqlGeneration/Filters/FullTextWhereFragment.cs
+++ b/src/Marten/Linq/SqlGeneration/Filters/FullTextWhereFragment.cs
@@ -18,6 +31,8 @@ internal class FullTextWhereFragment: ISqlFragment
     public FullTextWhereFragment(DocumentMapping? mapping, FullTextSearchFunction searchFunction, string searchTerm,
         string regConfig = FullTextIndexDefinition.DefaultRegConfig)
     {
+        ValidateRegConfig(regConfig);
+
         _regConfig = regConfig;
 
         _dataConfig = GetDataConfig(mapping, regConfig).Replace(&#34;data&#34;, &#34;d.data&#34;);</pre>
</details>
<p><b>Fix</b> : The patch introduces a regular expression to validate the &#39;regConfig&#39; parameter. It ensures that &#39;regConfig&#39; only contains characters valid for a PostgreSQL text-search configuration name, rejecting any input that could lead to SQL injection.</p>
<p>
<a href="https://github.com/advisories/GHSA-vmw2-qwm8-x84c">Advisory</a> · <a href="https://github.com/JasperFx/marten/commit/626249656829860b9c55895b5b6046b61a2a695f">Commit</a>
</p>
<hr>
<h3>GHSA-xg82-2hrv-hf64</h3>
<p>
<code>CRITICAL 9.8</code> · 2026-05-08 · PHP<br>
<code>snipe/snipe-it</code> · Pattern: <code>MISSING_AUTHZ→RESOURCE</code> · 60x across ecosystem
</p>
<p><b>Root cause</b> : The application allowed users with &#39;view&#39; permissions on an object to upload files associated with that object. This is a weaker permission than &#39;update&#39;, which should be required for file uploads, leading to an authorization bypass for file modification.</p>
<p><b>Impact</b> : An attacker with only &#39;view&#39; permissions on an object could upload arbitrary files, potentially leading to remote code execution if the uploaded file is a malicious script (e.g., PHP file) and the server is configured to execute it.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">-	        $this-&gt;authorize(&#39;view&#39;, $object);
+	        $this-&gt;authorize(&#39;update&#39;, $object);</pre>
</details>
<p><b>Fix</b> : The patch changes the authorization check for file uploads from &#39;view&#39; to &#39;update&#39;. This ensures that only users with sufficient privileges to modify an object can upload files associated with it.</p>
<p>
<a href="https://github.com/advisories/GHSA-xg82-2hrv-hf64">Advisory</a> · <a href="https://github.com/grokability/snipe-it/commit/676a9958895a77de340565e7a0b17ae744664904">Commit</a>
</p>
<hr>
<h3>GHSA-8x35-hph8-37hq</h3>
<p>
<code>CRITICAL 9.8</code> · 2026-04-24 · JavaScript<br>
<code>electerm</code> · Pattern: <code>UNSANITIZED_INPUT→COMMAND</code> · 43x across ecosystem
</p>
<p><b>Root cause</b> : The original `runLinux` function used `exec` from `shelljs` to execute shell commands, constructing parts of the command string directly from unsanitized version information (`ver`) and folder names (`folderName`). An attacker could manipulate these inputs to inject arbitrary shell commands.</p>
<p><b>Impact</b> : An attacker could achieve arbitrary code execution on the system where the `electerm` package is being installed, potentially leading to full system compromise.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/npm/install.js
+++ b/npm/install.js
@@ -100,9 +100,27 @@
 }
 
 async function runLinux (folderName, filePattern) {
-  const ver = await getVer()
-  const target = resolve(__dirname, `../electerm-${ver.replace(&#39;v&#39;, &#39;&#39;)}-${folderName}`)
-  const targetNew = resolve(__dirname, &#39;../electerm&#39;)
-  exec(`rm -rf</pre>
</details>
<p><b>Fix</b> : The patch introduces `sanitizeVersion` and `sanitizeFilename` functions to validate and clean inputs before they are used in shell commands. It also replaces `exec` with `execSync` for synchronous execution and `execFile` for safer execution of specific binaries, avoiding direct shell command construction with untrusted input.</p>
<p>
<a href="https://github.com/advisories/GHSA-8x35-hph8-37hq">Advisory</a> · <a href="https://github.com/electerm/electerm/commit/59708b38c8a52f5db59d7d4eff98e31d573128ee">Commit</a>
</p>
<hr>
<h3>GHSA-xhj4-g6w8-2xjw</h3>
<p>
<code>CRITICAL 9.8</code> · 2026-04-24 · Go<br>
<code>github.com/woven-planet/go-zserio</code> · Pattern: <code>DOS→RESOURCE_EXHAUSTION</code> · 64x across ecosystem
</p>
<p><b>Root cause</b> : The application did not limit the size of arrays, byte buffers, or strings when deserializing data from a zserio bitstream. An attacker could provide a crafted input with an extremely large declared size, causing the application to attempt to allocate an unbounded amount of memory.</p>
<p><b>Impact</b> : An attacker could trigger a denial of service by causing the application to exhaust available memory, leading to crashes or system instability.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/ztype/array_decode.go
+++ b/ztype/array_decode.go
 	arraySize := array.FixedSize
 	
 	// Limit the initial capacity to a reasonable number to avoid excessive memory allocation.
 	// This is needed in case the input is untrusted could have an overly large value.
-	array.RawArray = make([]T, 0, arraySize)
+	if maxInitialArrayCapacityInt == 0 {
+		array.RawArray = make([]T, 0, arraySize)
+	} else {
+		array.RawArray = make([]T, 0, min(arraySize, maxInitialArrayCapacityInt))
+	}</pre>
</details>
<p><b>Fix</b> : The patch introduces maximum initial capacity limits for arrays, byte buffers, and strings during deserialization. These limits are configurable via environment variables (ZSERIO_MAX_INITIAL_ARRAY_SIZE, ZSERIO_MAX_INITIAL_BLOB_SIZE, ZSERIO_MAX_INITIAL_STRING_SIZE) and prevent excessive memory allocation based on untrusted input.</p>
<p>
<a href="https://github.com/advisories/GHSA-xhj4-g6w8-2xjw">Advisory</a> · <a href="https://github.com/woven-by-toyota/go-zserio/commit/39ef1decde7e9766207794d396018776b33c6e45">Commit</a>
</p>
<hr>
<h3>GHSA-9qhq-v63v-fv3j</h3>
<p>
<code>CRITICAL 9.8</code> · 2026-04-17 · Python<br>
<code>praisonai</code> · Pattern: <code>UNSANITIZED_INPUT→COMMAND</code> · 43x across ecosystem
</p>
<p><b>Root cause</b> : The code did not validate the executable part of the command input.</p>
<p><b>Impact</b> : An attacker could execute arbitrary commands on the server if they could control the `--mcp` argument.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before:
    cmd = parts[0]

After:
    basename = os.path.basename(cmd)
    if basename not in ALLOWED_MCP_COMMANDS:
        raise ValueError(...)</pre>
</details>
<p><b>Fix</b> : The patch adds a whitelist of allowed MCP command executables and raises an error if the provided command is not in this list.</p>
<p>
<a href="https://github.com/advisories/GHSA-9qhq-v63v-fv3j">Advisory</a> · <a href="https://github.com/MervinPraison/PraisonAI/commit/47bff65413beaa3c21bf633c1fae4e684348368c">Commit</a>
</p>
<hr>
<h3>GHSA-2689-5p89-6j3j</h3>
<p>
<code>CRITICAL 9.8</code> · 2026-04-16 · Python<br>
<code>uefi-firmware</code> · Pattern: <code>BUFFER_OVERFLOW→STACK</code> · 2x across ecosystem
</p>
<p><b>Root cause</b> : The `MakeTable` function, responsible for creating Huffman code mapping tables, did not adequately validate the `BitLen` array values. Specifically, it failed to check if `BitLen[Index]` exceeded 16 or if `Start[Len]` (calculated from `BitLen`) could lead to an out-of-bounds write when indexing the `Table` array, which is allocated on the stack.</p>
<p><b>Impact</b> : An attacker providing specially crafted compressed data could cause a stack out-of-bounds write, potentially leading to arbitrary code execution or denial of service by corrupting stack data or control flow.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/uefi_firmware/compression/Tiano/Decompress.c
+++ b/uefi_firmware/compression/Tiano/Decompress.c
@@ -208,14 +188,16 @@ Routine Description:
   }
 
   for (Index = 0; Index &lt; NumOfChar; Index++) {
+    if (BitLen[Index] &gt; 16) {
+      return (UINT16) BAD_TABLE;
+    }
     Count[BitLen[Index]]++;
   }
 
@@ -245,18 +227,20 @@ Routine Description:
 
     if (Len &lt;= TableBits) {
 
+      if (Start[Len] &gt;= NextCode || NextCode &gt; MaxTableLength) {
+        return (UINT16) BAD_TABLE;
+      }
+
       for (Index = Start[Len]; Index &lt; NextCode; Index++) {
-        if(Index &gt;= TableSize)
-        {
-          Sd-&gt;mBadAlgorithm = 1;
-          return (UINT16) BAD_TABLE;
-        } 
         Table[Index] = Char;
       }
+</pre>
</details>
<p><b>Fix</b> : The patch adds checks within the `MakeTable` function to ensure that `BitLen[Index]` does not exceed 16 and that calculated table indices (`Start[Len]`) do not go out of bounds of the `Table` array. It also removes the `mBadAlgorithm` flag and replaces it with a direct return of `BAD_TABLE` upon detection of an invalid table.</p>
<p>
<a href="https://github.com/advisories/GHSA-2689-5p89-6j3j">Advisory</a> · <a href="https://github.com/theopolis/uefi-firmware-parser/commit/bf3dfaa8a05675bae6ea0cbfa082ddcebfcde23e">Commit</a>
</p>
<hr>
<h3>GHSA-gvvw-8j96-8g5r</h3>
<p>
<code>CRITICAL 9.8</code> · 2026-04-16 · C#<br>
<code>Microsoft.Native.Quic.MsQuic.OpenSSL</code> · Pattern: <code>UNCLASSIFIED</code> · 192x across ecosystem
</p>
<p><b>Root cause</b> : The code did not properly validate the count value before using it, allowing an attacker to potentially elevate privileges.</p>
<p><b>Impact</b> : An attacker could exploit this vulnerability to perform actions that require higher privileges than intended.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before:
Largest -= (Block.Gap + 1);
Count = Block.AckBlock + 1;

After:
if (Count &gt; Largest + 1) {
    *InvalidFrame = TRUE;
    return FALSE;
}
Largest -= (Block.Gap + 1);
Count = Block.AckBlock + 1;</pre>
</details>
<p><b>Fix</b> : The patch adds a validation check to ensure that Count is within a safe range before proceeding with further operations, preventing potential privilege escalation.</p>
<p>
<a href="https://github.com/advisories/GHSA-gvvw-8j96-8g5r">Advisory</a> · <a href="https://github.com/microsoft/msquic/commit/1e6e999b199430effeefee3d85baa0c9dd35ad5e">Commit</a>
</p>
<hr>
<h3>GHSA-hm2w-vr2p-hq7w</h3>
<p>
<code>CRITICAL 9.8</code> · 2026-04-16 · Python<br>
<code>uefi-firmware</code> · Pattern: <code>BUFFER_OVERFLOW→HEAP</code> · 21x across ecosystem
</p>
<p><b>Root cause</b> : The vulnerability existed in the `MakeTable` function within the Tiano decompressor. Specifically, the `Table` array, which is used to store Huffman code mappings, could be written to beyond its allocated bounds if the calculated `Index` or `NextCode` values exceeded the expected `TableSize` (or `MaxTableLength`). This was due to insufficient bounds checking on the `Index` variable before writing to `Table[Index]`, particularly when `Len` was less than or equal to `TableBits`.</p>
<p><b>Impact</b> : An attacker could craft a malicious compressed UEFI firmware image that, when processed by the decompressor, would trigger a heap out-of-bounds write. This could lead to denial of service (crash), arbitrary code execution, or other memory corruption issues, compromising the integrity and security of the system&#39;s firmware.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/uefi_firmware/compression/Tiano/Decompress.c
+++ b/uefi_firmware/compression/Tiano/Decompress.c
@@ -208,14 +188,16 @@ Routine Description:
   }
 
   for (Index = 0; Index &lt; NumOfChar; Index++) {
+    if (BitLen[Index] &gt; 16) {
+      return (UINT16) BAD_TABLE;
+    }
     Count[BitLen[Index]]++;
   }
 
   // ... (lines omitted for brevity)
 
     if (Len &lt;= TableBits) {
 
+      if (Start[Len] &gt;= NextCode || NextCode &gt; MaxTableLength) {
+        return (UINT16) BAD_TABLE;
+      }
+
       for (Index = Start[Len]; Index &lt; NextCode; Index++) {
-        if(Index &gt;= TableSize)
-        {
-          Sd-&gt;mBadAlgorithm = 1;
-          return (UINT16) BAD_TABLE;
-        } 
         Table[Index] = Char;
       }
+
     } else {</pre>
</details>
<p><b>Fix</b> : The patch introduces explicit bounds checks within the `MakeTable` function. It now verifies that `BitLen[Index]` does not exceed 16 and that `Start[Len]` and `NextCode` remain within the `MaxTableLength` before writing to the `Table` array. Additionally, it removes the `mBadAlgorithm` flag and simplifies the `TableSize` calculation, ensuring that all writes to `Table` are within its allocated memory.</p>
<p>
<a href="https://github.com/advisories/GHSA-hm2w-vr2p-hq7w">Advisory</a> · <a href="https://github.com/theopolis/uefi-firmware-parser/commit/bf3dfaa8a05675bae6ea0cbfa082ddcebfcde23e">Commit</a>
</p>
<hr>
<h3>GHSA-cw73-5f7h-m4gv</h3>
<p>
<code>CRITICAL 9.8</code> · 2026-04-15 · Python<br>
<code>upsonic</code> · Pattern: <code>UNCLASSIFIED</code> · 192x across ecosystem
</p>
<p><b>Root cause</b> : The code snippet provided does not contain any obvious security vulnerabilities.</p>
<p><b>Impact</b> : No impact can be determined from the given code snippet.</p>
<p><b>Fix</b> : No fix is applicable as there are no known issues in the provided code.</p>
<p>
<a href="https://github.com/advisories/GHSA-cw73-5f7h-m4gv">Advisory</a> · <a href="https://github.com/Upsonic/Upsonic/commit/855053fce0662227d9246268ff4a0844b481a305">Commit</a>
</p>
<hr>
<h3>GHSA-jmrh-xmgh-x9j4</h3>
<p>
<code>CRITICAL 9.8</code> · 2026-04-06 · Python<br>
<code>changedetection.io</code> · Pattern: <code>MISSING_AUTH→ENDPOINT</code> · 32x across ecosystem
</p>
<p><b>Root cause</b> : The `login_optionally_required` decorator was moved above the route decorators, allowing unauthenticated access to routes that should be protected.</p>
<p><b>Impact</b> : An attacker could bypass authentication and perform actions they are not authorized to do, such as downloading backups or removing backup files.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before:
-    @login_optionally_required
    @backups_blueprint.route(&#34;/request-backup&#34;, methods=[&#39;GET&#39;])
After:
+    @backups_blueprint.route(&#34;/request-backup&#34;, methods=[&#39;GET&#39;])
+    @login_optionally_required</pre>
</details>
<p><b>Fix</b> : Moved the `login_optionally_required` decorator below all route decorators to ensure proper authentication checks.</p>
<p>
<a href="https://github.com/advisories/GHSA-jmrh-xmgh-x9j4">Advisory</a> · <a href="https://github.com/dgtlmoon/changedetection.io/commit/31a760c2147e3e73a403baf6d7de34dc50429c85">Commit</a>
</p>
<hr>
<h3>GHSA-8whc-2wmv-ww35</h3>
<p>
<code>CRITICAL 9.6</code> · 2026-06-04 · PHP<br>
<code>WWBN/AVideo</code> · Pattern: <code>UNSANITIZED_INPUT→XSS</code> · 61x across ecosystem
</p>
<p><b>Root cause</b> : The application was vulnerable to XSS because it directly used user-supplied input from &#39;webSocketSelfURI&#39; and &#39;page_title&#39; parameters in the client-side DOM without proper sanitization or validation. An attacker could inject malicious JavaScript through these parameters.</p>
<p><b>Impact</b> : An unauthenticated attacker could inject arbitrary JavaScript code into other users&#39; browsers, leading to session hijacking, defacement, data theft, or redirection to malicious sites.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/plugin/YPTSocket/MessageSQLiteV2.php
+++ b/plugin/YPTSocket/MessageSQLiteV2.php
@@ -89,12 +89,18 @@ public function onOpen(ConnectionInterface $conn)
         $client[&#39;yptDeviceId&#39;] = $json-&gt;yptDeviceId;
         $client[&#39;client&#39;] = deviceIdToObject($json-&gt;yptDeviceId);
         if (!empty($wsocketGetVars[&#39;webSocketSelfURI&#39;])) {
-            $client[&#39;selfURI&#39;] = $wsocketGetVars[&#39;webSocketSelfURI&#39;];
+            $rawURI = $wsocketGetVars[&#39;webSocketSelfURI&#39;];
+            // Only accept http/https URIs to prevent javascript: href injection
+            if (filter_var($rawURI, FILTER_VALIDATE_URL) &amp;&amp; preg_match(&#39;/^https?:\/\//i&#39;, $rawURI)) {
+                $client[&#39;selfURI&#39;] = $rawURI;
+            } else {
+                $client[&#39;selfURI&#39;] = $json-&gt;selfURI;
+            }
         } else {
             $client[&#39;selfURI&#39;] = $json-&gt;selfURI;
         }
         $client[&#39;isCommandLine&#39;] = @$wsocketGetVars[&#39;isCommandLine&#39;];
-        $client[&#39;page_title&#39;] = @utf8_encode(@$wsocketGetVars[&#39;page_title&#39;]);
+        $client[&#39;page_title&#39;] = htmlspecialchars((string)@$wsocketGetVars[&#39;page_title&#39;], ENT_QUOTES | ENT_HTML5, &#39;UTF-8&#39;);
         $client[&#39;ip&#39;] = $json-&gt;ip;
         if (!empty($json-&gt;location)) {</pre>
</details>
<p><b>Fix</b> : The patch addresses the vulnerability by sanitizing the &#39;page_title&#39; parameter using htmlspecialchars to prevent script injection. It also validates the &#39;webSocketSelfURI&#39; parameter to ensure it is a valid HTTP/HTTPS URL, preventing &#39;javascript:&#39; scheme injection.</p>
<p>
<a href="https://github.com/advisories/GHSA-8whc-2wmv-ww35">Advisory</a> · <a href="https://github.com/WWBN/AVideo/commit/8be71e53ccbe9b84b30870db386fb4d2b11e1c16">Commit</a>
</p>
<hr>
<h3>GHSA-v529-vhwc-wfc5</h3>
<p>
<code>CRITICAL 9.6</code> · 2026-04-23 · Ruby<br>
<code>openc3</code> · Pattern: <code>UNSANITIZED_INPUT→SQL</code> · 16x across ecosystem
</p>
<p><b>Root cause</b> : The application directly embedded user-controlled input (start_time, end_time, col_name) into SQL queries without proper sanitization or parameterization. This allowed an attacker to inject arbitrary SQL code by crafting malicious input values.</p>
<p><b>Impact</b> : An attacker could execute arbitrary SQL commands on the QuestDB time-series database, potentially leading to data exfiltration, modification, or deletion, and could even achieve remote code execution in some database configurations.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before:
query += &#34;WHERE T0.PACKET_TIMESECONDS &lt; &#39;#{start_time}&#39; LIMIT -1&#34;
result = @@conn.exec(query)

After:
query += &#34;WHERE T0.PACKET_TIMESECONDS &lt; $1 LIMIT -1&#34;
query_params &lt;&lt; start_time
result = @@conn.exec_params(query, query_params)</pre>
</details>
<p><b>Fix</b> : The patch modifies the `tsdb_lookup` and `create_table` methods in both Ruby and Python implementations to use parameterized queries. Instead of directly interpolating user input into the SQL string, placeholders ($1, $2 or %s) are used, and the values are passed as separate parameters to the database driver&#39;s `exec_params` or `execute` method.</p>
<p>
<a href="https://github.com/advisories/GHSA-v529-vhwc-wfc5">Advisory</a> · <a href="https://github.com/OpenC3/cosmos/commit/9ba60c09c8836a37a2e4ea67ab35fe403e041415">Commit</a>
</p>
<hr>
<h3>GHSA-6973-8887-87ff</h3>
<p>
<code>CRITICAL 9.6</code> · 2026-04-22 · RUST<br>
<code>nimiq-block</code> · Pattern: <code>INTEGER_OVERFLOW→BOUNDARY</code> · 8x across ecosystem
</p>
<p><b>Root cause</b> : The vulnerability stemmed from improper validation of `BitSet` indices representing validator slots. An attacker could craft a `BitSet` with out-of-range indices or indices that, when truncated to `u16`, would map to valid slots. This allowed them to bypass the quorum check for skip blocks and equivocation proofs by making it appear as if enough validators had signed, even if they hadn&#39;t.</p>
<p><b>Impact</b> : An attacker could forge valid skip blocks or equivocation proofs without the required supermajority of validator signatures. This could lead to a denial of service, allowing them to halt or disrupt the blockchain&#39;s consensus mechanism.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/primitives/block/src/multisig.rs
+++ b/primitives/block/src/multisig.rs
@@ -37,3 +37,14 @@ impl MultiSignature {
         }
     }
 }
+
+pub(crate) fn checked_signer_slots(signers: &amp;BitSet) -&gt; Option&lt;Vec&lt;u16&gt;&gt; {
+    let mut slots = Vec::with_capacity(signers.len());
+    for slot in signers.iter() {
+        if slot &gt;= Policy::SLOTS as usize || slot &gt; u16::MAX as usize {
+            return None;
+        }
+        slots.push(slot</pre>
</details>
<p><b>Fix</b> : The patch introduces a new `checked_signer_slots` function that rigorously validates `BitSet` indices. It ensures that all signer slots are within the allowed range (`Policy::SLOTS`) and do not exceed `u16::MAX` before processing them. This prevents out-of-range or truncated indices from being used to bypass quorum checks.</p>
<p>
<a href="https://github.com/advisories/GHSA-6973-8887-87ff">Advisory</a> · <a href="https://github.com/nimiq/core-rs-albatross/commit/d02059053181ed8ddad6b59a0adfd661ef5cd823">Commit</a>
</p>
<hr>
<h3>GHSA-8wrq-fv5f-pfp2</h3>
<p>
<code>CRITICAL 9.6</code> · 2026-04-10 · Python<br>
<code>lollms</code> · Pattern: <code>UNSANITIZED_INPUT→XSS</code> · 61x across ecosystem
</p>
<p><b>Root cause</b> : The application did not properly sanitize user-supplied content before storing it in the database and later rendering it. This allowed attackers to inject malicious scripts into posts, comments, and direct messages.</p>
<p><b>Impact</b> : An attacker could inject arbitrary client-side scripts, leading to session hijacking, defacement, redirection to malicious sites, or other client-side attacks against users viewing the compromised content.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/backend/routers/social/__init__.py
+++ b/backend/routers/social/__init__.py
@@ -149,9 +176,12 @@ def create_post(
     moderation_enabled = settings.get(&#34;ai_bot_moderation_enabled&#34;, False)
     initial_status = &#34;pending&#34; if moderation_enabled else &#34;validated&#34;
 
+    # Sanitize content to prevent Stored XSS
+    clean_content = sanitize_content(post_data.content)
+
     new_post = DBPost(
         author_id=current_user.id,
-        content=post_data.content,
+        content=clean_content,
         visibility=post_data.visibility,</pre>
</details>
<p><b>Fix</b> : The patch introduces a `sanitize_content` function using the `bleach` library to clean user input. This function is applied to all user-generated content (posts, comments, direct messages, and group conversation names) before it is stored in the database, stripping or escaping disallowed HTML tags and attributes.</p>
<p>
<a href="https://github.com/advisories/GHSA-8wrq-fv5f-pfp2">Advisory</a> · <a href="https://github.com/parisneo/lollms/commit/9767b882dbc893c388a286856beeaead69b8292a">Commit</a>
</p>
<hr>
<h3>GHSA-pxm6-mhxr-q4mj</h3>
<p>
<code>CRITICAL 9.4</code> · 2026-05-05 · PHP<br>
<code>getgrav/grav</code> · Pattern: <code>PRIVILEGE_ESCALATION→ROLE</code> · 25x across ecosystem
</p>
<p><b>Root cause</b> : The Grav user registration process lacked server-side validation for critical privilege-related fields like &#39;groups&#39; and &#39;access&#39;. This allowed an attacker to include these fields in their registration form submission, and the application would honor these values, effectively granting them elevated privileges.</p>
<p><b>Impact</b> : An attacker could register a new user account and assign themselves administrative or other high-privilege roles, leading to full control over the Grav instance.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/login.php
+++ b/login.php
@@ -1040,6 +1047,17 @@ private function processUserRegistration(FormInterface $form, Event $event): voi
                 }
             }
 
+            if (in_array($field, $privilegeFields, true)) {
+                if ($form_data-&gt;get($field) !== null) {
+                    $this-&gt;grav[&#39;log&#39;]-&gt;warning(sprintf(
+                        &#39;Login registration: ignored client-supplied &#34;%s&#34; from form submission (username=%s)&#39;,
+                        $field,
+                        is_string($username) ? $username : &#39;&lt;invalid&gt;&#39;
+                    ));
+                }
+                continue;
+            }
+
             if (!isset($data[$field]) &amp;&amp; $form_data-&gt;get($field)) {
                 $data[$field] = $form_data-&gt;get($field);
             }</pre>
</details>
<p><b>Fix</b> : The patch explicitly identifies &#39;groups&#39; and &#39;access&#39; as privilege fields and prevents them from being sourced directly from public registration form input. Any client-supplied values for these fields are now ignored, and a warning is logged.</p>
<p>
<a href="https://github.com/advisories/GHSA-pxm6-mhxr-q4mj">Advisory</a> · <a href="https://github.com/getgrav/grav-plugin-login/commit/3d419a0dabd70aed1fd49afcd5919004a4141da1">Commit</a>
</p>
<hr>
<h3>GHSA-fv26-4939-62fh</h3>
<p>
<code>CRITICAL 9.4</code> · 2026-05-04 · PHP<br>
<code>nabeel/phpvms</code> · Pattern: <code>MISSING_AUTH→ENDPOINT</code> · 32x across ecosystem
</p>
<p><b>Root cause</b> : The vulnerability existed because the /importer endpoint, which is responsible for importing data and can wipe the existing database, lacked proper authorization checks. This allowed any unauthenticated user to access and trigger the database wipe functionality.</p>
<p><b>Impact</b> : An attacker could completely wipe the entire database of the phpVMS installation, leading to a denial of service and significant data loss for the application owner.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- resources/views/system/importer/app.blade.php
+++ /dev/null
@@ -1,90 +0,0 @@
-&lt;!DOCTYPE html&gt;
-&lt;html lang=&#34;en&#34;&gt;

--- resources/views/system/importer/step1-configure.blade.php
+++ /dev/null
@@ -1,132 +0,0 @@
-@extends(&#39;system.importer.app&#39;)</pre>
</details>
<p><b>Fix</b> : The patch completely removes the vulnerable /importer functionality by deleting all associated view files. This eliminates the unauthorized access point and prevents the database wipe from being triggered by unauthenticated users.</p>
<p>
<a href="https://github.com/advisories/GHSA-fv26-4939-62fh">Advisory</a> · <a href="https://github.com/phpvms/phpvms/commit/f59ba8e0e8fc25c60c3faf14e526cfd49df3f7dc">Commit</a>
</p>
<hr>
<h3>GHSA-j98m-w3xp-9f56</h3>
<p>
<code>CRITICAL 9.4</code> · 2026-04-14 · Python<br>
<code>excel-mcp-server</code> · Pattern: <code>PATH_TRAVERSAL→FILE_READ</code> · 41x across ecosystem
</p>
<p><b>Root cause</b> : The code did not properly sanitize the input filename, allowing attackers to traverse directories and access files outside of the intended directory.</p>
<p><b>Impact</b> : An attacker could read or write arbitrary files on the server, potentially leading to data theft, unauthorized modifications, or other malicious activities.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before:
    return os.path.join(EXCEL_FILES_PATH, filename)

After:
    base = os.path.realpath(EXCEL_FILES_PATH)
    candidate = os.path.realpath(os.path.join(base, filename))
    if not _resolved_path_is_within(base, candidate):
        raise ValueError(f&#34;Invalid filename: {filename}, path escapes EXCEL_FILES_PATH&#34;)</pre>
</details>
<p><b>Fix</b> : The patch introduced a function `_resolved_path_is_within` to ensure that the resolved path is within the allowed directory. It also added checks to validate the filename and prevent absolute paths when not in SSE mode.</p>
<p>
<a href="https://github.com/advisories/GHSA-j98m-w3xp-9f56">Advisory</a> · <a href="https://github.com/haris-musa/excel-mcp-server/commit/f51340ecd5778952405044b203d3a2d4c8a46833">Commit</a>
</p>
<hr>
<h3>GHSA-65w6-pf7x-5g85</h3>
<p>
<code>CRITICAL 9.4</code> · 2026-04-08 · JavaScript<br>
<code>@delmaredigital/payload-puck</code> · Pattern: <code>MISSING_AUTH→ENDPOINT</code> · 32x across ecosystem
</p>
<p><b>Root cause</b> : The endpoints were missing proper authorization checks, allowing unauthenticated access to CRUD operations on Puck-registered collections.</p>
<p><b>Impact</b> : An attacker could perform any CRUD operation on the collections without authentication, potentially leading to data leakage or manipulation.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before:
-      const body = await req.json?.()
-      const { _locale } = body || {}
-      const locale = resolveLocale(req, _locale)

After:
+      const locale = resolveLocale(req)
+
+      const result = await req.payload.find({
+        collection: collection as CollectionSlug,
+        req,
+        overrideAccess: false,</pre>
</details>
<p><b>Fix</b> : The patch adds access control by passing `overrideAccess: false` and `req` to Payload&#39;s local API, ensuring that collection-level access rules are enforced.</p>
<p>
<a href="https://github.com/advisories/GHSA-65w6-pf7x-5g85">Advisory</a> · <a href="https://github.com/delmaredigital/payload-puck/commit/9148201c6bbfa140d44546438027a2f8a70f79a4">Commit</a>
</p>
<hr>
<h3>GHSA-jv46-xfwm-36j7</h3>
<p>
<code>CRITICAL 9.1</code> · 2026-06-26 · Erlang<br>
<code>relyra</code> · Pattern: <code>MISSING_VERIFICATION→SIGNATURE</code> · 27x across ecosystem
</p>
<p><b>Root cause</b> : The Relyra SAML library failed to cryptographically verify the SignatureValue element in SAML responses. While it performed checks like algorithm allowlisting and certificate trust, it did not actually perform the cryptographic signature validation against the signed content, allowing an attacker to forge SAML responses.</p>
<p><b>Impact</b> : An attacker could bypass authentication by crafting a malicious SAML response with a valid-looking but unverified signature, gaining unauthorized access to resources or impersonating legitimate users.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/lib/relyra/security/signature.ex
+++ b/lib/relyra/security/signature.ex
@@ -165,14 +167,24 @@ defmodule Relyra.Security.Signature do
          Error.new(:missing_signature, &#34;No signed node candidates were verified&#34;, details)}
 
       [candidate] -&gt;
-        {:ok,
-         %SignedNode{
-           xml_id: Map.get(candidate, :xml_id),
-           xpath: Map.get(candidate, :xpath),
-           signed_xml: Map.get(candidate, :signed_xml, &#34;&#34;),
-           signature_method: signature_method,
-           digest_method: digest_method
-         }}
+        with :ok &lt;- cryptographically_verify(candidate, signature_method, cert_chain, details) do
+          {:ok,
+           %SignedNode{
+             xml_id: Map.get(candidate, :xml_id),
+             xpath: Map.get(candidate, :xpath),
+             signed_xml: Map.get(candidate, :signed_xml, &#34;&#34;),
+             signature_method: signature_method,
+             digest_method: digest_method
+           }}
+        end</pre>
</details>
<p><b>Fix</b> : The patch introduces a new `cryptographically_verify` function that performs the actual cryptographic signature and digest validation. This function is called before building the `SignedNode`, ensuring that the SAML response&#39;s signature is properly verified against the provided certificate chain and canonicalized XML content.</p>
<p>
<a href="https://github.com/advisories/GHSA-jv46-xfwm-36j7">Advisory</a> · <a href="https://github.com/szTheory/relyra/commit/2e456897af3158c175bb490ce7fc51d6241c8922">Commit</a>
</p>
<hr>
<h3>GHSA-2933-q333-qg83</h3>
<p>
<code>CRITICAL 9.1</code> · 2026-06-25 · JavaScript<br>
<code>i18next-fs-backend</code> · Pattern: <code>PROTOTYPE_POLLUTION→OVERRIDE</code> · 12x across ecosystem
</p>
<p><b>Root cause</b> : The application&#39;s utility functions `getLastOfPath`, `setPath`, and `pushPath` did not properly sanitize user-controlled input used as object keys. This allowed an attacker to inject special keys like `__proto__`, `constructor`, or `prototype` into the object path, leading to modification of `Object.prototype`.</p>
<p><b>Impact</b> : An attacker could modify the properties of `Object.prototype`, which could lead to denial of service, remote code execution, or other severe impacts depending on the application&#39;s usage of JavaScript objects and their properties.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/lib/utils.js
+++ b/lib/utils.js
@@ -91,25 +91,30 @@ function getLastOfPath (object, path, Empty) {
     if (!object) return {}
 
     const key = cleanKey(stack.shift())
+    if (UNSAFE_KEYS.indexOf(key) &gt; -1) return {}
     if (!object[key] &amp;&amp; Empty) object[key] = new Empty()
     object = object[key]
   }
 
   if (!object) return {}
-  return {
-    obj: object,
-    k: cleanKey(stack.shift())
-  }
+  const k = cleanKey(stack.shift())
+  if (UNSAFE_KEYS.indexOf(k) &gt; -1) return {}
+  return { obj: object, k }
 }</pre>
</details>
<p><b>Fix</b> : The patch introduces a check for &#39;UNSAFE_KEYS&#39; (e.g., `__proto__`, `constructor`, `prototype`) within the `getLastOfPath` function. If an unsafe key is detected, the function now returns an empty object or `undefined`, preventing the traversal into or modification of `Object.prototype`.</p>
<p>
<a href="https://github.com/advisories/GHSA-2933-q333-qg83">Advisory</a> · <a href="https://github.com/i18next/i18next-fs-backend/commit/3ab0448087da6935a40117f904b7457281f963f4">Commit</a>
</p>
<hr>
<h3>GHSA-f49m-vf83-692w</h3>
<p>
<code>CRITICAL 9.1</code> · 2026-06-25 · JavaScript<br>
<code>i18next-http-middleware</code> · Pattern: <code>PROTOTYPE_POLLUTION→OVERRIDE</code> · 12x across ecosystem
</p>
<p><b>Root cause</b> : The `missingKeyHandler` in `i18next-http-middleware` did not adequately sanitize incoming keys from user requests. While it had a denylist for literal unsafe keys like `__proto__`, it failed to account for keys containing dotted segments (e.g., `__proto__.polluted`). When these keys were processed by backends that split them using a `keySeparator` (like `i18next-fs-backend`), the individual segments could then be used in an unguarded `setPath` operation, leading to prototype pollution.</p>
<p><b>Impact</b> : An attacker could manipulate object prototypes, potentially leading to denial of service, remote code execution in certain contexts, or other unexpected application behavior by injecting properties into `Object.prototype`.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/lib/index.js
+++ b/lib/index.js
@@ -311,12 +311,15 @@ export function missingKeyHandler (i18next, options = {}) {
     }
 
     const body = options.getBody(req)
+    const keySeparator = i18next.options &amp;&amp; i18next.options.keySeparator
 
-    // iterate only over own, non-prototype-polluting keys
+    // iterate only over own, non-prototype-polluting keys. The check also
+    // rejects dotted variants like `__proto__.polluted` whose segments under
+    // the configured keySeparator land on an unsafe key — see utils.js.
     const saveMissingKeys = src =&gt; {
       if (!src || typeof src !== &#39;object&#39;) return
       for (const m of Object.keys(src)) {
-        if (utils.UNSAFE_KEYS.indexOf(m) &gt; -1) continue
+        if (utils.hasUnsafeKeySegment(m, keySeparator)) continue
         i18next.services.backendConnector.saveMissing([lng], ns, m, src[m])
       }
     }</pre>
</details>
<p><b>Fix</b> : The patch introduces a new utility function `hasUnsafeKeySegment` that checks if any segment of a given key (when split by the configured `keySeparator`) matches an unsafe key. This function is then used in `missingKeyHandler` to reject any incoming keys that contain prototype-polluting segments, thus preventing the vulnerability.</p>
<p>
<a href="https://github.com/advisories/GHSA-f49m-vf83-692w">Advisory</a> · <a href="https://github.com/i18next/i18next-http-middleware/commit/7c6d26f137d3e940b8d229ca148bca38845faf49">Commit</a>
</p>
<hr>
<h3>GHSA-9m6g-wc8r-q59c</h3>
<p>
<code>CRITICAL 9.1</code> · 2026-06-22 · JavaScript<br>
<code>scim-patch</code> · Pattern: <code>PROTOTYPE_POLLUTION→OVERRIDE</code> · 12x across ecosystem
</p>
<p><b>Root cause</b> : The `scimPatch` function did not properly filter keys in patch paths, allowing an attacker to use special keys like `__proto__`, `constructor`, or `prototype`. This enabled the modification of `Object.prototype`, affecting all objects in the application.</p>
<p><b>Impact</b> : An attacker could inject or modify properties on `Object.prototype`, potentially leading to denial of service, remote code execution, or other arbitrary code execution scenarios depending on how the polluted properties are later used by the application.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/src/scimPatch.ts
+++ b/src/scimPatch.ts
@@ -68,6 +68,8 @@ const AUTHORIZED_OPERATION = [&#39;remove&#39;, &#39;add&#39;, &#39;replace&#39;];
 
 const CORE_SCHEMA_USER = &#39;urn:ietf:params:scim:schemas:core:2.0:User&#39;;
 const CORE_SCHEMA_GROUP = &#39;urn:ietf:params:scim:schemas:core:2.0:Group&#39;;
+// Keys that would let a patch reach Object.prototype (prototype pollution, GHSA-9m6g-wc8r-q59c).
+const DANGEROUS_KEYS = new Set([&#39;__proto__&#39;, &#39;constructor&#39;, &#39;prototype&#39;]);
 
 export const PATCH_OPERATION_SCHEMA = &#39;urn:ietf:params:scim:api:messages:2.0:PatchOp&#39;;
 /*
@@ -146,3 +148,10 @@ function validatePatchOperation(operation: ScimPatchOperation): void {
     }
     return paths;
 }
+
+    // Reject keys that would walk into Object.prototype (prototype pollution, GHSA-9m6g-wc8r-q59c).
+    for (const segment of paths) {
+        if (DANGEROUS_KEYS.has(segment)) {
+            throw new InvalidScimPatchOp(`Forbidden key in patch path: ${segment}`);
+        }
+    }</pre>
</details>
<p><b>Fix</b> : The patch introduces a `DANGEROUS_KEYS` set containing `__proto__`, `constructor`, and `prototype`. The `resolvePaths` function now explicitly checks if any segment in the SCIM patch path matches these dangerous keys and throws an `InvalidScimPatchOp` error if found, preventing prototype pollution.</p>
<p>
<a href="https://github.com/advisories/GHSA-9m6g-wc8r-q59c">Advisory</a> · <a href="https://github.com/thomaspoignant/scim-patch/commit/260f9cd2ac5ceac3976978850bb47dcb391720f6">Commit</a>
</p>
<hr>
<h3>GHSA-mqq6-462x-jxmm</h3>
<p>
<code>CRITICAL 9.1</code> · 2026-06-10 · Go<br>
<code>github.com/dhax/go-base</code> · Pattern: <code>UNCLASSIFIED</code> · 192x across ecosystem
</p>
<p><b>Root cause</b> : </p>
<p><b>Impact</b> : </p>
<p><b>Fix</b> : </p>
<p>
<a href="https://github.com/advisories/GHSA-mqq6-462x-jxmm">Advisory</a> · <a href="https://github.com/dhax/go-base/commit/cc82b9740fa6b08e0fad409cd4b418e240dd0e00">Commit</a>
</p>
<hr>
<h2 id="how-it-works">How it works</h2>
<pre>
06:00 UTC    Pull advisories (GitHub Advisory DB, GraphQL)
             Filter: has linked patch commit, severity >= MEDIUM
                          ↓
06:00:10     Fetch commit diff via GitHub API
             Filter: exclude tests/docs/lockfiles, keep top 5 source files
                          ↓
06:00:15     LLM analysis (Gemini 2.5 Flash)
             Extract: vuln_type, root_cause, impact, fix_summary, key_diff
             Map to closed taxonomy of 49 normalized pattern IDs
                          ↓
06:00:20     Pattern matching against SQLite historical DB
             Cross-language correlation, recurrence scoring
                          ↓
06:00:25     Output: patches/*.md, README.md, docs/index.html
             Single atomic commit per run
</pre>
<p>Three runs per day: <code>06:00</code>, <code>14:00</code>, <code>23:00</code> UTC. Render pipeline runs independently at <code>07:00</code>, <code>15:00</code>, <code>00:00</code> UTC.</p>
<details>
<summary>Stack</summary>
<table>
<tr><th>Component</th><th>Tech</th><th>Notes</th></tr>
<tr><td>Automation</td><td>GitHub Actions cron</td><td>Zero infra</td></tr>
<tr><td>Data source</td><td>GitHub Advisory DB</td><td>GraphQL, filtered on patch commits</td></tr>
<tr><td>LLM</td><td>Gemini 2.5 Flash</td><td>Free tier, JSON-only output</td></tr>
<tr><td>DB</td><td>SQLite rebuilt from JSONL</td><td>Git-friendly, versioned</td></tr>
<tr><td>Frontend</td><td>Static HTML</td><td>Client-side search, zero build step</td></tr>
<tr><td>Scripting</td><td>Python 3.11</td><td>requests, jinja2, sqlite3</td></tr>
</table>
</details>
<details>
<summary>Stats</summary>
<table>
<tr><th>Metric</th><th>Value</th></tr>
<tr><td>Total advisories</td><td>867</td></tr>
<tr><td>Unique patterns</td><td>49</td></tr>
<tr><td>Pending</td><td>0</td></tr>
<tr><td>Last updated</td><td>2026-07-01</td></tr>
</table>
</details>
<hr>
<sub><a href="https://christbowel.com">christbowel.com</a></sub>
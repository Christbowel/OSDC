<div align="center">
<h1>🎣 Open Source Daily Catch</h1>
<p><b>Automated Patch Intelligence for Security Engineers</b></p>
<p>
<a href="https://github.com/christbowel/osdc/actions/workflows/daily.yml"><img src="https://github.com/christbowel/osdc/actions/workflows/daily.yml/badge.svg" alt="Analysis"></a>
<a href="https://github.com/christbowel/osdc/actions/workflows/render.yml"><img src="https://github.com/christbowel/osdc/actions/workflows/render.yml/badge.svg" alt="Render"></a>
<a href="https://christbowel.github.io/OSDC"><img src="https://img.shields.io/badge/advisories-721-blue" alt="Advisories"></a>
<a href="https://christbowel.github.io/OSDC"><img src="https://img.shields.io/badge/patterns-48-purple" alt="Patterns"></a>
</p>
<p>
<a href="https://christbowel.github.io/OSDC">Live dashboard</a> · <a href="#how-it-works">How it works</a>
</p>
</div>
<hr>
<h3>GHSA-76w7-j9cq-rx2j</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-05-29 · JavaScript<br>
<code>vm2</code> · Pattern: <code>UNCLASSIFIED</code> · 126x across ecosystem
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
<code>vm2</code> · Pattern: <code>UNCLASSIFIED</code> · 126x across ecosystem
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
<code>vm2</code> · Pattern: <code>UNCLASSIFIED</code> · 126x across ecosystem
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
<code>vm2</code> · Pattern: <code>UNCLASSIFIED</code> · 126x across ecosystem
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
<code>github.com/free5gc/smf</code> · Pattern: <code>MISSING_AUTH→ENDPOINT</code> · 28x across ecosystem
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
<code>github.com/enchant97/note-mark/backend</code> · Pattern: <code>INSECURE_DEFAULT→CONFIG</code> · 13x across ecosystem
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
<code>github.com/jkroepke/openvpn-auth-oauth2</code> · Pattern: <code>MISSING_AUTH→ENDPOINT</code> · 28x across ecosystem
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
<code>wwbn/avideo</code> · Pattern: <code>UNSANITIZED_INPUT→XSS</code> · 52x across ecosystem
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
<code>github.com/daptin/daptin</code> · Pattern: <code>PATH_TRAVERSAL→FILE_WRITE</code> · 25x across ecosystem
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
<code>axios</code> · Pattern: <code>UNSANITIZED_INPUT→HEADER</code> · 8x across ecosystem
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
<h3>GHSA-jvc5-6g7q-c843</h3>
<p>
<code>CRITICAL 9.9</code> · 2026-06-09 · PHP<br>
<code>pheditor/pheditor</code> · Pattern: <code>UNSANITIZED_INPUT→COMMAND</code> · 39x across ecosystem
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
<code>github.com/juev/nebula-mesh</code> · Pattern: <code>PRIVILEGE_ESCALATION→ROLE</code> · 20x across ecosystem
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
<code>codeigniter4/framework</code> · Pattern: <code>UNCLASSIFIED</code> · 126x across ecosystem
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
<code>vm2</code> · Pattern: <code>UNCLASSIFIED</code> · 126x across ecosystem
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
<code>Marten</code> · Pattern: <code>UNSANITIZED_INPUT→SQL</code> · 15x across ecosystem
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
<code>snipe/snipe-it</code> · Pattern: <code>MISSING_AUTHZ→RESOURCE</code> · 56x across ecosystem
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
<code>electerm</code> · Pattern: <code>UNSANITIZED_INPUT→COMMAND</code> · 39x across ecosystem
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
<code>github.com/woven-planet/go-zserio</code> · Pattern: <code>DOS→RESOURCE_EXHAUSTION</code> · 52x across ecosystem
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
<code>praisonai</code> · Pattern: <code>UNSANITIZED_INPUT→COMMAND</code> · 39x across ecosystem
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
<code>Microsoft.Native.Quic.MsQuic.OpenSSL</code> · Pattern: <code>UNCLASSIFIED</code> · 126x across ecosystem
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
<code>uefi-firmware</code> · Pattern: <code>BUFFER_OVERFLOW→HEAP</code> · 20x across ecosystem
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
<code>upsonic</code> · Pattern: <code>UNCLASSIFIED</code> · 126x across ecosystem
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
<code>changedetection.io</code> · Pattern: <code>MISSING_AUTH→ENDPOINT</code> · 28x across ecosystem
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
<code>WWBN/AVideo</code> · Pattern: <code>UNSANITIZED_INPUT→XSS</code> · 52x across ecosystem
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
<code>openc3</code> · Pattern: <code>UNSANITIZED_INPUT→SQL</code> · 15x across ecosystem
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
<code>nimiq-block</code> · Pattern: <code>INTEGER_OVERFLOW→BOUNDARY</code> · 7x across ecosystem
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
<code>lollms</code> · Pattern: <code>UNSANITIZED_INPUT→XSS</code> · 52x across ecosystem
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
<code>getgrav/grav</code> · Pattern: <code>PRIVILEGE_ESCALATION→ROLE</code> · 20x across ecosystem
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
<code>nabeel/phpvms</code> · Pattern: <code>MISSING_AUTH→ENDPOINT</code> · 28x across ecosystem
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
<code>excel-mcp-server</code> · Pattern: <code>PATH_TRAVERSAL→FILE_READ</code> · 38x across ecosystem
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
<code>@delmaredigital/payload-puck</code> · Pattern: <code>MISSING_AUTH→ENDPOINT</code> · 28x across ecosystem
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
<h3>GHSA-mqq6-462x-jxmm</h3>
<p>
<code>CRITICAL 9.1</code> · 2026-06-10 · Go<br>
<code>github.com/dhax/go-base</code> · Pattern: <code>UNCLASSIFIED</code> · 126x across ecosystem
</p>
<p><b>Root cause</b> : </p>
<p><b>Impact</b> : </p>
<p><b>Fix</b> : </p>
<p>
<a href="https://github.com/advisories/GHSA-mqq6-462x-jxmm">Advisory</a> · <a href="https://github.com/dhax/go-base/commit/cc82b9740fa6b08e0fad409cd4b418e240dd0e00">Commit</a>
</p>
<hr>
<h3>GHSA-fwj3-42wh-8673</h3>
<p>
<code>CRITICAL 9.1</code> · 2026-05-07 · Go<br>
<code>github.com/gtsteffaniak/filebrowser</code> · Pattern: <code>PATH_TRAVERSAL→FILE_DELETE</code> · 5x across ecosystem
</p>
<p><b>Root cause</b> : The application did not properly sanitize user-supplied paths in the DELETE API for public shares. An attacker could provide a path containing &#39;..&#39; sequences, which would allow them to traverse outside the intended directory and delete arbitrary files on the server.</p>
<p><b>Impact</b> : An unauthenticated attacker could delete any file on the server that the FileBrowser process has write permissions to, potentially leading to denial of service or data loss.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/backend/http/middleware.go
+++ b/backend/http/middleware.go
@@ -53,7 +53,11 @@ type handleFunc func(w http.ResponseWriter, r *http.Request, data *requestContex
 func withHashFileHelper(fn handleFunc) handleFunc {
 	return withOrWithoutUserHelper(func(w http.ResponseWriter, r *http.Request, data *requestContext) (int, error) {
 		hash := r.URL.Query().Get(&#34;hash&#34;)
-		path := r.URL.Query().Get(&#34;path&#34;)
+		inputPath := r.URL.Query().Get(&#34;path&#34;)
+		path, err := utils.SanitizeUserPath(inputPath)
+		if err != nil &amp;&amp; inputPath != &#34;&#34; {
+			return http.StatusBadRequest, err
+		}
 
 		// Get the file link by hash
 		link, err := store.Share.GetByHash(hash)</pre>
</details>
<p><b>Fix</b> : The patch introduces a `utils.SanitizeUserPath` function to validate and sanitize user-provided paths, specifically in the `withHashFileHelper` and `resourceBulkDeleteHandler` functions. This prevents path traversal sequences like &#39;..&#39; from being interpreted by the file system.</p>
<p>
<a href="https://github.com/advisories/GHSA-fwj3-42wh-8673">Advisory</a> · <a href="https://github.com/gtsteffaniak/filebrowser/commit/112740bdd41de7d5eb01e13ba49d406bfc463f69">Commit</a>
</p>
<hr>
<h3>GHSA-w48r-jppp-rcfw</h3>
<p>
<code>CRITICAL 9.1</code> · 2026-05-05 · PHP<br>
<code>getgrav/grav</code> · Pattern: <code>PATH_TRAVERSAL→FILE_WRITE</code> · 25x across ecosystem
</p>
<p><b>Root cause</b> : The vulnerability stemmed from multiple issues. Firstly, the `unZip` function did not validate archive entry names, allowing &#39;Zip Slip&#39; attacks where malicious ZIP files could write files outside the intended directory using path traversal sequences (e.g., `../`). Secondly, the `attribute` function in `MediaObjectTrait` allowed arbitrary attribute names, which could be exploited for XSS by injecting event handlers (e.g., `onerror`) or other dangerous attributes. Lastly, the `detectXss` function&#39;s regex for `on_events` was bypassable, and the SVG parsing in `VectorImageMedium` was vulnerable to XXE attacks due to not stripping DOCTYPE/ENTITY declarations and lacking `LIBXML_NONET`.</p>
<p><b>Impact</b> : An attacker could achieve remote code execution by uploading a crafted plugin ZIP file that writes PHP files to arbitrary locations. They could also inject malicious JavaScript via XSS in image attributes or potentially perform server-side request forgery (SSRF) or information disclosure via XXE in SVG files.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/system/src/Grav/Common/GPM/Installer.php
+++ b/system/src/Grav/Common/GPM/Installer.php
@@ -179,6 +179,24 @@ public static function unZip($zip_file, $destination)
         $archive = $zip-&gt;open($zip_file);
 
         if ($archive === true) {
+            $numFiles = $zip-&gt;numFiles;
+            for ($i = 0; $i &lt; $numFiles; $i++) {
+                $entryName = (string) $zip-&gt;getNameIndex($i);
+                if (!self::isSafeArchiveEntry($entryName)) {
+                    self::$error = self::ZIP_EXTRACT_ERROR;
+                    $zip-&gt;close();
+                    return false;
+                }
+            }
+
             Folder::create($destination);
 
             $unzip = $zip-&gt;extractTo($destination);</pre>
</details>
<p><b>Fix</b> : The patch introduces `isSafeArchiveEntry` to validate ZIP entry names, preventing path traversal. It also adds `isSafeAttributeName` to restrict allowed HTML attribute names, mitigating XSS. The `detectXss` regex for `on_events` was improved to be more robust. Finally, the SVG parsing now strips DOCTYPE/ENTITY declarations and uses `LIBXML_NONET` to prevent XXE vulnerabilities.</p>
<p>
<a href="https://github.com/advisories/GHSA-w48r-jppp-rcfw">Advisory</a> · <a href="https://github.com/getgrav/grav/commit/5a12f9be8314682c8713e569e330f11805d0a663">Commit</a>
</p>
<hr>
<h3>GHSA-xj4f-8jjg-vx4q</h3>
<p>
<code>CRITICAL 9.1</code> · 2026-05-04 · Java<br>
<code>org.openmrs.api:openmrs-api</code> · Pattern: <code>UNSANITIZED_INPUT→TEMPLATE</code> · 3x across ecosystem
</p>
<p><b>Root cause</b> : The application used Apache Velocity for evaluating user-supplied criteria in `ConceptReferenceRangeUtility.java`. The `evaluateCriteria` method directly passed unsanitized user input into `velocityEngine.evaluate()`, allowing an attacker to inject Velocity Template Language (VTL) directives. Since Velocity templates can execute arbitrary Java code, this led to Remote Code Execution (RCE).</p>
<p><b>Impact</b> : An authenticated attacker with privileges to create or modify ConceptReferenceRange objects could store malicious Velocity templates. When these templates were evaluated, the attacker could achieve arbitrary code execution on the server, leading to full system compromise.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java
+++ b/api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java
@@ -96,387 +128,383 @@ public boolean evaluateCriteria(String criteria, ConceptReferenceRangeContext co
 			throw new IllegalArgumentException(&#34;Failed to evaluate criteria with reason: criteria is empty&#34;);
 		}
 
-		VelocityContext velocityContext = new VelocityContext();
-		velocityContext.put(&#34;fn&#34;, this);
-		velocityContext.put(&#34;patient&#34;, HibernateUtil.getRealObjectFromProxy(context.getPerson()));
-		velocityContext.put(&#34;context&#34;, context);
-
-		velocityContext.put(&#34;obs&#34;, context.getObs());
-		velocityContext.put(&#34;encounter&#34;, context.getEncounter());
-		velocityContext.put(&#34;date&#34;, context.getDate());
-
-		VelocityEngine velocityEngine = new VelocityEngine();
-		try {
-			Properties props = new Properties();
-			props.put(&#34;runtime.log.logsystem.log4j.category&#34;, &#34;velocity&#34;);
-			props.put(&#34;runtime.log.logsystem.log4j.logger&#34;, &#34;velocity&#34;);
-			velocityEngine.init(props);
-		} catch (Exception e) {
-			throw new APIException(&#34;Failed to create the velocity engine: &#34; + e.getMessage(), e);
-		}
-
-		StringWriter writer = new StringWriter();
-		String wrappedCriteria = &#34;#set( $criteria = &#34; + criteria + &#34; )$criteria&#34;;
+		Map&lt;String, Object&gt; root = new HashMap&lt;&gt;();
+		root.put(&#34;$fn&#34;, functions);
+		root.put(&#34;$patient&#34;, HibernateUtil.getRealObjectFromProxy(context.getPerson()));
+		root.put(&#34;$context&#34;, context);
+		root.put(&#34;$obs&#34;, context.getObs());
+		root.put(&#34;$encounter&#34;, context.getEncounter());
+		root.put(&#34;$date&#34;, context.getDate());
 
 		try {
-			velocityEngine.evaluate(velocityContext, writer, ConceptReferenceRangeUtility.class.getName(), wrappedCriteria);
-			return Boolean.parseBoolean(writer.toString());
-		} catch (ParseErrorException e) {
-			throw new APIException(&#34;An error occurred while evaluating criteria. Invalid criteria: &#34; + criteria, e);
+			Expression expression = EXPRESSION_CACHE.get(criteria, PARSER::parseExpression);
+			Boolean result = expression.getValue(EVAL_CONTEXT, root, Boolean.class);
+			return result != null &amp;&amp; result;
+		} catch (SpelEvaluationException e) {
+			SpelMessage msg = e.getMessageCode();
+			if (msg == SpelMessage.METHOD_CALL_ON_NULL_OBJECT_NOT_ALLOWED
+			        || msg == SpelMessage.PROPERTY_OR_FIELD_NOT_READABLE_ON_NULL) {
+				return false;
+			}
+			throw new APIException(&#34;An error occurred while evaluating criteria: &#34; + criteria, e);
 		} catch (Exception e) {
-			throw new APIException(&#34;An error occurred while evaluating criteria: &#34;, e);
+			throw new APIException(&#34;An error occurred while evaluating criteria: &#34; + criteria, e);
 		}
 	}</pre>
</details>
<p><b>Fix</b> : The patch replaces the vulnerable Apache Velocity template engine with Spring Expression Language (SpEL). It also introduces a `CriteriaFunctions` class to explicitly define available functions, preventing direct access to arbitrary Java methods. Additionally, a cache for parsed expressions is implemented to improve performance.</p>
<p>
<a href="https://github.com/advisories/GHSA-xj4f-8jjg-vx4q">Advisory</a> · <a href="https://github.com/openmrs/openmrs-core/commit/8d1c193">Commit</a>
</p>
<hr>
<h3>GHSA-f6qq-3m3h-4g42</h3>
<p>
<code>CRITICAL 9.1</code> · 2026-04-30 · Go<br>
<code>github.com/go-pkgz/auth/v2</code> · Pattern: <code>PRIVILEGE_ESCALATION→ROLE</code> · 20x across ecosystem
</p>
<p><b>Root cause</b> : The vulnerability existed because the Patreon OAuth2 provider incorrectly generated the local user ID. Instead of using the unique ID provided by Patreon (uinfoJSON.Data.ID), it used an uninitialized or default value from userInfo.ID, which was likely constant or empty across all users. This resulted in all authenticated Patreon users being assigned the same local user ID.</p>
<p><b>Impact</b> : An attacker could impersonate any other Patreon-authenticated user by simply logging in with their own Patreon account. This allows for cross-user impersonation and unauthorized access to other users&#39; data or actions within the application.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">-				userInfo.ID = &#34;patreon_&#34; + token.HashID(sha1.New(), userInfo.ID)
+				userInfo.ID = &#34;patreon_&#34; + token.HashID(sha1.New(), uinfoJSON.Data.ID)</pre>
</details>
<p><b>Fix</b> : The patch corrects the user ID generation logic for the Patreon OAuth2 provider. It changes the source of the ID used for hashing from the potentially uninitialized `userInfo.ID` to the unique and correct `uinfoJSON.Data.ID` obtained from the Patreon user information JSON response. This ensures each Patreon user gets a unique local ID.</p>
<p>
<a href="https://github.com/advisories/GHSA-f6qq-3m3h-4g42">Advisory</a> · <a href="https://github.com/go-pkgz/auth/commit/c0b15ee72a8401da83c01781c16636c521f42698">Commit</a>
</p>
<hr>
<h3>GHSA-rcmw-7mc7-3rj7</h3>
<p>
<code>CRITICAL 9.1</code> · 2026-04-30 · Python<br>
<code>sentry</code> · Pattern: <code>MISSING_AUTH→ENDPOINT</code> · 28x across ecosystem
</p>
<p><b>Root cause</b> : During the SAML SSO setup process, Sentry was using the email provided by the Identity Provider (IdP) to link the SAML identity to a Sentry user. This allowed a malicious IdP or an attacker controlling the IdP&#39;s response to assert an arbitrary email address, potentially linking the SAML identity to an existing Sentry user who was not the administrator performing the setup.</p>
<p><b>Impact</b> : An attacker could link their SAML identity to an arbitrary Sentry user&#39;s account, effectively taking over that user&#39;s account within the organization. This could lead to unauthorized access to sensitive data and actions.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/src/sentry/auth/helper.py
+++ b/src/sentry/auth/helper.py
@@ -1017,7 +1017,11 @@ def _finish_setup_pipeline(self, identity: Mapping[str, Any]) -&gt; HttpResponseRed
             organization_id=self.organization.id, provider=self.provider.key, config=config
         )
 
-        self.auth_handler(identity).handle_attach_identity(om)
+        # The setup flow should always link the identity to the admin who is
+        # performing setup, so override the email to ensure resolve_email_to_user
+        # returns the authenticated user rather than whoever the IdP asserted.
+        setup_identity = {**identity, &#34;email&#34;: request.user.email}
+        self.auth_handler(setup_identity).handle_attach_identity(om)
 
         auth.mark_sso_complete(request, self.organization.id)</pre>
</details>
<p><b>Fix</b> : The patch ensures that during the SAML SSO setup flow, the identity is always linked to the email of the administrator who is currently logged in and performing the setup. It explicitly overrides the email from the IdP&#39;s response with the authenticated user&#39;s email before attaching the identity.</p>
<p>
<a href="https://github.com/advisories/GHSA-rcmw-7mc7-3rj7">Advisory</a> · <a href="https://github.com/getsentry/sentry/commit/0c67558ae7fe08738912d4c5233b53ead048da3b">Commit</a>
</p>
<hr>
<h3>GHSA-m5gr-86j6-99jp</h3>
<p>
<code>CRITICAL 9.1</code> · 2026-04-10 · Python<br>
<code>gramps-webapi</code> · Pattern: <code>PATH_TRAVERSAL→FILE_WRITE</code> · 25x across ecosystem
</p>
<p><b>Root cause</b> : The application extracted files from a user-provided zip archive without validating the paths of the entries within the archive. This allowed an attacker to craft a zip file containing entries with malicious paths (e.g., `../../../../etc/passwd`) that, when extracted, would write files outside the intended temporary directory.</p>
<p><b>Impact</b> : An attacker could write arbitrary files to arbitrary locations on the server&#39;s filesystem, potentially leading to remote code execution, data corruption, or denial of service.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">temp_dir_real = os.path.realpath(temp_dir)
for member in zip_file.namelist():
    member_path = os.path.realpath(os.path.join(temp_dir_real, member))
    if not member_path.startswith(temp_dir_real + os.sep):
        raise ValueError(f&#34;Zip Slip path traversal detected: {member}&#34;)</pre>
</details>
<p><b>Fix</b> : The patch adds a validation step before extraction. It iterates through each member of the zip file, constructs its intended extraction path, and checks if the real path of the member remains within the designated temporary directory. If a path traversal attempt is detected, an error is raised.</p>
<p>
<a href="https://github.com/advisories/GHSA-m5gr-86j6-99jp">Advisory</a> · <a href="https://github.com/gramps-project/gramps-web-api/commit/3ed4342711e3ec849552df09b1fe2fbf2ca5c29a">Commit</a>
</p>
<hr>
<h3>GHSA-fxc7-fm93-6q77</h3>
<p>
<code>CRITICAL 9.0</code> · 2026-05-05 · Java<br>
<code>com.arcadedb:arcadedb-server</code> · Pattern: <code>MISSING_AUTHZ→RESOURCE</code> · 56x across ecosystem
</p>
<p><b>Root cause</b> : The ArcadeDB server did not properly enforce security configurations for newly created databases and had a flawed logic for merging database-specific and wildcard security group configurations. This allowed users to create databases without proper security settings and bypass intended authorization rules by exploiting how group permissions were retrieved.</p>
<p><b>Impact</b> : An attacker could create new databases that are unsecured by default, gaining unauthorized access to them. They could also potentially bypass authorization checks on existing databases by manipulating schema properties or exploiting the flawed group configuration merge logic, leading to data access or modification across databases.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/server/src/main/java/com/arcadedb/server/ArcadeDBServer.java
+++ b/server/src/main/java/com/arcadedb/server/ArcadeDBServer.java
@@ -474,6 +474,8 @@ public ServerDatabase createDatabase(final String databaseName, final ComponentF
           configuration.getValueAsString(GlobalConfiguration.SERVER_DATABASE_DIRECTORY) + File.separator
               + databaseName).setAutoTransaction(true);
 
+      factory.setSecurity(getSecurity());
+
       if (factory.exists())
         throw new IllegalArgumentException(&#34;Database &#39;&#34; + databaseName + &#34;&#39; already exists&#34;);</pre>
</details>
<p><b>Fix</b> : The patch ensures that newly created databases inherit the server&#39;s security configuration. It also refines the logic for retrieving database group configurations, specifically for wildcard (&#39;*&#39;) entries, to correctly merge or return specific database groups, preventing unintended authorization bypasses.</p>
<p>
<a href="https://github.com/advisories/GHSA-fxc7-fm93-6q77">Advisory</a> · <a href="https://github.com/ArcadeData/arcadedb/commit/04110c06315da55604ac107f71fe7182f3a3deb8">Commit</a>
</p>
<hr>
<h3>GHSA-fcw5-x6j4-ccmp</h3>
<p>
<code>CRITICAL 0.0</code> · 2026-06-18 · Python<br>
<code>jupyter-server</code> · Pattern: <code>UNSANITIZED_INPUT→XSS</code> · 52x across ecosystem
</p>
<p><b>Root cause</b> : The Jupyter Server&#39;s `NbconvertFileHandler` and `NbconvertPostHandler` did not include a &#39;sandbox&#39; directive in their Content-Security-Policy (CSP) headers when serving HTML content generated by nbconvert. This allowed malicious JavaScript embedded in a notebook to execute within the same origin as the Jupyter server.</p>
<p><b>Impact</b> : An attacker could embed malicious JavaScript in a notebook, which, when viewed via nbconvert, would execute with the same privileges as the Jupyter server. This could lead to session hijacking, data exfiltration, or further compromise of the user&#39;s environment.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/jupyter_server/nbconvert/handlers.py
+++ b/jupyter_server/nbconvert/handlers.py
@@ -92,6 +92,14 @@ class NbconvertFileHandler(JupyterHandler):
     auth_resource = AUTH_RESOURCE
     SUPPORTED_METHODS = (&#34;GET&#34;,)
 
+    @property
+    def content_security_policy(self):
+        # In case we&#39;re serving HTML, confine any Javascript to a unique
+        # origin so it can&#39;t interact with the Jupyter server.
+        if self.settings.get(&#34;nbconvert_csp_sandbox&#34;, True):
+            return super().content_security_policy + &#34;; sandbox allow-scripts&#34;
+        return super().content_security_policy
+
     @web.authenticated
     @authorized
     async def get(self, format, path):</pre>
</details>
<p><b>Fix</b> : The patch introduces a new configuration option `nbconvert_csp_sandbox` which defaults to `True`. When enabled, the `NbconvertFileHandler` and `NbconvertPostHandler` now add a `sandbox allow-scripts` directive to their Content-Security-Policy headers, isolating the nbconvert-served content to a unique origin.</p>
<p>
<a href="https://github.com/advisories/GHSA-fcw5-x6j4-ccmp">Advisory</a> · <a href="https://github.com/jupyter-server/jupyter_server/commit/6cbee8d65e71abac851c4492fea987ad080580bd">Commit</a>
</p>
<hr>
<h3>GHSA-qvv5-jq5g-4cgg</h3>
<p>
<code>CRITICAL 0.0</code> · 2026-06-10 · JavaScript<br>
<code>@whiskeysockets/baileys</code> · Pattern: <code>UNCLASSIFIED</code> · 126x across ecosystem
</p>
<p><b>Root cause</b> : </p>
<p><b>Impact</b> : </p>
<p><b>Fix</b> : </p>
<p>
<a href="https://github.com/advisories/GHSA-qvv5-jq5g-4cgg">Advisory</a> · <a href="https://github.com/WhiskeySockets/Baileys/commit/3beb08eecfcb4e65722e674034bd84fb11a9de35">Commit</a>
</p>
<hr>
<h3>GHSA-55hg-8qxv-qj4p</h3>
<p>
<code>CRITICAL 0.0</code> · 2026-06-09 · Erlang<br>
<code>phoenix_storybook</code> · Pattern: <code>UNCLASSIFIED</code> · 126x across ecosystem
</p>
<p><b>Root cause</b> : </p>
<p><b>Impact</b> : </p>
<p><b>Fix</b> : </p>
<p>
<a href="https://github.com/advisories/GHSA-55hg-8qxv-qj4p">Advisory</a> · <a href="https://github.com/phenixdigital/phoenix_storybook/commit/56ab8464d4375fa52db806148a06cce126ad481d">Commit</a>
</p>
<hr>
<h3>GHSA-4p62-hqp5-g644</h3>
<p>
<code>CRITICAL 0.0</code> · 2026-06-04 · Python<br>
<code>stata-mcp</code> · Pattern: <code>UNSANITIZED_INPUT→COMMAND</code> · 39x across ecosystem
</p>
<p><b>Root cause</b> : The application allowed an attacker to control the `log_file_name` parameter, which was directly used to construct a log file path. This lack of input validation enabled both path traversal characters (e.g., `../`) and potentially command injection through crafted filenames, as the log file name could influence commands executed by Stata.</p>
<p><b>Impact</b> : An attacker could write arbitrary files to arbitrary locations on the file system, potentially leading to remote code execution by overwriting critical system files or injecting malicious scripts. They could also create log files with names that, when processed by Stata, could execute arbitrary commands.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/src/stata_mcp/stata/stata_do/do.py
+++ b/src/stata_mcp/stata/stata_do/do.py
@@ -79,7 +82,8 @@ def execute_dofile(
         &#34;&#34;&#34;
         nowtime = get_nowtime()
         log_name = log_file_name or nowtime
-        log_file = self.log_file_path / f&#34;{log_name}.log&#34;
+        self._validate_log_name(log_name)
+        log_file = self.generate_log_file(log_name)</pre>
</details>
<p><b>Fix</b> : The patch introduces a regular expression to validate the `log_file_name` parameter, ensuring it only contains alphanumeric characters, underscores, dots, or hyphens, and has a length between 1 and 128 characters. It also explicitly checks for path traversal attempts by disallowing parts like &#39;.&#39;, &#39;..&#39;, or empty strings in the path components.</p>
<p>
<a href="https://github.com/advisories/GHSA-4p62-hqp5-g644">Advisory</a> · <a href="https://github.com/SepineTam/mcp-for-stata/commit/e6f945941ae0c7cf5e74a428e0b3dc82b396382f">Commit</a>
</p>
<hr>
<h3>GHSA-qrvh-r3f2-9h4r</h3>
<p>
<code>CRITICAL 0.0</code> · 2026-05-26 · Java<br>
<code>org.xwiki.platform:xwiki-platform-rest-server</code> · Pattern: <code>MISSING_AUTHZ→RESOURCE</code> · 56x across ecosystem
</p>
<p><b>Root cause</b> : The REST endpoint for importing XAR (XWiki Archive) files into a wiki did not perform any authorization checks. This allowed any unauthenticated or unauthorized user to upload and import a malicious XAR file.</p>
<p><b>Impact</b> : An attacker could import arbitrary XAR files, potentially leading to remote code execution, privilege escalation, or complete compromise of the XWiki instance.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/xwiki-platform-core/xwiki-platform-rest/xwiki-platform-rest-server/src/main/java/org/xwiki/rest/internal/resources/wikis/WikiResourceImpl.java
+++ b/xwiki-platform-core/xwiki-platform-rest/xwiki-platform-rest-server/src/main/java/org/xwiki/rest/internal/resources/wikis/WikiResourceImpl.java
@@ -74,6 +80,13 @@ public Wiki get(String wikiName) throws XWikiRestException
     public Wiki importXAR(String wikiName, Boolean backup, String historyStrategy, InputStream is)
         throws XWikiRestException
     {
+        // Importing a XAR require wiki admin right
+        try {
+            this.authorizationManager.checkAccess(Right.ADMIN, new WikiReference(wikiName));
+        } catch (AccessDeniedException e) {
+            throw new WebApplicationException(e.getMessage(), Response.Status.FORBIDDEN);
+        }
+
         try {
             if (!this.wikis.exists(wikiName)) {
                 throw new WebApplicationException(Response.Status.NOT_FOUND);</pre>
</details>
<p><b>Fix</b> : The patch adds an authorization check to the `importXAR` method. It now requires the user to have &#39;ADMIN&#39; rights for the specified wiki before proceeding with the XAR import operation, throwing a 403 Forbidden error if the check fails.</p>
<p>
<a href="https://github.com/advisories/GHSA-qrvh-r3f2-9h4r">Advisory</a> · <a href="https://github.com/xwiki/xwiki-platform/commit/4b7b95b79256374d487e9ece1dc48f527966990f">Commit</a>
</p>
<hr>
<h3>GHSA-xq3r-2qv5-vqqm</h3>
<p>
<code>CRITICAL 0.0</code> · 2026-05-26 · Java<br>
<code>org.xwiki.commons:xwiki-commons-classloader-api</code> · Pattern: <code>PATH_TRAVERSAL→FILE_READ</code> · 38x across ecosystem
</p>
<p><b>Root cause</b> : The application used `Paths.get(fullPath).normalize()` to prevent path traversal. However, it did not correctly handle leading slashes in the `resourcePath` parameter. When a resource path started with one or more leading slashes (e.g., &#34;//../&#34;), `Paths.get().normalize()` would treat it differently than intended, allowing an attacker to bypass the `startsWith(&#34;../&#34;)` check and access resources outside the intended directory.</p>
<p><b>Impact</b> : An attacker could use specially crafted `resources` parameters in `ssx` and `jsx` endpoints to read arbitrary files on the server&#39;s file system, potentially leading to information disclosure or further compromise.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/xwiki-commons-core/xwiki-commons-classloader/xwiki-commons-classloader-api/src/main/java/org/xwiki/classloader/internal/ClassLoaderUtils.java
+++ b/xwiki-commons-core/xwiki-commons-classloader/xwiki-commons-classloader-api/src/main/java/org/xwiki/classloader/internal/ClassLoaderUtils.java
@@ -47,20 +47,30 @@ private static String resolveResourceName(String prefixPath, String resourcePath
             fullPath = resourcePath;
 
             // Prevent access to resources from other directories
-            // TODO: find or implement something closed to Servlet ClassLoader behavior to be as accurate as possible
-            // and be able to reuse the normalized result
-            Path normalizedResource = Paths.get(fullPath).normalize();
+            // On Tomcat, all leading / have no effect, contrary to Paths#normalize()
+            int index = 0;
+            while (index &lt; fullPath.length() &amp;&amp; fullPath.charAt(index) == &#39;/&#39;) {
+                ++index;
+            }
+            String normalizedPath = fullPath.substring(index);
+
+            Path normalizedResource = Paths.get(normalizedPath).normalize();
             if (normalizedResource.startsWith(&#34;../&#34;)) {
                 throw new IllegalArgumentException(String.format(
                     &#34;The provided resource name [%s] is trying to navigate out of the mandatory root location&#34;,
-                    resourcePath));
+                    fullPath));
             }
         } else {
             fullPath = prefixPath + resourcePath;
 
             // Prevent access to resources from other directories
             // TODO: find or implement something closed to Servlet ClassLoader behavior to be as accurate as possible
-            // and be able to reuse the normalized result
+            // and be able to reuse the normalized result. Not so easy since the various applications servers can use
+            // different logics.
             Path normalizedResource = Paths.get(fullPath).normalize();
             if (!normalizedResource.startsWith(prefixPath)) {
                 throw new IllegalArgumentException(String.format(</pre>
</details>
<p><b>Fix</b> : The patch modifies the `resolveResourceName` method to explicitly remove all leading slashes from the `resourcePath` before normalization. This ensures that `Paths.get().normalize()` behaves consistently and the subsequent `startsWith(&#34;../&#34;)` check correctly identifies and prevents path traversal attempts.</p>
<p>
<a href="https://github.com/advisories/GHSA-xq3r-2qv5-vqqm">Advisory</a> · <a href="https://github.com/xwiki/xwiki-commons/commit/a979cafd89f6a9c9c0b9ab19744d672df64429bf">Commit</a>
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
             Map to closed taxonomy of 48 normalized pattern IDs
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
<tr><td>Total advisories</td><td>721</td></tr>
<tr><td>Unique patterns</td><td>48</td></tr>
<tr><td>Pending</td><td>0</td></tr>
<tr><td>Last updated</td><td>2026-06-19</td></tr>
</table>
</details>
<hr>
<sub><a href="https://christbowel.com">christbowel.com</a></sub>
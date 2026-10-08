<div align="center">
<h1>🎣 Open Source Daily Catch</h1>
<p><b>Automated Patch Intelligence for Security Engineers</b></p>
<p>
<a href="https://github.com/christbowel/osdc/actions/workflows/daily.yml"><img src="https://github.com/christbowel/osdc/actions/workflows/daily.yml/badge.svg" alt="Analysis"></a>
<a href="https://github.com/christbowel/osdc/actions/workflows/render.yml"><img src="https://github.com/christbowel/osdc/actions/workflows/render.yml/badge.svg" alt="Render"></a>
<a href="https://christbowel.github.io/OSDC"><img src="https://img.shields.io/badge/advisories-2502-blue" alt="Advisories"></a>
<a href="https://christbowel.github.io/OSDC"><img src="https://img.shields.io/badge/patterns-51-purple" alt="Patterns"></a>
</p>
<p>
<a href="https://christbowel.github.io/OSDC">Live dashboard</a> · <a href="#how-it-works">How it works</a>
</p>
</div>
<hr>
<h3>GHSA-pq96-jpmf-w254</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-10-07 · JavaScript<br>
<code>quasar</code> · Pattern: <code>UNSANITIZED_INPUT→XSS</code> · 127x across ecosystem
</p>
<p><b>Root cause</b> : The Quasar Framework&#39;s Server-Side Rendering (SSR) mechanism for meta tags (like title, meta, link, script, noscript) did not properly escape user-controlled input before rendering it into the HTML head. This allowed attackers to inject arbitrary HTML and JavaScript.</p>
<p><b>Impact</b> : An attacker could inject malicious scripts into web pages, leading to session hijacking, defacement, redirection, or other client-side attacks against users viewing the affected pages.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/ui/src/plugins/meta/Meta.js
+++ b/ui/src/plugins/meta/Meta.js
@@ -148,15 +190,17 @@ function apply({ add, remove }) {
 
 function getAttr(seed) {
   return att =&gt; {
+    if (isValidAttrName(att) === false) return
+
     const val = seed[att]
-    return att + (val !== true &amp;&amp; val !== void 0 ? `=&#34;${val}&#34;` : &#39;&#39;)
+    return att + (val !== true &amp;&amp; val !== void 0 ? `=&#34;${encodeHtml(val)}&#34;` : &#39;&#39;)
   }
 }
 
 function getHead(meta) {
   let output = &#39;&#39;
   if (meta.title) {
-    output += `&lt;title&gt;${meta.title}&lt;/title&gt;`
+    output += `&lt;title&gt;${encodeHtml(meta.title)}&lt;/title&gt;`
   }
   ;[&#39;meta&#39;, &#39;link&#39;, &#39;script&#39;].forEach(type =&gt; {
     const metaType = meta[type]</pre>
</details>
<p><b>Fix</b> : The patch introduces several HTML and JSON encoding functions (`encodeHtml`, `encodeJson`, `protectRawText`) and a validation function for attribute names (`isValidAttrName`). These functions are applied to all user-controlled data rendered within meta tags, attributes, and script contents to ensure proper escaping and prevent injection.</p>
<p>
<a href="https://github.com/advisories/GHSA-pq96-jpmf-w254">Advisory</a> · <a href="https://github.com/quasarframework/quasar/commit/11505afe5b5218f2c468f130181815b898fd1e40">Commit</a>
</p>
<hr>
<h3>GHSA-r488-j9vj-wx3q</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-10-07 · JavaScript<br>
<code>@payloadcms/plugin-form-builder</code> · Pattern: <code>MISSING_AUTHZ→RESOURCE</code> · 125x across ecosystem
</p>
<p><b>Root cause</b> : The vulnerability stemmed from overly permissive access control configurations in the Payload Form Builder plugin. Specifically, the &#39;read&#39; access for &#39;FormSubmissions&#39; and the &#39;emails&#39; field within &#39;Forms&#39; collections was set to allow any logged-in user to read, rather than restricting it to administrative users.</p>
<p><b>Impact</b> : An attacker, if authenticated as any user (not necessarily an admin), could read sensitive form submission data and email configurations, potentially leading to information disclosure or further attacks.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">-      read: ({ req: { user } }) =&gt; !!user, // logged-in users,
+      read: ({ req }) =&gt; req.user?.collection === req.payload.config.admin.user,</pre>
</details>
<p><b>Fix</b> : The patch tightens access control by changing the &#39;read&#39; access logic. Instead of allowing any logged-in user, it now explicitly checks if the logged-in user belongs to the admin user collection configured in Payload CMS, thereby restricting access to administrative users only.</p>
<p>
<a href="https://github.com/advisories/GHSA-r488-j9vj-wx3q">Advisory</a> · <a href="https://github.com/payloadcms/payload/commit/333b82b9f3e685fed6826c2e3270da79df8336c6">Commit</a>
</p>
<hr>
<h3>GHSA-3vgf-8m4q-q4qr</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-10-05 · JavaScript<br>
<code>vm2</code> · Pattern: <code>PROTOTYPE_POLLUTION→OVERRIDE</code> · 39x across ecosystem
</p>
<p><b>Root cause</b> : The vm2 sandbox environment failed to properly protect the prototypes of host TypedArray and ArrayBuffer intrinsics, as well as various iterator prototypes. These prototypes were not included in the list of protected host objects, allowing sandbox code to modify their host-realm definitions.</p>
<p><b>Impact</b> : An attacker could mutate host TypedArray and ArrayBuffer intrinsics, potentially leading to arbitrary code execution or other severe integrity violations outside the sandbox.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/lib/bridge.js
+++ b/lib/bridge.js
@@ -31,6 +31,29 @@ const globalsList = [
 	&#39;WeakSet&#39;,
 	&#39;Promise&#39;,
 	&#39;Function&#39;,
+	&#39;ArrayBuffer&#39;,
+	&#39;SharedArrayBuffer&#39;,
+	&#39;DataView&#39;,
+	&#39;Uint8Array&#39;,
+	&#39;Int8Array&#39;,
+	&#39;Uint8ClampedArray&#39;,
+	&#39;Uint16Array&#39;,
+	&#39;Int16Array&#39;,
+	&#39;Uint32Array&#39;,
+	&#39;Int32Array&#39;,
+	&#39;Float32Array&#39;,
+	&#39;Float64Array&#39;,
+	&#39;BigInt64Array&#39;,
+	&#39;BigUint64Array&#39;,
 ];
 
 const errorsList = [
@@ -79,6 +102,54 @@ try {
 	thisGlobalPrototypes[&#39;AsyncGeneratorFunction&#39;] = eval(&#39;(async function*() {})&#39;).constructor.prototype;
 } catch (e) {}
 
+// SECURITY (GHSA-3vgf-8m4q-q4qr / GHSA-59g5-pmg6-5gr4): abstract intrinsic
+// prototypes with NO named global. Same protection gap as the binary-data
+// globals above, but they cannot be reached through `global[key]`, so resolve
+// them structurally (mirroring the AsyncFunction / GeneratorFunction pattern).
+// Adding them to `thisGlobalPrototypes` routes them into `protectedHostObjects`
+// (which enumerates every key) and the mapping loops below, so the write traps
+// refuse sandbox `set` / `defineProperty` on host `%TypedArray%.prototype`,
+// `%IteratorPrototype%`, `ArrayIterator.prototype`, etc.
+// `TypedArrayProto` — the shared `%TypedArray%.prototype` above every concrete
+// typed array (Buffer -&gt; Uint8Array.prototype -&gt; %TypedArray%.prototype).
+try {
+	thisGlobalPrototypes[&#39;TypedArray&#39;] = Object.getPrototypeOf(Uint8Array.prototype);
+} catch (e) {}
+// The iterator prototype chain: concrete iterator prototypes and the shared
+// `%IteratorPrototype%` they all inherit from (GHSA-59g5 targets both).
+try {
+	const arrayIteratorProto = Object.getPrototypeOf([][Symbol.iterator]());
+	thisGlobalPrototypes[&#39;ArrayIterator&#39;] = arrayIteratorProto;
+	thisGlobalPrototypes[&#39;IteratorPrototype&#39;] = Object.getPrototypeOf(arrayIteratorProto);
+} catch (e) {}
+try {
+	thisGlobalPrototypes[&#39;StringIterator&#39;] = Object.getPrototypeOf(&#39;&#39;[Symbol.iterator]());
+} catch (e) {}
+try {
+	thisGlobalPrototypes[&#39;MapIterator&#39;] = Object.getPrototypeOf(new Map()[Symbol.iterator]());
+} catch (e) {}
+try {
+	thisGlobalPrototypes[&#39;SetIterator&#39;] = Object.getPrototypeOf(new Set()[Symbol.iterator]());
+} catch (e) {}
+try {
+	// %RegExpStringIteratorPrototype% — matchAll&#39;s iterator (Node 12+).
+	thisGlobalPrototypes[&#39;RegExpStringIterator&#39;] = Object.getPrototypeOf(&#39;a&#39;.matchAll(/a/g));
+} catch (e) {}
+
+// Keys in `thisGlobalPrototypes` that are NOT named globals (so the
+// globalsList/errorsList mapping loops below do not cover them) but MUST still
+// receive proto + identity mappings so their host prototypes are recognized
+// and their `constructor` reads collapse to the sandbox realm.
+const nonGlobalProtoKeys = [
+	&#39;TypedArray&#39;,
+	&#39;ArrayIterator&#39;,
+	&#39;IteratorPrototype&#39;,
+	&#39;StringIterator&#39;,
+	&#39;MapIterator&#39;,
+	&#39;SetIterator&#39;,
+	&#39;RegExpStringIterator&#39;,
+];
 
 // Cache this-realm dangerous function constructors.
 // Used to block raw host Function constructors from leaking when handler</pre>
</details>
<p><b>Fix</b> : The patch extends the list of protected global objects to include all TypedArray and ArrayBuffer related intrinsics, as well as various iterator prototypes. It ensures these prototypes are properly mapped and their constructors are collapsed to the sandbox realm, preventing modification from within the sandbox.</p>
<p>
<a href="https://github.com/advisories/GHSA-3vgf-8m4q-q4qr">Advisory</a> · <a href="https://github.com/patriksimek/vm2/commit/92a10fca7b3ca63bb1574b6795540264f6805b30">Commit</a>
</p>
<hr>
<h3>GHSA-5h3f-q97h-ccvc</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-10-05 · JavaScript<br>
<code>vm2</code> · Pattern: <code>UNCLASSIFIED</code> · 844x across ecosystem
</p>
<p><b>Root cause</b> : </p>
<p><b>Impact</b> : </p>
<p><b>Fix</b> : </p>
<p>
<a href="https://github.com/advisories/GHSA-5h3f-q97h-ccvc">Advisory</a> · <a href="https://github.com/patriksimek/vm2/commit/6ac3916da84e060c403e407b6b6318fcc66b0e72">Commit</a>
</p>
<hr>
<h3>GHSA-88hf-g992-jg85</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-10-05 · JavaScript<br>
<code>vm2</code> · Pattern: <code>PROTOTYPE_POLLUTION→OVERRIDE</code> · 39x across ecosystem
</p>
<p><b>Root cause</b> : The vm2 sandbox allowed an attacker to obtain raw host-realm prototype-reading functions (like `Object.prototype.__proto__` getter or `Object.getPrototypeOf`). By invoking these functions on a wrapped host object, the sandbox could pierce the flattened prototype chain enforced by the bridge, gaining access to intermediate host builtin prototypes (e.g., `EventEmitter.prototype`). These intermediate prototypes were not protected against modification, allowing the attacker to write a callable function onto them.</p>
<p><b>Impact</b> : An attacker could achieve Remote Code Execution (RCE) by installing a malicious function on a shared host prototype (e.g., `EventEmitter.prototype.emit = fn`). When a host-side operation later invoked this function with a host `this` context, the attacker&#39;s code would execute outside the sandbox with host privileges.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/lib/bridge.js
+++ b/lib/bridge.js
@@ -1124,10 +1224,16 @@ function createBridge(otherInit, registerProxy) {
 		const protoDesc = otherSafeGetOwnPropertyDescriptor(otherGlobalPrototypes.Object, &#39;__proto__&#39;);
 		if (protoDesc) {
 			addDangerousHostProtoMutator(protoDesc.set);
-			// Note: we intentionally do NOT add the getter — reading a host
-			// prototype is not, by itself, a privilege escalation primitive, and
-			// blocking the getter would break legitimate `instanceof` and
-			// inspection paths.
+			// SECURITY (GHSA-88hf-g992-jg85): classify the host `__proto__` GETTER
+			// as dangerous-to-DELIVER (not dangerous-to-invoke). Extracting the raw
+			// host getter and calling `gP.call(x)` pierces the bridge&#39;s flattened
+			// prototype view and hands the sandbox the true intermediate host
+			// builtin prototypes (EventEmitter.prototype, etc.), which are writable.
+			// We do NOT add it to the mutator set (which THROWS in the apply trap
+			// and would break legitimate `instanceof` / inspection that internally
+			// walk prototypes); instead we deny its DELIVERY at the read-side
+			// chokepoints so the sandbox can never hold the raw reader to invoke.
+			addDangerousHostProtoReader(protoDesc.get);
 		}
 		// Cache host `Function.prototype.call` / `Function.prototype.apply` as
 		// the canonical indirection primitives. The canonical PoC reaches host</pre>
</details>
<p><b>Fix</b> : The patch introduces `dangerousHostProtoReaders` to identify and prevent the delivery of raw host prototype-reading functions into the sandbox. It also adds `hostObjectsUsedAsPrototype` and `looksLikeHostPrototype` to structurally identify and protect host prototype objects from having sandbox-controlled functions written to them, even if a future read path exposes them.</p>
<p>
<a href="https://github.com/advisories/GHSA-88hf-g992-jg85">Advisory</a> · <a href="https://github.com/patriksimek/vm2/commit/22a43704c04b66823b4064b8a16fe1ad54ad0290">Commit</a>
</p>
<hr>
<h3>GHSA-fcqc-726x-5wfc</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-10-05 · JavaScript<br>
<code>vm2</code> · Pattern: <code>UNCLASSIFIED</code> · 844x across ecosystem
</p>
<p><b>Root cause</b> : The vm2 sandbox allowed sandboxed code to access Node.js&#39;s shared Buffer pool. When a small Buffer was created, it would often be backed by a shared 64 KiB ArrayBuffer. The sandboxed code could then obtain a reference to this entire shared ArrayBuffer, allowing it to read and write memory outside its intended boundaries, including data from other host-realm buffers.</p>
<p><b>Impact</b> : An attacker could achieve a full sandbox escape, leading to arbitrary read and write access to the host-realm memory. This could result in information disclosure (e.g., reading secrets, database rows) and integrity compromise (e.g., corrupting host data), effectively breaking the isolation provided by the sandbox.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/lib/setup-sandbox.js
+++ b/lib/setup-sandbox.js
@@ -584,7 +584,11 @@ class BufferHandler extends ReadOnlyHandler {
 			checkBufferAllocLimit(args[0]);
 			return LocalBuffer.alloc(args[0]);
 		}
-		return apply(LocalBuffer.from, LocalBuffer, args);
+		// SECURITY (GHSA-fcqc-726x-5wfc): deprecated Buffer(array|string|arrayBuffer)
+		// form aliases Buffer.from. Route through `bufferFrom` so the result is
+		// depooled (exact-size backing store) — a raw `LocalBuffer.from` here would
+		// return a pool-backed buffer whose `.buffer` exposes the shared 64 KiB pool.
+		return apply(bufferFrom, LocalBuffer, args);
 	}
 
 	construct(target, args, newTarget) {</pre>
</details>
<p><b>Fix</b> : The patch modifies Buffer creation methods (Buffer.from, Buffer.concat, Buffer.copyBytesFrom, and Buffer constructor aliases) within the sandbox to ensure that any buffer returned to sandboxed code owns its entire backing store. This is achieved by &#39;depooling&#39; buffers that would otherwise be backed by Node&#39;s shared pool, copying their contents into a new, exact-size, non-pooled ArrayBuffer. This prevents sandboxed code from accessing the larger shared memory pool.</p>
<p>
<a href="https://github.com/advisories/GHSA-fcqc-726x-5wfc">Advisory</a> · <a href="https://github.com/patriksimek/vm2/commit/4f2508abeb252aa86eb6761c78b3b000248fb089">Commit</a>
</p>
<hr>
<h3>GHSA-j3hm-6rg5-mchv</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-10-05 · JavaScript<br>
<code>vm2</code> · Pattern: <code>INSECURE_DEFAULT→CONFIG</code> · 42x across ecosystem
</p>
<p><b>Root cause</b> : The vm2 library, when configured with `require.external: true` but without an explicit `require.root`, allowed sandboxed code to use the host&#39;s `require()` function to load arbitrary paths. This effectively granted unrestricted access to the host filesystem and enabled full Remote Code Execution (RCE) because the sandboxed code could load and execute any module available to the host process.</p>
<p><b>Impact</b> : An attacker could escape the sandbox, execute arbitrary code on the host system with the privileges of the vm2 process, and potentially access or manipulate host files.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/lib/cli.js
+++ b/lib/cli.js
 		NodeVM.file(path, {
 			verbose: true,
 			require: {
-				external: true
+				external: true,
+				root: pa.dirname(path),
+				context: &#39;sandbox&#39;
 			}
 		});</pre>
</details>
<p><b>Fix</b> : The patch introduces defense-in-depth measures. It prevents sandboxed code from requiring vm2&#39;s own package (which could lead to nested unrestricted sandboxes). For the CLI, it explicitly sets `require.root` to the script&#39;s directory and `context: &#39;sandbox&#39;` to ensure external requires are sandboxed. It also adds a security warning when `require.external: true` is used without `require.root` in a host context.</p>
<p>
<a href="https://github.com/advisories/GHSA-j3hm-6rg5-mchv">Advisory</a> · <a href="https://github.com/patriksimek/vm2/commit/903017c8a1eae9aba947ec854468b48155e79f86">Commit</a>
</p>
<hr>
<h3>GHSA-wjwh-qqvp-g4p4</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-10-05 · JavaScript<br>
<code>vm2</code> · Pattern: <code>TYPE_CONFUSION→BYPASS</code> · 16x across ecosystem
</p>
<p><b>Root cause</b> : The vm2 sandbox failed to properly isolate WebAssembly streaming compilation APIs. Specifically, `WebAssembly.compileStreaming` and `WebAssembly.instantiateStreaming` could return Promises whose prototype chain reached the host realm&#39;s `Promise.prototype`. This bypasses the sandbox&#39;s `then`/`catch` overrides and `resetPromiseSpecies` mechanism, allowing an attacker to manipulate the `Symbol.species` property of the host Promise and execute arbitrary code in the host context.</p>
<p><b>Impact</b> : An attacker could achieve a complete sandbox escape, executing arbitrary code in the host environment with the privileges of the vm2 process. This leads to remote code execution (RCE) outside the sandbox.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">- if (typeof WebAssembly.promising !== &#39;undefined&#39;) {
- 	localReflectDeleteProperty(WebAssembly, &#39;promising&#39;);
- }
+ if (typeof WebAssembly.compileStreaming !== &#39;undefined&#39;) {
+ 	localReflectDeleteProperty(WebAssembly, &#39;compileStreaming&#39;);
+ }
+ if (typeof WebAssembly.instantiateStreaming !== &#39;undefined&#39;) {
+ 	localReflectDeleteProperty(WebAssembly, &#39;instantiateStreaming&#39;);
+ }</pre>
</details>
<p><b>Fix</b> : The patch removes `WebAssembly.compileStreaming` and `WebAssembly.instantiateStreaming` from the sandbox environment. By removing these APIs, the sources of cross-realm-prototype Promises are eliminated, preventing attackers from leveraging the Promise species bypass to escape the sandbox.</p>
<p>
<a href="https://github.com/advisories/GHSA-wjwh-qqvp-g4p4">Advisory</a> · <a href="https://github.com/patriksimek/vm2/commit/cb85599e4470afa308e7c807b5c6b3ec9bf58b18">Commit</a>
</p>
<hr>
<h3>GHSA-jqmf-mx4f-hfr6</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-10-02 · Python<br>
<code>vibe-trading-ai</code> · Pattern: <code>MISSING_AUTH→ENDPOINT</code> · 78x across ecosystem
</p>
<p><b>Root cause</b> : The application had a &#39;dev mode&#39; where authentication was skipped if the API_AUTH_KEY environment variable was not set. This dev mode was not sufficiently restricted to local clients, allowing remote attackers to bypass authentication entirely if the key was unset. Additionally, several sensitive API endpoints lacked explicit authentication dependencies.</p>
<p><b>Impact</b> : An unauthenticated remote attacker could access sensitive API endpoints, potentially leading to command execution, code injection, or Server-Side Request Forgery (SSRF) if the LLM-callable tools were enabled, or at minimum, information disclosure.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/agent/api_server.py
+++ b/agent/api_server.py
@@ -286,23 +289,74 @@ def _configured_api_key() -&gt; str:
 
 
 async def require_auth(
-    cred: HTTPAuthorizationCredentials = Security(_security),
+    request: Request,
+    cred: Optional[HTTPAuthorizationCredentials] = Security(_security),
 ) -&gt; None:
-    &#34;&#34;&#34;Validate Bearer token against API_AUTH_KEY environment variable.
-    if not api_key:
-        return
-    if not cred or cred.credentials != api_key:
+    api_key = _configured_api_key()
+    if not api_key:
+        if _is_local_client(request):
+            return
+        raise HTTPException(
+            status_code=status.HTTP_403_FORBIDDEN,
+            detail=&#34;API_AUTH_KEY is required for non-local API access&#34;,
+        )
+
+    token = _auth_credential_from_header_or_query(cred, query_api_key, allow_query=allow_query)
+    if not token or not hmac.compare_digest(token, api_key):
         raise HTTPException(status_code=401, detail=&#34;Invalid or missing API key&#34;)</pre>
</details>
<p><b>Fix</b> : The patch introduces stricter checks for dev-mode authentication, ensuring it only applies to local clients. It also explicitly adds `require_auth` dependencies to several previously unprotected API endpoints and uses `hmac.compare_digest` for secure token comparison. New environment flags were added to control shell tools and Docker loopback trust.</p>
<p>
<a href="https://github.com/advisories/GHSA-jqmf-mx4f-hfr6">Advisory</a> · <a href="https://github.com/HKUDS/Vibe-Trading/commit/9454d4a27a763b80e1d6eb5763b86c88e9e4e714">Commit</a>
</p>
<hr>
<h3>GHSA-v2f8-6655-7grj</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-10-02 · Python<br>
<code>vibe-trading-ai</code> · Pattern: <code>MISSING_AUTH→ENDPOINT</code> · 78x across ecosystem
</p>
<p><b>Root cause</b> : The application&#39;s API endpoints lacked proper authentication checks, especially when the API_AUTH_KEY environment variable was not set. In &#39;dev mode&#39; (API_AUTH_KEY unset), the system incorrectly allowed unauthenticated access from non-local clients, treating them as local. Additionally, the comparison of API keys was not constant-time, potentially leaking information.</p>
<p><b>Impact</b> : An unauthenticated attacker could access sensitive API endpoints, including those for file upload and potentially remote code execution (RCE) chains, leading to full system compromise.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/agent/api_server.py
+++ b/agent/api_server.py
@@ -286,10 +289,20 @@ def _configured_api_key() -&gt; str:
 
 async def require_auth(
-    cred: HTTPAuthorizationCredentials = Security(_security),
+    request: Request,
+    cred: Optional[HTTPAuthorizationCredentials] = Security(_security),
 ) -&gt; None:
-    api_key = _configured_api_key()
-    if not api_key:
-        return
-    if not cred or cred.credentials != api_key:
+    _validate_api_auth(request=request, cred=cred)
+
+def _validate_api_auth(
+    *, request: Request, cred: Optional[HTTPAuthorizationCredentials],
+    query_api_key: Optional[str] = None, allow_query: bool = False,
+) -&gt; None:
+    api_key = _configured_api_key()
+    if not api_key:
+        if _is_local_client(request):
+            return
+        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=&#34;API_AUTH_KEY is required for non-local API access&#34;)
+
+    token = _auth_credential_from_header_or_query(cred, query_api_key, allow_query=allow_query)
+    if not token or not hmac.compare_digest(token, api_key):
         raise HTTPException(status_code=401, detail=&#34;Invalid or missing API key&#34;)</pre>
</details>
<p><b>Fix</b> : The patch introduces robust authentication checks, ensuring that even in &#39;dev mode&#39; (API_AUTH_KEY unset), only genuinely local clients can bypass authentication. It also applies authentication to several previously unprotected GET endpoints and uses `hmac.compare_digest` for constant-time API key comparison to prevent timing attacks.</p>
<p>
<a href="https://github.com/advisories/GHSA-v2f8-6655-7grj">Advisory</a> · <a href="https://github.com/HKUDS/Vibe-Trading/commit/9454d4a27a763b80e1d6eb5763b86c88e9e4e714">Commit</a>
</p>
<hr>
<h3>GHSA-647f-g98j-qq25</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-10-01 · JavaScript<br>
<code>vm2</code> · Pattern: <code>UNCLASSIFIED</code> · 844x across ecosystem
</p>
<p><b>Root cause</b> : </p>
<p><b>Impact</b> : </p>
<p><b>Fix</b> : </p>
<p>
<a href="https://github.com/advisories/GHSA-647f-g98j-qq25">Advisory</a> · <a href="https://github.com/patriksimek/vm2/commit/315786904c416be68ff2517b86fb9d71fa6761db">Commit</a>
</p>
<hr>
<h3>GHSA-98xx-8mx4-x7cm</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-10-01 · JavaScript<br>
<code>vm2</code> · Pattern: <code>PRIVILEGE_ESCALATION→ROLE</code> · 52x across ecosystem
</p>
<p><b>Root cause</b> : The vm2 library&#39;s NodeVM allowed sandboxed code to call `tls.setDefaultCACertificates()`. This function, when called from within the sandbox, would modify the host process&#39;s global TLS trust store, effectively allowing the sandboxed code to influence the security of the entire host application&#39;s TLS connections.</p>
<p><b>Impact</b> : An attacker could replace the host process&#39;s default CA trust store, enabling them to intercept and decrypt TLS traffic from the host application by presenting attacker-signed certificates. This leads to a complete compromise of the host&#39;s TLS security.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/lib/builtin.js
+++ b/lib/builtin.js
@@ -210,6 +210,163 @@ if (EventEmitter.EventEmitterAsyncResource) {
 
 // SECURITY (GHSA-98xx-8mx4-x7cm): `tls.setDefaultCACertificates(list)` replaces
 // the calling thread&#39;s process-wide default CA trust store, so every subsequent
-// host TLS client that doesn&#39;t supply its own `ca` accepts attacker-signed
-// certificates. This is the same process-wide-mutation class as the already-
-// denied `dns.setServers`; unlike dns the rest of `tls` is legitimately useful
-// to sandboxed code, so neutralize just this member. (The native function
-// requires a real host array, which the sandbox can forge via `url`&#39;s
-// `URLSearchParams.getAll()` — the bridge unwraps it back to a host array — so
-// argument-side defenses are insufficient; the member itself must be removed.)
+function sanitizeTlsModule(mod) {
+	if (typeof mod.setDefaultCACertificates !== &#39;function&#39;) return mod;
+	const copy = Object.assign({}, mod);
+	copy.setDefaultCACertificates = function setDefaultCACertificates() {
+		throw new Error(&#39;tls.setDefaultCACertificates is disabled in vm2 sandboxes: it replaces the host process default CA trust store (GHSA-98xx-8mx4-x7cm).&#39;);
+	};
+	return copy;
+}</pre>
</details>
<p><b>Fix</b> : The patch introduces a `sanitizeTlsModule` function that intercepts calls to `tls.setDefaultCACertificates`. Instead of forwarding the call to the host function, it now throws an error, preventing sandboxed code from modifying the host&#39;s TLS trust store.</p>
<p>
<a href="https://github.com/advisories/GHSA-98xx-8mx4-x7cm">Advisory</a> · <a href="https://github.com/patriksimek/vm2/commit/aa146a77f859325e079f3bfbfe6d8309af483daa">Commit</a>
</p>
<hr>
<h3>GHSA-h85j-hv3c-qfgq</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-10-01 · JavaScript<br>
<code>vm2</code> · Pattern: <code>INFO_DISCLOSURE→STACK_TRACE</code> · 5x across ecosystem
</p>
<p><b>Root cause</b> : The vm2 sandbox exposed host process-wide singletons like `http.globalAgent` and `https.globalAgent` directly to sandboxed code. While these were wrapped as &#39;read-only&#39;, the `readonly()` proxy only prevents property *assignment*, not method calls or event subscriptions. This allowed the sandbox to subscribe to events on the host&#39;s global agents.</p>
<p><b>Impact</b> : An attacker could subscribe to events on the host&#39;s `globalAgent` objects, allowing them to observe sensitive information such as HTTP/HTTPS request options (including authorization tokens, private host/port details) and released TLS sockets from unrelated host requests, leading to credential and traffic exfiltration.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/lib/builtin.js
+++ b/lib/builtin.js
@@ -210,6 +210,163 @@ if (EventEmitter.EventEmitterAsyncResource) {
 	EventEmitterReferencingAsyncResourceClass = EventEmitterReferencingAsyncResource;
 }
 
+// SECURITY (GHSA-h85j-hv3c-qfgq): `http.globalAgent` / `https.globalAgent` are
+// the real process-wide host singletons. The read-only wrap hands them straight
+// to the sandbox, and `.on(&#39;free&#39;|&#39;keylog&#39;|...)` is a *read*+subscribe, not a
+// property assignment, so it is forwarded to the host object. A sandbox listener
+// then receives live host request options (Authorization tokens, private
+// host/port) and the released host TLSSocket whenever an unrelated host request
+// completes — credential/traffic exfiltration. Replace the exposed `globalAgent`
+// with a fresh sandbox-dedicated Agent so the sandbox can never reach the host
+// singleton.
+function makeHttpAgentSanitizer(agentKey) {
+	return function sanitizeHttpModule(mod) {
+		if (typeof mod.Agent !== &#39;function&#39; || !mod[agentKey]) return mod;
+		const copy = Object.assign({}, mod);
+		const sandboxAgent = new mod.Agent();
+		// The exposed globalAgent is the sandbox-dedicated one — a direct read +
+		// `.on(&#39;free&#39;)` reaches only this empty agent, never the host singleton.
+		copy[agentKey] = sandboxAgent;</pre>
</details>
<p><b>Fix</b> : The patch replaces the exposed `http.globalAgent` and `https.globalAgent` with fresh, sandbox-dedicated `Agent` instances. It also modifies the `request()` and `get()` methods of the `http` and `https` modules to default to using these sandbox-dedicated agents, preventing sandboxed code from interacting with the host&#39;s shared agents.</p>
<p>
<a href="https://github.com/advisories/GHSA-h85j-hv3c-qfgq">Advisory</a> · <a href="https://github.com/patriksimek/vm2/commit/aa146a77f859325e079f3bfbfe6d8309af483daa">Commit</a>
</p>
<hr>
<h3>GHSA-6rf4-v2fh-m6p4</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-09-24 · JavaScript<br>
<code>suneditor</code> · Pattern: <code>UNSANITIZED_INPUT→XSS</code> · 127x across ecosystem
</p>
<p><b>Root cause</b> : The vulnerability existed because the SunEditor&#39;s sanitizer could be bypassed. Specifically, when setting code data to the editor, the `_deleteDisallowedTags` function was not consistently applied, allowing malicious HTML content (like script tags) to persist. Additionally, the regular expressions used to identify and remove disallowed tags were not comprehensive enough, failing to catch certain variations or combinations of tags like &#39;style&#39;, &#39;meta&#39;, &#39;link&#39;, and namespaced tags.</p>
<p><b>Impact</b> : An attacker could inject arbitrary JavaScript code into the editor&#39;s content, leading to Cross-Site Scripting (XSS). This could allow them to steal user sessions, deface websites, redirect users, or perform other malicious actions within the context of the user&#39;s browser.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/src/lib/core.js
+++ b/src/lib/core.js
@@ -4764,7 +4764,7 @@ export default function (context, pluginCallButtons, plugins, lang, options, _re
          * @private
          */
         _setCodeDataToEditor: function () {
-            const code_html = this._getCodeView();
+            const code_html = this._deleteDisallowedTags(this._getCodeView());
 
             if (options.fullPage) {
                 const parseDocument = this._parser.parseFromString(code_html, &#39;text/html&#39;);</pre>
</details>
<p><b>Fix</b> : The patch addresses the vulnerability by ensuring that the `_deleteDisallowedTags` function is called when setting code data to the editor, thus sanitizing the input. It also updates the regular expressions (`__disallowedTagsRegExp` and `__disallowedTagNameRegExp`) to include a broader range of potentially malicious tags, such as &#39;style&#39;, &#39;meta&#39;, &#39;link&#39;, and namespaced tags (e.g., &#39;svg:script&#39;), preventing their injection.</p>
<p>
<a href="https://github.com/advisories/GHSA-6rf4-v2fh-m6p4">Advisory</a> · <a href="https://github.com/JiHong88/suneditor/commit/a94ace269c7102bfb6de58a27a6547bc4eb09045">Commit</a>
</p>
<hr>
<h3>GHSA-g5f9-3xfg-p9mf</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-09-24 · Python<br>
<code>decepticon-sdk</code> · Pattern: <code>UNCLASSIFIED</code> · 844x across ecosystem
</p>
<p><b>Root cause</b> : The vulnerability existed because attacker-controlled web crawl output, when composed into an LLM&#39;s context, could contain special-token literals (e.g., &lt;|im_start|&gt;, [INST]) that a self-hosted LLM tokenizer would parse as structural role delimiters. This allowed an attacker to forge system or operator turns, bypassing the intended quarantine envelope.</p>
<p><b>Impact</b> : An attacker could achieve role-boundary forgery, making the LLM treat attacker-controlled input as authoritative system or operator instructions. This could lead to a full bypass of security controls and potentially arbitrary code execution or data exfiltration, depending on the LLM&#39;s capabilities and downstream integrations.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/packages/decepticon/decepticon/middleware/untrusted_output.py
+++ b/packages/decepticon/decepticon/middleware/untrusted_output.py
@@ -145,5 +146,5 @@ def _format_envelope(
     body: str,
 ) -&gt; str:
     cats_attr = f&#39; categories=&#34;{&#34;,&#34;.join(categories)}&#34;&#39; if categories else &#34;&#34;
-    safe_body = _MARKER_RE.sub(&#34;UNTRUSTED_TOOL\u200bOUTPUT&#34;, body)
+    safe_body = _MARKER_RE.sub(&#34;UNTRUSTED_TOOL\u200bOUTPUT&#34;, neutralize_special_tokens(body))
     return (</pre>
</details>
<p><b>Fix</b> : The patch introduces a `neutralize_special_tokens` function that identifies and &#39;defangs&#39; known chat-template special-token literals by inserting a zero-width space (U+200B) immediately after the opening bracket. This prevents the tokenizer from recognizing the literal as a special token while keeping the text visually identical. This neutralization is applied to all untrusted content before it is composed into the LLM context.</p>
<p>
<a href="https://github.com/advisories/GHSA-g5f9-3xfg-p9mf">Advisory</a> · <a href="https://github.com/BitterSecurity/Decepticon/commit/79ee2aaf22f4c36a5b1968f6ca3f8086b6e35b67">Commit</a>
</p>
<hr>
<h3>GHSA-wrhw-j3f9-8vc6</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-09-22 · Python<br>
<code>mcp-atlassian</code> · Pattern: <code>UNSANITIZED_INPUT→SQL</code> · 40x across ecosystem
</p>
<p><b>Root cause</b> : The application was vulnerable to JQL injection because it did not properly sanitize user-supplied project filters before incorporating them into JQL queries. Additionally, it lacked robust SSRF protection, allowing for potential server-side request forgery through redirect validation and DNS rebinding attacks.</p>
<p><b>Impact</b> : An attacker could bypass configured project restrictions in Jira, potentially accessing or manipulating data outside their authorized scope. The SSRF vulnerabilities could allow an attacker to make arbitrary requests from the server, potentially accessing internal network resources or sensitive cloud metadata.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/src/mcp_atlassian/jira/search.py
+++ b/src/mcp_atlassian/jira/search.py
-            filter_to_use = projects_filter or self.config.projects_filter
-            if filter_to_use:
-                projects = [p.strip() for p in filter_to_use.split(&#34;,&#34;)]
+            for filter_str in (self.config.projects_filter, projects_filter):
+                if filter_str:
+                    jql = self._and_projects_filter(jql, filter_str)</pre>
</details>
<p><b>Fix</b> : The patch refactors JQL filtering to ensure that the configured project allowlist is always ANDed with any user-supplied filters, preventing bypass. It also introduces SSRF protection by validating redirects and pinning DNS resolution to prevent rebinding attacks.</p>
<p>
<a href="https://github.com/advisories/GHSA-wrhw-j3f9-8vc6">Advisory</a> · <a href="https://github.com/sooperset/mcp-atlassian/commit/b041733473f95119dd539542a43c280737a8e460">Commit</a>
</p>
<hr>
<h3>GHSA-jrc7-96c5-q579</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-09-08 · JavaScript<br>
<code>maplibre-gl</code> · Pattern: <code>UNSANITIZED_INPUT→XSS</code> · 127x across ecosystem
</p>
<p><b>Root cause</b> : The vulnerability existed because the `DOM.removeAttributes` method iterated directly over `elem.attributes`, which is a live `NamedNodeMap`. When a dangerous attribute was removed using `elem.removeAttribute(name)`, it modified the live collection, causing the loop to skip the next attribute in the original sequence, thus failing to sanitize all malicious attributes.</p>
<p><b>Impact</b> : An attacker could bypass the HTML sanitizer, allowing them to inject malicious scripts or content into the DOM. This could lead to arbitrary code execution in the user&#39;s browser, session hijacking, or defacement of the web application.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/src/util/dom.ts
+++ b/src/util/dom.ts
@@ -131,7 +131,7 @@ export class DOM {
 	 * @param elem - The element
 	 */
     private static removeAttributes(elem: Element) {
-        for (const {name, value} of elem.attributes) {
+        for (const {name, value} of Array.from(elem.attributes)) {
             if (!DOM.isPossiblyDangerous(name, value)) continue;
             elem.removeAttribute(name);
         }</pre>
</details>
<p><b>Fix</b> : The patch fixes the vulnerability by converting the live `NamedNodeMap` returned by `elem.attributes` into a static array using `Array.from()`. This ensures that all attributes are processed and sanitized, even when attributes are removed during the iteration, preventing the sanitizer bypass.</p>
<p>
<a href="https://github.com/advisories/GHSA-jrc7-96c5-q579">Advisory</a> · <a href="https://github.com/maplibre/maplibre-gl-js/commit/1da69f3cd913a39fa948708e01478663bf48bc27">Commit</a>
</p>
<hr>
<h3>GHSA-fph3-ghq9-vw66</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-09-03 · Go<br>
<code>github.com/siyuan-note/siyuan/kernel</code> · Pattern: <code>UNSANITIZED_INPUT→SQL</code> · 40x across ecosystem
</p>
<p><b>Root cause</b> : The application directly concatenated user-supplied input into SQL queries and regular expressions without proper sanitization or parameterization. Specifically, the `fullTextSearchAssetContent` function, when `method` was set to 2 (SQL) or 3 (Regexp), allowed unauthenticated users to inject arbitrary SQL or regular expression syntax.</p>
<p><b>Impact</b> : An unauthenticated attacker could execute arbitrary SQL commands on the underlying database, leading to data exfiltration, modification, or deletion. Additionally, they could perform REGEXP injection, potentially causing denial of service or information disclosure through crafted regular expressions.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/kernel/model/asset_content.go
+++ b/kernel/model/asset_content.go
@@ -74,10 +75,12 @@ func GetAssetContent(id, query string, queryMethod int) (ret *AssetContent) {
 
 	table := &#34;asset_contents_fts_case_insensitive&#34;
-	filter := &#34; id = &#39;&#34; + id + &#34;&#39;&#34;
+	filter := &#34;id = ?&#34;
+	args := []any{id}
 	if &#34;&#34; != query {
-		filter += &#34; AND `&#34; + table + &#34;` MATCH &#39;&#34; + buildAssetContentColumnFilter() + &#34;:(&#34; + query + &#34;)&#39;&#34;
+		filter += &#34; AND `&#34; + table + &#34;` MATCH ?&#34;
+		args = append(args, buildAssetContentColumnFilter()+&#34;:(&#34;+query+&#34;)&#34;)
 	}
 
 	projections := &#34;id, name, ext, path, size, updated, &#34; +
-		highlight(&#34; + table + &#34;, 6, &#39;&#34; + search.SearchMarkLeft + &#34;&#39;, &#39;&#34; + search.SearchMarkRight + &#34;&#39;) AS content&#34;
-	stmt := &#34;SELECT &#34; + projections + &#34; FROM &#34; + table + &#34; WHERE &#34; + filter
-	assetContents := sql.SelectAssetContentsRawStmt(stmt, 1, 1)
+		highlight(&#34; + table + &#34;, 6, &#39;&#34; + search.SearchMarkLeft + &#34;&#39;, &#39;&#34; + search.SearchMarkRight + &#34;&#39;) AS content&#34;
+	stmt := &#34;SELECT &#34; + projections + &#34; FROM &#34; + table + &#34; WHERE &#34; + filter
+	assetContents := sql.SelectAssetContentsRawStmtNoParseArgs(stmt, args, 1)</pre>
</details>
<p><b>Fix</b> : The patch refactors SQL query construction to use parameterized queries (prepared statements) via `?` placeholders and `sql.SelectAssetContentsRawStmtNoParseArgs` for all affected functions. It also modifies the regular expression search to use parameterized queries for the `REGEXP` operator, preventing direct concatenation of user input into the regex pattern.</p>
<p>
<a href="https://github.com/advisories/GHSA-fph3-ghq9-vw66">Advisory</a> · <a href="https://github.com/siyuan-note/siyuan/commit/cf42dd5680c8f2d50cebfada5d639c8d59faf50e">Commit</a>
</p>
<hr>
<h3>GHSA-q2vg-7qgx-x5fc</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-09-03 · Go<br>
<code>github.com/siyuan-note/siyuan/kernel</code> · Pattern: <code>UNSANITIZED_INPUT→SQL</code> · 40x across ecosystem
</p>
<p><b>Root cause</b> : The application constructed SQL queries by directly concatenating user-controlled input (mentionKeywords and keyword) into the FTS MATCH clause without proper escaping. This allowed an attacker to inject arbitrary SQL into the query by crafting malicious input containing double quotes, breaking out of the intended string literal.</p>
<p><b>Impact</b> : An attacker could execute arbitrary SQL commands within the database, potentially leading to data exfiltration, modification, or deletion, and could bypass intended access controls.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">- buf.WriteString(&#34;\&#34;&#34; + mentionKeyword + &#34;\&#34;&#34;)
+ buf.WriteString(quoteFTSPhrase(mentionKeyword))
...
- sqlBlocks := sql.SelectBlocksRawStmtInBox(query, 1, Conf.Search.Limit, boxID)
+ sqlBlocks := sql.SelectBlocksRawStmtArgsInBox(query, args, Conf.Search.Limit, boxID)</pre>
</details>
<p><b>Fix</b> : The patch introduces a `quoteFTSPhrase` function to properly escape double quotes in user input for FTS queries. It also refactors the query construction to use parameterized queries via `sql.SelectBlocksRawStmtArgsInBox`, ensuring that user input is treated as data rather than executable code.</p>
<p>
<a href="https://github.com/advisories/GHSA-q2vg-7qgx-x5fc">Advisory</a> · <a href="https://github.com/siyuan-note/siyuan/commit/1a5b3431d5ab3036b19c1cc79486fedd6906fb57">Commit</a>
</p>
<hr>
<h3>GHSA-vh22-h7hf-www7</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-09-03 · Go<br>
<code>github.com/siyuan-note/siyuan/kernel</code> · Pattern: <code>UNCLASSIFIED</code> · 844x across ecosystem
</p>
<p><b>Root cause</b> : </p>
<p><b>Impact</b> : </p>
<p><b>Fix</b> : </p>
<p>
<a href="https://github.com/advisories/GHSA-vh22-h7hf-www7">Advisory</a> · <a href="https://github.com/siyuan-note/siyuan/commit/0015cbafbf685363b217bbc46283a3c0f51c79fa">Commit</a>
</p>
<hr>
<h3>GHSA-x2rj-828p-hx9m</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-08-21 · Python<br>
<code>xinference</code> · Pattern: <code>UNSANITIZED_INPUT→COMMAND</code> · 110x across ecosystem
</p>
<p><b>Root cause</b> : The application used the unsafe `eval()` function to parse tool-call arguments from untrusted model outputs. An attacker could craft a malicious string that, when evaluated by `eval()`, would execute arbitrary Python code on the server.</p>
<p><b>Impact</b> : An attacker could achieve full remote code execution on the server hosting the Xinference application, leading to complete system compromise.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/xinference/model/llm/utils.py
+++ b/xinference/model/llm/utils.py
-            data = eval(text, {}, {})
+            data = json.loads(text)
+        except (json.JSONDecodeError, TypeError):
+            try:
+                data = ast.literal_eval(text)</pre>
</details>
<p><b>Fix</b> : The patch replaces the unsafe `eval()` calls with a safer parsing mechanism. It first attempts to parse the input as JSON and, if that fails, falls back to `ast.literal_eval()`. `ast.literal_eval()` is a safe alternative to `eval()` for evaluating strings containing Python literal structures, preventing arbitrary code execution.</p>
<p>
<a href="https://github.com/advisories/GHSA-x2rj-828p-hx9m">Advisory</a> · <a href="https://github.com/xorbitsai/inference/commit/1b3d220f342ce68d34cec4586d9409d457dadc42">Commit</a>
</p>
<hr>
<h3>GHSA-7pwq-q9jf-539h</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-08-18 · Ruby<br>
<code>kobako</code> · Pattern: <code>DESERIALIZATION→RCE</code> · 30x across ecosystem
</p>
<p><b>Root cause</b> : The `kobako` gem allowed guest code to invoke arbitrary methods on host objects via `public_send`. This included Ruby&#39;s reflection and metaprogramming methods like `send`, `public_send`, `instance_eval`, `method`, `tap`, and `instance_variable_get`. An attacker could chain these methods to bypass the sandbox and execute arbitrary code on the host system.</p>
<p><b>Impact</b> : An attacker could achieve Remote Code Execution (RCE) on the host system, completely escaping the intended sandbox environment. This allows full control over the host machine.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/lib/kobako/transport/dispatcher.rb
+++ b/lib/kobako/transport/dispatcher.rb
@@ -109,14 +120,33 @@ def encode_caught_error(error)
       # so the same call site handles both cases without an explicit
       # conditional.
       def invoke(target, method, args, kwargs, yielder = nil)
+        name = method.to_sym
+        reject_meta_method!(target, name)
         block = yielder&amp;.to_proc
         if kwargs.empty?
-          target.public_send(method.to_sym, *args, &amp;block)
+          target.public_send(name, *args, &amp;block)
         else
-          target.public_send(method.to_sym, *args, **kwargs, &amp;block)
+          target.public_send(name, *args, **kwargs, &amp;block)
         end
       end
 
+      # Guard the +public_send+ below against ambient reflection methods
+      # (see {META_OWNERS}).
+      def reject_meta_method!(target, name)
+        owner = target.public_method(name).owner
+        return unless META_OWNERS.include?(owner)
+
+        raise UndefinedTargetError, &#34;method #{name.inspect} is not a Service method&#34;
+      rescue NameError
+        return if target.respond_to?(name)
+
+        raise UndefinedTargetError, &#34;no public method #{name.inspect} on target&#34;
+      end</pre>
</details>
<p><b>Fix</b> : The patch introduces a `META_OWNERS` constant listing modules that contain dangerous reflection methods. A new `reject_meta_method!` guard is added to the `invoke` method, which checks if the method being called belongs to one of these meta modules. If so, the call is rejected, preventing guest code from invoking these sensitive methods.</p>
<p>
<a href="https://github.com/advisories/GHSA-7pwq-q9jf-539h">Advisory</a> · <a href="https://github.com/elct9620/kobako/commit/64f84700c81f44902bed9211318d5362f44987b3">Commit</a>
</p>
<hr>
<h3>GHSA-p849-8hwh-84j9</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-07-31 · JavaScript<br>
<code>@nocobase/plugin-notification-in-app-message</code> · Pattern: <code>UNCLASSIFIED</code> · 844x across ecosystem
</p>
<p><b>Root cause</b> : </p>
<p><b>Impact</b> : </p>
<p><b>Fix</b> : </p>
<p>
<a href="https://github.com/advisories/GHSA-p849-8hwh-84j9">Advisory</a> · <a href="https://github.com/nocobase/nocobase/commit/68d64e3fcfb8be2ae4f3bfc9e1ee3f85b87c89ce">Commit</a>
</p>
<hr>
<h3>GHSA-2956-977x-2w3r</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-07-30 · Python<br>
<code>flyto-core</code> · Pattern: <code>PATH_TRAVERSAL→FILE_WRITE</code> · 66x across ecosystem
</p>
<p><b>Root cause</b> : The application allowed an attacker to control both the target file path and its base directory when writing files. The existing path traversal check was ineffective because it validated the output path against a caller-supplied output directory, which an attacker could manipulate to bypass the check and write files outside the intended sandbox.</p>
<p><b>Impact</b> : An attacker could write arbitrary files to any location on the file system where the application has write permissions, potentially leading to remote code execution, data corruption, or denial of service.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">-    base_real = os.path.realpath(output_dir)
-    target_real = os.path.realpath(output_path)
-    if os.path.commonpath([base_real, target_real]) != base_real:
-        raise Exception(&#39;Invalid file path&#39;)
+    try:
+        target_real = validate_path_with_env_config(output_path)
+    except PathTraversalError as e:
+        raise ModuleError(str(e), code=&#34;PATH_TRAVERSAL&#34;)</pre>
</details>
<p><b>Fix</b> : The patch removes the ineffective local path traversal check and replaces it with a centralized `validate_path_with_env_config` utility function. This new function enforces that all file write operations are confined to a secure, operator-configured sandbox directory (`FLYTO_SANDBOX_DIR`), preventing path traversal attacks.</p>
<p>
<a href="https://github.com/advisories/GHSA-2956-977x-2w3r">Advisory</a> · <a href="https://github.com/flytohub/flyto-core/commit/d5f89d71303e3c1e6418d347c5c55fcd173cc8cc">Commit</a>
</p>
<hr>
<h3>GHSA-4p3g-4hcj-wpvx</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-07-29 · Go<br>
<code>github.com/prebid/prebid-server</code> · Pattern: <code>SSRF→INTERNAL_ACCESS</code> · 141x across ecosystem
</p>
<p><b>Root cause</b> : The application was vulnerable to Server-Side Request Forgery (SSRF) because it constructed outbound HTTP requests using user-controlled input (e.g., &#39;endpoint&#39;, &#39;host&#39;, &#39;account&#39;) without sufficient validation. An attacker could manipulate these parameters to make the server send requests to arbitrary internal or external hosts.</p>
<p><b>Impact</b> : An attacker could force the Prebid Server to make requests to internal network resources, potentially extracting sensitive data from the host environment (e.g., cloud metadata, internal services) or bypassing firewall rules.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- /dev/null
+++ b/util/urlutil/security.go
@@ -0,0 +1,12 @@
+package urlutil
+
+import &#34;regexp&#34;
+
+var safeHostPattern = regexp.MustCompile(`^[a-zA-Z0-9.-]+(:[0-9]+)?$`)
+
+// IsSafeHost returns true for bare hostnames with an optional port.
+// It intentionally rejects URL control characters such as &#39;/&#39;, &#39;?&#39;, &#39;#&#39;, and &#39;@&#39;
+// so user-supplied host values cannot rewrite the outbound request URL.
+func IsSafeHost(host string) bool {
+	return safeHostPattern.MatchString(host)
+}

--- adapters/acuityads/acuityads.go
+++ b/adapters/acuityads/acuityads.go
@@ -107,6 +108,9 @@ func (a *AcuityAdsAdapter) buildEndpointURL(params *openrtb_ext.ExtAcuityAds) (string, error) {
 }</pre>
</details>
<p><b>Fix</b> : The patch introduces a new utility function, `urlutil.IsSafeHost`, which validates user-supplied hostnames to ensure they do not contain URL control characters. This function is then applied to all user-controlled parameters that are used in constructing outbound request URLs, preventing attackers from injecting malicious URLs or paths.</p>
<p>
<a href="https://github.com/advisories/GHSA-4p3g-4hcj-wpvx">Advisory</a> · <a href="https://github.com/prebid/prebid-server/commit/494ac271cd4b5024df9123ef25ca3cff96390be3">Commit</a>
</p>
<hr>
<h3>GHSA-f25v-x6vr-962g</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-07-24 · PHP<br>
<code>pheditor/pheditor</code> · Pattern: <code>MISSING_AUTH→ENDPOINT</code> · 78x across ecosystem
</p>
<p><b>Root cause</b> : The vulnerability existed because the application had a hardcoded default password &#39;admin&#39; which, when set, triggered a forced password change flow. During this flow, the application did not verify the current password provided by the user against the actual stored password. Instead, it only checked if the submitted password was &#39;admin&#39; (which was hardcoded into a hidden input field in the password change form), allowing an attacker to bypass authentication and set a new password without knowing the original one.</p>
<p><b>Impact</b> : An attacker could completely bypass the authentication mechanism, gain administrative access to the Pheditor application, and potentially execute arbitrary code or modify files on the server, leading to full system compromise.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/pheditor.php
+++ b/pheditor.php
@@ -152,7 +152,9 @@
 
 if (empty(PASSWORD) === false &amp;&amp; (isset($_SESSION[&#39;pheditor_admin&#39;], $_SESSION[&#39;pheditor_password&#39;]) === false || $_SESSION[&#39;pheditor_admin&#39;] !== true || $_SESSION[&#39;pheditor_password&#39;] != PASSWORD)) {
     if (isset($_POST[&#39;pheditor_password&#39;]) &amp;&amp; empty($_POST[&#39;pheditor_password&#39;]) === false) {
-        if (PASSWORD == hash(&#39;sha512&#39;, &#39;admin&#39;)) {
+        $submitted_hash = hash(&#39;sha512&#39;, $_POST[&#39;pheditor_password&#39;]);
+
+        if (PASSWORD == hash(&#39;sha512&#39;, &#39;admin&#39;) &amp;&amp; $submitted_hash === PASSWORD) {
             if (isset($_POST[&#39;pheditor_new_password&#39;]) &amp;&amp; isset($_POST[&#39;pheditor_confirm_password&#39;])) {
                 if ($_POST[&#39;pheditor_new_password&#39;] === &#39;admin&#39;) {
                     $error = &#39;Password cannot be admin&#39;;</pre>
</details>
<p><b>Fix</b> : The patch introduces a check to ensure that when the hardcoded &#39;admin&#39; password triggers a forced password change, the submitted password hash also matches the actual stored password. This prevents an attacker from simply submitting &#39;admin&#39; as the current password without knowing the real password, thereby enforcing proper authentication during the password change process.</p>
<p>
<a href="https://github.com/advisories/GHSA-f25v-x6vr-962g">Advisory</a> · <a href="https://github.com/pheditor/pheditor/commit/0978bcda644832b67357340e2f271e32d86fdf86">Commit</a>
</p>
<hr>
<h3>GHSA-w28w-gp39-m4p6</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-07-24 · JavaScript<br>
<code>@prompty/core</code> · Pattern: <code>UNSANITIZED_INPUT→TEMPLATE</code> · 28x across ecosystem
</p>
<p><b>Root cause</b> : The Nunjucks templating engine was used to render user-controlled templates and inputs without sufficient sanitization or sandboxing. This allowed attackers to access and invoke dangerous properties and methods (like `__proto__`, `constructor`, `prototype`) through template expressions, leading to arbitrary code execution.</p>
<p><b>Impact</b> : An attacker could achieve remote code execution on the server by injecting malicious template code, potentially compromising the entire system.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/runtime/typescript/packages/core/src/renderers/nunjucks.ts
+++ b/runtime/typescript/packages/core/src/renderers/nunjucks.ts
@@ -13,11 +13,91 @@ import type { Prompty } from &#34;../model/agent/prompty.js&#34;;
 import type { Renderer } from &#34;../core/interfaces.js&#34;;
 import { prepareRenderInputs } from &#34;./common.js&#34;;
 
+type NunjucksRuntime = {
+  memberLookup: (object: unknown, property: unknown) =&gt; unknown;
+  callWrap: (callable: unknown, name: string, context: unknown, args: unknown[]) =&gt; unknown;
+};
+
+const UNSAFE_PROPERTIES = new Set([&#34;__proto__&#34;, &#34;constructor&#34;, &#34;prototype&#34;]);
+
 const env = new nunjucks.Environment(null, {
   autoescape: false,
   throwOnUndefined: false,
 });
 
+function safeMemberLookup(object: unknown, property: unknown): unknown {
+  if (typeof property === &#34;string&#34; &amp;&amp; UNSAFE_PROPERTIES.has(property)) {
+    throw new Error(`Unsafe template member access: ${property}`);
+  }
+
+  if (
+    (typeof property !== &#34;string&#34; &amp;&amp; typeof property !== &#34;number&#34;) ||
+    object === null ||
+    typeof object !== &#34;object&#34;
+  ) {
+    return undefined;
+  }
+
+  const descriptor = Object.getOwnPropertyDescriptor(object, property);
+  return descriptor !== undefined &amp;&amp; &#34;value&#34; in descriptor ? descriptor.value : undefined;
+}
+
+function safeCallWrap(_callable: unknown, name: string, _context: unknown, _args: unknown[]): never {
+  throw new Error(`Template function calls are not allowed: ${name}`);
+}
+
+function sanitizeValue(value: unknown, seen = new WeakMap&lt;object, unknown&gt;()): unknown {
+  if (value === null || typeof value === &#34;string&#34; || typeof value === &#34;number&#34; || typeof value === &#34;boolean&#34;) {
+    return value;
+  }
+
+  if (typeof value !== &#34;object&#34;) {
+    return undefined;
+  }
+
+  const existing = seen.get(value);
+  if (existing !== undefined) {
+    return existing;
+  }
+
+  if (Array.isArray(value)) {
+    const result: unknown[] = [];
+    seen.set(value, result);
+    for (const item of value) {
+      result.push(sanitizeValue(item, seen));
+    }
+    return result;
+  }
+
+  const result = Object.create(null) as Record&lt;string, unknown&gt;;
+  seen.set(value, result);
+  for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
+    if (!UNSAFE_PROPERTIES.has(key) &amp;&amp; &#34;value&#34; in descriptor) {
+      result[key] = sanitizeValue(descriptor.value, seen);
+    }
+  }
+  return result;
+}
+
+function sanitizeInputs(inputs: Record&lt;string, unknown&gt;): Record&lt;string, unknown&gt; {
+  return sanitizeValue(inputs) as Record&lt;string, unknown&gt;;
+}
+
+function renderSafely(template: string, inputs: Record&lt;string, unknown&gt;): string {
+  const runtime = nunjucks.runtime as unknown as NunjucksRuntime;
+  const memberLookup = runtime.memberLookup;
+  const callWrap = runtime.callWrap;
+  runtime.memberLookup = safeMemberLookup;
+  runtime.callWrap = safeCallWrap;
+
+  try {
+    return env.renderString(template, inputs);
+  } finally {
+    runtime.memberLookup = memberLookup;
+    runtime.callWrap = callWrap;
+  }
+}
+
 export class NunjucksRenderer implements Renderer {
   async render(
     agent: Prompty,
     template: string,
     inputs: Record&lt;string, unknown&gt;,
   ): Promise&lt;string&gt; {
     const [modified] = prepareRenderInputs(agent, inputs);
-    return env.renderString(template, modified);
+    return renderSafely(template, sanitizeInputs(modified));
   }
 }</pre>
</details>
<p><b>Fix</b> : The patch introduces `safeMemberLookup` and `safeCallWrap` functions to restrict access to unsafe properties and prevent function calls within templates. It also includes `sanitizeValue` and `sanitizeInputs` to recursively clean input data by creating a new object with only safe properties, effectively sandboxing the template rendering environment.</p>
<p>
<a href="https://github.com/advisories/GHSA-w28w-gp39-m4p6">Advisory</a> · <a href="https://github.com/microsoft/prompty/commit/047756f4c8caf91c5868eeb42520c938393277b0">Commit</a>
</p>
<hr>
<h3>GHSA-v5px-423j-pf7p</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-07-08 · Go<br>
<code>github.com/nuclio/nuclio</code> · Pattern: <code>UNCLASSIFIED</code> · 844x across ecosystem
</p>
<p><b>Root cause</b> : </p>
<p><b>Impact</b> : </p>
<p><b>Fix</b> : </p>
<p>
<a href="https://github.com/advisories/GHSA-v5px-423j-pf7p">Advisory</a> · <a href="https://github.com/nuclio/nuclio/commit/3356b86a8bfab3f960aa420310ebff765df9dede">Commit</a>
</p>
<hr>
<h3>GHSA-73cv-556c-w3g6</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-06-26 · Python<br>
<code>mcp-pinot-server</code> · Pattern: <code>UNSANITIZED_INPUT→SQL</code> · 40x across ecosystem
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
<code>gogs.io/gogs</code> · Pattern: <code>UNCLASSIFIED</code> · 844x across ecosystem
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
<code>vm2</code> · Pattern: <code>UNCLASSIFIED</code> · 844x across ecosystem
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
<code>vm2</code> · Pattern: <code>UNCLASSIFIED</code> · 844x across ecosystem
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
<code>vm2</code> · Pattern: <code>UNCLASSIFIED</code> · 844x across ecosystem
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
<code>vm2</code> · Pattern: <code>UNCLASSIFIED</code> · 844x across ecosystem
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
<code>@nyariv/sandboxjs</code> · Pattern: <code>TYPE_CONFUSION→BYPASS</code> · 16x across ecosystem
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
<code>github.com/free5gc/smf</code> · Pattern: <code>MISSING_AUTH→ENDPOINT</code> · 78x across ecosystem
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
<code>github.com/enchant97/note-mark/backend</code> · Pattern: <code>INSECURE_DEFAULT→CONFIG</code> · 42x across ecosystem
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
<code>github.com/jkroepke/openvpn-auth-oauth2</code> · Pattern: <code>MISSING_AUTH→ENDPOINT</code> · 78x across ecosystem
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
<code>wwbn/avideo</code> · Pattern: <code>UNSANITIZED_INPUT→XSS</code> · 127x across ecosystem
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
<code>github.com/daptin/daptin</code> · Pattern: <code>PATH_TRAVERSAL→FILE_WRITE</code> · 66x across ecosystem
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
<code>axios</code> · Pattern: <code>UNSANITIZED_INPUT→HEADER</code> · 22x across ecosystem
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
<h3>GHSA-w794-rj3p-xv45</h3>
<p>
<code>CRITICAL 9.9</code> · 2026-10-07 · Python<br>
<code>lfx</code> · Pattern: <code>UNCLASSIFIED</code> · 844x across ecosystem
</p>
<p><b>Root cause</b> : </p>
<p><b>Impact</b> : </p>
<p><b>Fix</b> : </p>
<p>
<a href="https://github.com/advisories/GHSA-w794-rj3p-xv45">Advisory</a> · <a href="https://github.com/langflow-ai/langflow/commit/eba285edf1dd4a33bf23a9cb8113c991fcdf3d1d">Commit</a>
</p>
<hr>
<h3>GHSA-8qpj-27x8-pwpq</h3>
<p>
<code>CRITICAL 9.9</code> · 2026-10-06 · Python<br>
<code>langflow</code> · Pattern: <code>MISSING_AUTHZ→RESOURCE</code> · 125x across ecosystem
</p>
<p><b>Root cause</b> : The Langflow application&#39;s PythonREPLComponent and PythonREPLToolComponent allowed authenticated users to execute arbitrary Python code without proper authorization checks. Although there was a `allow_custom_components` setting, it was not enforced for these specific components, enabling a bypass.</p>
<p><b>Impact</b> : An authenticated attacker could execute arbitrary Python code on the server, leading to full system compromise (Remote Code Execution) and potential privilege escalation.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/src/lfx/src/lfx/components/tools/python_repl.py
+++ b/src/lfx/src/lfx/components/tools/python_repl.py
@@ -78,6 +78,9 @@ def get_globals(self, global_imports: str | list[str]) -&gt; dict:
     def build_tool(self) -&gt; Tool:
         def run_python_code(code: str) -&gt; str:
             try:
+                # Refuse to run user code when allow_custom_components is disabled
+                # (GHSA-8qpj-27x8-pwpq).
+                ensure_code_execution_enabled()
                 # Validate the exact (sanitized) code that will run, rejecting inline</pre>
</details>
<p><b>Fix</b> : The patch introduces a new function, `ensure_code_execution_enabled()`, which is called before any user-supplied Python code is executed in the PythonREPLComponent and PythonREPLToolComponent. This function checks the `allow_custom_components` setting and raises an error if code execution is disabled, thereby enforcing the security policy.</p>
<p>
<a href="https://github.com/advisories/GHSA-8qpj-27x8-pwpq">Advisory</a> · <a href="https://github.com/langflow-ai/langflow/commit/2754c84aad1306f463db1c3bbb3e8ffbe85da77d">Commit</a>
</p>
<hr>
<h3>GHSA-46pr-c5wc-xffx</h3>
<p>
<code>CRITICAL 9.9</code> · 2026-10-01 · JavaScript<br>
<code>vm2</code> · Pattern: <code>DESERIALIZATION→RCE</code> · 30x across ecosystem
</p>
<p><b>Root cause</b> : The vm2 sandbox allowed access to certain Node.js built-in modules (like `crypto`) without properly sanitizing or restricting dangerous functions. Specifically, `crypto.setEngine()` could be called by sandboxed code, which then instructed OpenSSL to dynamically load a native library from a specified path into the host process. The constructor of this native library would execute arbitrary code before OpenSSL even validated it as a legitimate engine.</p>
<p><b>Impact</b> : An attacker could achieve arbitrary native code execution on the host system, effectively escaping the vm2 sandbox and gaining full control over the host process.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/lib/builtin.js
+++ b/lib/builtin.js
@@ -210,6 +210,163 @@ if (EventEmitter.EventEmitterAsyncResource) {
 	EventEmitterReferencingAsyncResourceClass = EventEmitterReferencingAsyncResource;
 }
 
+// SECURITY (GHSA-46pr-c5wc-xffx): Some builtins are safe to expose EXCEPT for a
+// handful of members that reach host-process authority the `vm.readonly()` wrap
+// cannot contain. readonly() blocks property *assignment* through the sandbox
+// proxy, but it forwards every *call* to the host member with full host
+// authority -- so a callable that loads native code, mutates a process-wide
+// security setting, or hands back a shared host singleton is a sandbox-escape
+// primitive even behind the read-only proxy. Rather than deny these
+// otherwise-useful modules wholesale (hashing/signing is a legitimate sandbox
+// use of `crypto`), expose a sanitized shallow copy with just the dangerous
+// member neutralized.
+//
+//   - crypto.setEngine(path[, flags]) : hands `path` to OpenSSL&#39;s ENGINE loader,
+//     which asks the OS dynamic loader to load the named shared library. The
+//     library&#39;s constructor runs as arbitrary native code BEFORE OpenSSL decides
+//     whether the file is a usable engine -- so even the expected
+//     ERR_CRYPTO_ENGINE_UNKNOWN rejection happens only after host-native code has
+//     already executed. A sandbox with only `crypto` allowed and a native file in
+//     its own package directory therefore has a native-RCE primitive.
+//
+// The stub throws instead of forwarding to host OpenSSL, so no library is ever
+// loaded. Matching strips the `node:` prefix so `node:crypto` shares fate.
+function sanitizeCryptoModule(mod) {
+	const copy = Object.assign({}, mod);
+	copy.setEngine = function setEngine() {
+		throw new Error(&#39;crypto.setEngine is disabled in vm2 sandboxes: it asks OpenSSL to dynamically load a native library into the host process, executing arbitrary native code (GHSA-46pr-c5wc-xffx).&#39;);
+	};
+	return copy;
+}</pre>
</details>
<p><b>Fix</b> : The patch introduces a `sanitizeCryptoModule` function that intercepts calls to `crypto.setEngine()`. Instead of forwarding the call to the host&#39;s OpenSSL, it now throws an error, preventing the dynamic loading of native libraries and thus neutralizing the sandbox escape vector.</p>
<p>
<a href="https://github.com/advisories/GHSA-46pr-c5wc-xffx">Advisory</a> · <a href="https://github.com/patriksimek/vm2/commit/aa146a77f859325e079f3bfbfe6d8309af483daa">Commit</a>
</p>
<hr>
<h3>GHSA-6w8r-xxw2-g3hx</h3>
<p>
<code>CRITICAL 9.9</code> · 2026-10-01 · JavaScript<br>
<code>vm2</code> · Pattern: <code>DESERIALIZATION→RCE</code> · 30x across ecosystem
</p>
<p><b>Root cause</b> : The vm2 sandbox failed to properly restrict access to certain Node.js built-in modules, specifically `node:sqlite`. The `DatabaseSync` constructor in `node:sqlite` allowed the `allowExtension` option to be set, which, if enabled, permits loading native SQLite extensions. This capability was not adequately neutralized by the sandbox&#39;s read-only proxy, enabling a sandboxed plugin to execute arbitrary native code in the host process.</p>
<p><b>Impact</b> : An attacker could execute arbitrary native code on the host system, effectively escaping the sandbox and achieving full remote code execution (RCE) with the privileges of the Node.js process.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/lib/builtin.js
+++ b/lib/builtin.js
@@ -210,6 +210,163 @@ if (EventEmitter.EventEmitterAsyncResource) {
 
+// SECURITY (GHSA-6w8r-xxw2-g3hx): `node:sqlite`&#39;s DatabaseSync can load a native
+// SQLite extension (`loadExtension(path)` / the `loadExtension` SQL function) —
+// arbitrary native code in the host process. Node gates this entirely on the
+// constructor&#39;s `allowExtension` option: with it off (the default), both
+// `loadExtension()` and `enableLoadExtension()` throw `ERR_INVALID_STATE`.
+// Wrap the DatabaseSync constructor so `allowExtension` is forced off, which
+// closes every extension-loading path while leaving normal SQL usable.
+function sanitizeSqliteModule(mod) {
+	const HostDatabaseSync = mod.DatabaseSync;
+	if (typeof HostDatabaseSync !== &#39;function&#39;) return mod;
+	const copy = Object.assign({}, mod);
+	class DatabaseSync extends HostDatabaseSync {
+		constructor(location, ...rest) {
+			// Preserve call arity (native DatabaseSync rejects an explicit
+			// `undefined` options arg). Force `allowExtension` off only when an
+			// options value is actually supplied; otherwise the native default
+			// (off) already applies. SECURITY (GHSA-6w8r-xxw2-g3hx follow-up): the
+			// native DatabaseSync also accepts a FUNCTION as its options argument
+			// (functions carry own properties), so `function o(){}; o.allowExtension
+			// = true` bypassed an `object`-only check. Treat functions as options
+			// too — Object.assign copies their own enumerable props and forces
+			// allowExtension off.
+			if (rest.length &gt; 0 &amp;&amp; rest[0] !== null &amp;&amp;
+				(typeof rest[0] === &#39;object&#39; || typeof rest[0] === &#39;function&#39;)) {
+				rest[0] = Object.assign({}, rest[0], {allowExtension: false});
+			}
+			super(location, ...rest);
+		}
+	}
+	copy.DatabaseSync = DatabaseSync;
+	return copy;
+}
+
+// SECURITY (GHSA-98xx-8mx4-x7cm): `tls.setDefaultCACertificates(list)` replaces</pre>
</details>
<p><b>Fix</b> : The patch introduces a `sanitizeSqliteModule` function that wraps the `node:sqlite.DatabaseSync` constructor. This wrapper forces the `allowExtension` option to `false` when an options object is provided, preventing the loading of native SQLite extensions. This ensures that even if a sandboxed plugin attempts to enable extensions, the underlying host functionality will deny it.</p>
<p>
<a href="https://github.com/advisories/GHSA-6w8r-xxw2-g3hx">Advisory</a> · <a href="https://github.com/patriksimek/vm2/commit/aa146a77f859325e079f3bfbfe6d8309af483daa">Commit</a>
</p>
<hr>
<h3>GHSA-8686-vhfx-7r3j</h3>
<p>
<code>CRITICAL 9.9</code> · 2026-10-01 · JavaScript<br>
<code>vm2</code> · Pattern: <code>UNCLASSIFIED</code> · 844x across ecosystem
</p>
<p><b>Root cause</b> : </p>
<p><b>Impact</b> : </p>
<p><b>Fix</b> : </p>
<p>
<a href="https://github.com/advisories/GHSA-8686-vhfx-7r3j">Advisory</a> · <a href="https://github.com/patriksimek/vm2/commit/b0f50662dd499ff33544bb42387958c64711af1e">Commit</a>
</p>
<hr>
<h3>GHSA-c48m-32m9-vx93</h3>
<p>
<code>CRITICAL 9.9</code> · 2026-10-01 · JavaScript<br>
<code>vm2</code> · Pattern: <code>UNCLASSIFIED</code> · 844x across ecosystem
</p>
<p><b>Root cause</b> : The vulnerability stemmed from an insufficiently strict regular expression used to validate allowed external package names. The regex allowed partial matches, meaning a malicious package name like &#39;evil-left-pad&#39; could bypass the allowlist if &#39;left-pad&#39; was permitted. Additionally, even with an anchored regex, path traversal sequences (&#39;..&#39;) within subpaths of allowed packages were not explicitly forbidden, allowing an attacker to escape the intended package and load an arbitrary host package.</p>
<p><b>Impact</b> : An attacker could bypass the `vm2` sandbox and execute arbitrary code in the host environment with the privileges of the Node.js process running the sandbox.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">- this.externalCache = externals.map(pattern =&gt; new RegExp(makeExternalMatcherRegex(pattern)));
+ this.externalCache = externals.map(pattern =&gt; new RegExp(&#39;^(?:&#39; + makeExternalMatcherRegex(pattern) + &#39;)(?:[\\/].*)?$&#39;));
+ if (x.split(/[\/]/).indexOf(&#39;..&#39;) !== -1) return undefined;</pre>
</details>
<p><b>Fix</b> : The patch introduces two main fixes: first, it anchors the regular expression used for external package allowlisting to ensure it matches the entire package name, optionally followed by a subpath. Second, it explicitly checks for and rejects any package specifier containing &#39;..&#39; path segments before calling the custom resolver, preventing path traversal attacks.</p>
<p>
<a href="https://github.com/advisories/GHSA-c48m-32m9-vx93">Advisory</a> · <a href="https://github.com/patriksimek/vm2/commit/ab4ee7d803e8c80155e9eb3672226bddbca4aa9c">Commit</a>
</p>
<hr>
<h3>GHSA-qhwx-74w5-xhxq</h3>
<p>
<code>CRITICAL 9.9</code> · 2026-10-01 · JavaScript<br>
<code>vm2</code> · Pattern: <code>UNSANITIZED_INPUT→COMMAND</code> · 110x across ecosystem
</p>
<p><b>Root cause</b> : The vm2 sandbox environment failed to properly restrict access to the &#39;node:test&#39; built-in module. This module, when invoked with specific `execArgv` parameters, could spawn a separate Node.js process outside the sandbox, executing attacker-controlled code with full host privileges.</p>
<p><b>Impact</b> : An attacker could achieve arbitrary code execution on the host system, completely escaping the vm2 sandbox and gaining full control over the environment.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/lib/builtin.js
+++ b/lib/builtin.js
@@ -162,7 +162,20 @@ const DANGEROUS_BUILTINS = new Set([
 	// `os.platform()`, `os.EOL`, `os.constants`) can register a controlled
 	// wrapper under the same name via `mock` / `override`.
 	&#39;os&#39;,
-	&#39;dns&#39;
+	&#39;dns&#39;,
+	&#39;test&#39;
 ]);
 
 // SECURITY (GHSA-rp36-8xq3-r6c4): Family-prefix denylist check. `inspector` and
@@ -171,7 +184,10 @@ const DANGEROUS_BUILTINS = new Set([
 // `node:process` and `node:inspector/promises` cannot bypass via spelling.
 function isDangerousBuiltin(key) {
 	if (typeof key !== &#39;string&#39;) return false;
-	if (key.startsWith(&#39;node:&#39;)) key = key.slice(5);
+	while (key.startsWith(&#39;node:&#39;)) key = key.slice(5);</pre>
</details>
<p><b>Fix</b> : The patch adds &#39;test&#39; to the `DANGEROUS_BUILTINS` denylist, preventing its use within the sandbox. It also enhances the `isDangerousBuiltin` function to strip all leading &#39;node:&#39; prefixes from module names, preventing bypasses via double-prefixed spellings like &#39;node:node:test&#39;.</p>
<p>
<a href="https://github.com/advisories/GHSA-qhwx-74w5-xhxq">Advisory</a> · <a href="https://github.com/patriksimek/vm2/commit/415339f698f0d52d3c5ad358b12b79c8072d5b4b">Commit</a>
</p>
<hr>
<h3>GHSA-jjq7-m736-w977</h3>
<p>
<code>CRITICAL 9.9</code> · 2026-09-23 · Ruby<br>
<code>openc3</code> · Pattern: <code>MISSING_AUTHZ→RESOURCE</code> · 125x across ecosystem
</p>
<p><b>Root cause</b> : The system allowed authenticated non-admin users to write to specific configuration overlay paths (targets_modified/TARGET/cmd_tlm/) which were later loaded and executed as code (via ERB rendering and GENERIC_*_CONVERSION evaluation) by PacketConfig. This bypasses intended authorization checks for code execution.</p>
<p><b>Impact</b> : An authenticated attacker could inject and execute arbitrary code on the server, leading to full system compromise and potentially impacting the underlying infrastructure.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/openc3-cosmos-cmd-tlm-api/app/controllers/storage_controller.rb
+++ b/openc3-cosmos-cmd-tlm-api/app/controllers/storage_controller.rb
@@ -429,8 +429,10 @@ def get_upload_presigned_request
       end
     end
 
-    # Anywhere other than config/SCOPE/targets_modified or config/SCOPE/tmp requires admin
-    if !(params[:bucket] == &#39;OPENC3_CONFIG_BUCKET&#39; &amp;&amp; (key_split[1] == &#39;targets_modified&#39; || key_split[1] == &#39;tmp&#39;))
+    # Non-admins may only write the user-writable overlay (config/SCOPE/targets_modified
+    # or config/SCOPE/tmp), and never the cmd_tlm overlay, which PacketConfig ERB-renders
+    # and whose GENERIC_*_CONVERSION blocks it evaluates as code. Everything else is admin.
+    unless non_admin_config_overlay_write?(params[:bucket], path)
       return unless authorization(&#39;admin&#39;)</pre>
</details>
<p><b>Fix</b> : The patch introduces a new authorization check, `non_admin_config_overlay_write?`, to explicitly prevent non-admin users from writing to the `cmd_tlm` overlay path within the `targets_modified` directory. Additionally, a new `original: true` parameter is added to the `TargetFile.body` method, ensuring that code execution paths only load files from the read-only plugin-installed `targets/` tree, ignoring user-writable overlays.</p>
<p>
<a href="https://github.com/advisories/GHSA-jjq7-m736-w977">Advisory</a> · <a href="https://github.com/OpenC3/cosmos/commit/71943352a28128ef3e7e894319d97a656b5cd4f2">Commit</a>
</p>
<hr>
<h3>GHSA-rr49-f9g6-c9r5</h3>
<p>
<code>CRITICAL 9.9</code> · 2026-09-23 · Python<br>
<code>plone.app.portlets</code> · Pattern: <code>UNSANITIZED_INPUT→TEMPLATE</code> · 28x across ecosystem
</p>
<p><b>Root cause</b> : The application allowed user-controlled input (template and macro names) to be directly used in a TALES (TAL Expression Syntax) path expression without sufficient validation. This enabled an attacker to inject TALES metacharacters, transforming a simple path traversal into an arbitrary TALES expression, which could then execute Python code.</p>
<p><b>Impact</b> : An attacker could achieve arbitrary remote code execution on the server, leading to full compromise of the application and potentially the underlying system.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/src/plone/app/portlets/portlets/classic.py
+++ b/src/plone/app/portlets/portlets/classic.py
@@ -13,6 +30,7 @@ class IClassicPortlet(IPortletDataProvider):
         title=_(&#34;Template&#34;),
         description=_(&#34;The template containing the portlet.&#34;),
         required=True,
+        constraint=_valid_name,
     )
 
     macro = schema.ASCIILine(
@@ -22,6 +40,7 @@ class IClassicPortlet(IPortletDataProvider):
         ),
         default=&#34;portlet&#34;,
         required=False,
+        constraint=_valid_name,
     )
 
 
@@ -48,6 +67,20 @@ def use_macro(self):
         return bool(self.data.macro)
 
     def path_expression(self):
+        # Defense in depth: validate again at render time so assignments
+        # created programmatically (e.g. via GenericSetup import) that bypass
+        # the form field constraint are still rejected. Raises on illegal names.
+        _valid_name(self.data.template)
+        _valid_name(self.data.macro)
         expr = &#34;context/%s&#34; % self.data.template
         if self.use_macro():
             expr += &#34;/macros/%s&#34; % self.data.macro</pre>
</details>
<p><b>Fix</b> : The patch introduces a strict regular expression validator for the &#39;template&#39; and &#39;macro&#39; fields. This validator ensures that only alphanumeric characters, underscores, at signs, periods, hyphens, and forward slashes are allowed, effectively preventing the injection of TALES metacharacters like &#39;:&#39; or &#39;|&#39;. The validation is applied both at the schema level and as a defense-in-depth measure at render time.</p>
<p>
<a href="https://github.com/advisories/GHSA-rr49-f9g6-c9r5">Advisory</a> · <a href="https://github.com/plone/plone.app.portlets/commit/1d9cacacfad9ed08b890dadc6e75741e295dc151">Commit</a>
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
             Map to closed taxonomy of 51 normalized pattern IDs
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
<tr><td>Total advisories</td><td>2502</td></tr>
<tr><td>Unique patterns</td><td>51</td></tr>
<tr><td>Pending</td><td>86</td></tr>
<tr><td>Last updated</td><td>2026-10-08</td></tr>
</table>
</details>
<hr>
<sub><a href="https://christbowel.com">christbowel.com</a></sub>
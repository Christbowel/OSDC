<div align="center">
<h1>🎣 Open Source Daily Catch</h1>
<p><b>Automated Patch Intelligence for Security Engineers</b></p>
<p>
<a href="https://github.com/christbowel/osdc/actions/workflows/daily.yml"><img src="https://github.com/christbowel/osdc/actions/workflows/daily.yml/badge.svg" alt="Analysis"></a>
<a href="https://github.com/christbowel/osdc/actions/workflows/render.yml"><img src="https://github.com/christbowel/osdc/actions/workflows/render.yml/badge.svg" alt="Render"></a>
<a href="https://christbowel.github.io/OSDC"><img src="https://img.shields.io/badge/advisories-1680-blue" alt="Advisories"></a>
<a href="https://christbowel.github.io/OSDC"><img src="https://img.shields.io/badge/patterns-50-purple" alt="Patterns"></a>
</p>
<p>
<a href="https://christbowel.github.io/OSDC">Live dashboard</a> · <a href="#how-it-works">How it works</a>
</p>
</div>
<hr>
<h3>GHSA-x2rj-828p-hx9m</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-08-21 · Python<br>
<code>xinference</code> · Pattern: <code>UNSANITIZED_INPUT→COMMAND</code> · 83x across ecosystem
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
<code>kobako</code> · Pattern: <code>DESERIALIZATION→RCE</code> · 22x across ecosystem
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
<code>@nocobase/plugin-notification-in-app-message</code> · Pattern: <code>UNCLASSIFIED</code> · 476x across ecosystem
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
<code>flyto-core</code> · Pattern: <code>PATH_TRAVERSAL→FILE_WRITE</code> · 51x across ecosystem
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
<code>github.com/prebid/prebid-server</code> · Pattern: <code>SSRF→INTERNAL_ACCESS</code> · 110x across ecosystem
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
<code>pheditor/pheditor</code> · Pattern: <code>MISSING_AUTH→ENDPOINT</code> · 55x across ecosystem
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
<code>@prompty/core</code> · Pattern: <code>UNSANITIZED_INPUT→TEMPLATE</code> · 9x across ecosystem
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
<code>github.com/nuclio/nuclio</code> · Pattern: <code>UNCLASSIFIED</code> · 476x across ecosystem
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
<code>mcp-pinot-server</code> · Pattern: <code>UNSANITIZED_INPUT→SQL</code> · 27x across ecosystem
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
<code>gogs.io/gogs</code> · Pattern: <code>UNCLASSIFIED</code> · 476x across ecosystem
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
<code>vm2</code> · Pattern: <code>UNCLASSIFIED</code> · 476x across ecosystem
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
<code>vm2</code> · Pattern: <code>UNCLASSIFIED</code> · 476x across ecosystem
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
<code>vm2</code> · Pattern: <code>UNCLASSIFIED</code> · 476x across ecosystem
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
<code>vm2</code> · Pattern: <code>UNCLASSIFIED</code> · 476x across ecosystem
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
<code>@nyariv/sandboxjs</code> · Pattern: <code>TYPE_CONFUSION→BYPASS</code> · 5x across ecosystem
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
<code>github.com/free5gc/smf</code> · Pattern: <code>MISSING_AUTH→ENDPOINT</code> · 55x across ecosystem
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
<code>github.com/enchant97/note-mark/backend</code> · Pattern: <code>INSECURE_DEFAULT→CONFIG</code> · 27x across ecosystem
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
<code>github.com/jkroepke/openvpn-auth-oauth2</code> · Pattern: <code>MISSING_AUTH→ENDPOINT</code> · 55x across ecosystem
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
<code>wwbn/avideo</code> · Pattern: <code>UNSANITIZED_INPUT→XSS</code> · 103x across ecosystem
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
<code>github.com/daptin/daptin</code> · Pattern: <code>PATH_TRAVERSAL→FILE_WRITE</code> · 51x across ecosystem
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
<code>axios</code> · Pattern: <code>UNSANITIZED_INPUT→HEADER</code> · 14x across ecosystem
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
<h3>GHSA-pfvc-3p5h-x7h6</h3>
<p>
<code>CRITICAL 9.9</code> · 2026-07-31 · Go<br>
<code>github.com/pterodactyl/wings</code> · Pattern: <code>UNCLASSIFIED</code> · 476x across ecosystem
</p>
<p><b>Root cause</b> : </p>
<p><b>Impact</b> : </p>
<p><b>Fix</b> : </p>
<p>
<a href="https://github.com/advisories/GHSA-pfvc-3p5h-x7h6">Advisory</a> · <a href="https://github.com/pterodactyl/wings/commit/eb65e27ae077a63e38518c490768486af1cd86a9">Commit</a>
</p>
<hr>
<h3>GHSA-mjqf-28ph-426h</h3>
<p>
<code>CRITICAL 9.9</code> · 2026-07-29 · Go<br>
<code>github.com/kube-logging/logging-operator</code> · Pattern: <code>UNSANITIZED_INPUT→COMMAND</code> · 83x across ecosystem
</p>
<p><b>Root cause</b> : The logging operator was vulnerable to Fluentd configuration injection because it did not properly validate or escape user-provided input before incorporating it into Fluentd configuration files. Specifically, newline characters in directive names, types, IDs, labels, log levels, tags, and parameter names, as well as parameter values, could break out of the intended configuration structure, allowing an attacker to inject arbitrary Fluentd directives, including those that execute remote code.</p>
<p><b>Impact</b> : An attacker could inject arbitrary Fluentd configuration, leading to remote code execution on the Fluentd pods managed by the logging operator. This could compromise the entire Kubernetes cluster where the operator is deployed.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/pkg/sdk/logging/model/render/fluent.go
+++ b/pkg/sdk/logging/model/render/fluent.go
@@ -44,6 +44,19 @@ func (f *FluentRender) RenderDirectives(directives []types.Directive, indent int
 		if meta.Directive == &#34;&#34; {
 			return fmt.Errorf(&#34;directive must have a name %s&#34;, meta)
 		}
+		// Structural tokens can&#39;t be quoted, so a newline would break out.
+		for _, t := range []struct{ kind, value string }{
+			{&#34;directive name&#34;, meta.Directive},
+			{&#34;@type&#34;, meta.Type},
+			{&#34;@id&#34;, meta.Id},
+			{&#34;@label&#34;, meta.Label},
+			{&#34;@log_level&#34;, meta.LogLevel},
+			{&#34;tag&#34;, meta.Tag},
+		} {
+			if err := validateFluentToken(t.kind, t.value); err != nil {
+				return err
+			}
+		}
 		f.indentedf(indent, &#34;&lt;%s%s&gt;&#34;, meta.Directive, tag(meta.Tag))
 		if meta.Type != &#34;&#34; {
 			f.indentedf(indent+f.Indent, &#34;@type %s&#34;, meta.Type)
@@ -61,7 +74,10 @@ func (f *FluentRender) RenderDirectives(directives []types.Directive, indent int
 			keys := mapstrstr.Keys(params)
 			sort.Strings(keys)
 			for _, k := range keys {
-				f.indentedf(indent+f.Indent, &#34;%s %s&#34;, k, params[k])
+				if err := validateFluentToken(&#34;parameter name&#34;, k); err != nil {
+					return err
+				}
+				f.indentedf(indent+f.Indent, &#34;%s %s&#34;, k, escapeFluentValue(params[k]))
 			}
 		}
 		if sections := d.GetSections(); len(sections) &gt; 0 {</pre>
</details>
<p><b>Fix</b> : The patch introduces validation to prevent newline characters in Fluentd structural tokens (directive names, types, IDs, labels, log levels, tags, and parameter names). It also adds an `escapeFluentValue` function to properly quote and escape parameter values that contain newlines or &#39;#&#39; characters, preventing them from being interpreted as structural elements or Ruby interpolations.</p>
<p>
<a href="https://github.com/advisories/GHSA-mjqf-28ph-426h">Advisory</a> · <a href="https://github.com/kube-logging/logging-operator/commit/cf437d7f1e056c78740bf5716ac8bdebcf002425">Commit</a>
</p>
<hr>
<h3>GHSA-rjg6-39jm-rgg4</h3>
<p>
<code>CRITICAL 9.9</code> · 2026-07-24 · JavaScript<br>
<code>@better-auth/scim</code> · Pattern: <code>MISSING_AUTHZ→RESOURCE</code> · 93x across ecosystem
</p>
<p><b>Root cause</b> : The vulnerability stemmed from the SCIM provider&#39;s update functionality not properly validating email uniqueness during user updates (PUT/PATCH operations). An attacker could change a user&#39;s email to one already registered by another user, leading to a collision. Additionally, the system did not properly handle user deactivation via the &#39;active&#39; SCIM attribute, failing to revoke sessions or enforce the deactivation consistently.</p>
<p><b>Impact</b> : An attacker could take over another user&#39;s account by reassigning their email address. They could also maintain access to a deactivated account if their sessions were not properly revoked, or bypass deactivation entirely if the &#39;admin&#39; plugin was not present.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/packages/scim/src/routes.ts
+++ b/packages/scim/src/routes.ts
@@ -850,19 +932,37 @@ export const updateSCIMUser = (authMiddleware: AuthMiddleware) =&gt;
 				});
 			}
 
+			const email = getUserPrimaryEmail(
+				body.userName,
+				body.emails,
+			).toLowerCase();
+			const name = getUserFullName(email, body.name);
+			const emailChanged = email !== user.email;
+
+			if (emailChanged) {
+				await assertSCIMEmailAvailable(ctx, email, userId);
+			}
+
+			const userUpdate: Record&lt;string, unknown&gt; = {
+				email,
+				name,
+				updatedAt: new Date(),
+			};
+			if (emailChanged) {
+				// A reassigned email is unverified until the new address is confirmed.
+				userUpdate.emailVerified = false;
+			}
+			if (body.active !== undefined) {
+				userUpdate.banned = body.active === false;
+			}
+			const deactivating = resolveSCIMActiveDeactivation(ctx, userUpdate);
+
 			const [updatedUser, updatedAccount] =
 				await ctx.context.adapter.transaction&lt;[User | null, Account | null]&gt;(
 					async () =&gt; {
-						const email = getUserPrimaryEmail(body.userName, body.emails);
-						const name = getUserFullName(email, body.name);
-
 						const updatedUser = await ctx.context.internalAdapter.updateUser(
 							userId,
-							{
-								email,
-								name,
-								updatedAt: new Date(),
-							},
+							userUpdate,
 						);
 
 						const updatedAccount =
@@ -875,6 +975,10 @@ export const updateSCIMUser = (authMiddleware: AuthMiddleware) =&gt;
 					},
 				);
 
+			if (deactivating) {
+				await ctx.context.internalAdapter.deleteUserSessions(userId);
+			}
+
 			const userResource = createUserResource(
 				ctx.context.baseURL,
 				updatedUser!,</pre>
</details>
<p><b>Fix</b> : The patch introduces `assertSCIMEmailAvailable` to enforce email uniqueness during user updates. It also adds `resolveSCIMActiveDeactivation` to correctly map SCIM `active` status to the internal `banned` field, revoke user sessions upon deactivation, and ensure the admin plugin is present for deactivation. The `deleteSCIMUser` function was also updated to only delete the global user if no other accounts are linked.</p>
<p>
<a href="https://github.com/advisories/GHSA-rjg6-39jm-rgg4">Advisory</a> · <a href="https://github.com/better-auth/better-auth/commit/7c126dcd1aad24468ec37e876545c1d083d8acca">Commit</a>
</p>
<hr>
<h3>GHSA-gx55-f84r-v3r7</h3>
<p>
<code>CRITICAL 9.9</code> · 2026-06-30 · Go<br>
<code>github.com/fission/fission</code> · Pattern: <code>UNCLASSIFIED</code> · 476x across ecosystem
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
<code>github.com/fission/fission</code> · Pattern: <code>PRIVILEGE_ESCALATION→ROLE</code> · 39x across ecosystem
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
<code>github.com/fission/fission</code> · Pattern: <code>UNCLASSIFIED</code> · 476x across ecosystem
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
<code>github.com/fission/fission</code> · Pattern: <code>UNCLASSIFIED</code> · 476x across ecosystem
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
<code>@deepstream/server</code> · Pattern: <code>UNCLASSIFIED</code> · 476x across ecosystem
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
<code>gogs.io/gogs</code> · Pattern: <code>UNCLASSIFIED</code> · 476x across ecosystem
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
<code>paymenter/paymenter</code> · Pattern: <code>UNCLASSIFIED</code> · 476x across ecosystem
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
<code>pheditor/pheditor</code> · Pattern: <code>UNSANITIZED_INPUT→COMMAND</code> · 83x across ecosystem
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
<code>github.com/juev/nebula-mesh</code> · Pattern: <code>PRIVILEGE_ESCALATION→ROLE</code> · 39x across ecosystem
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
<code>firefighter-incident</code> · Pattern: <code>SSRF→CLOUD_METADATA</code> · 3x across ecosystem
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
<h3>GHSA-jrw6-7x4q-w25j</h3>
<p>
<code>CRITICAL 9.8</code> · 2026-08-26 · Python<br>
<code>senaite.core</code> · Pattern: <code>UNSANITIZED_INPUT→COMMAND</code> · 83x across ecosystem
</p>
<p><b>Root cause</b> : The application used Python&#39;s `eval()` function to parse stringified record values from user-controlled input. The `eval()` function executes arbitrary Python code, making it highly dangerous when used with untrusted input.</p>
<p><b>Impact</b> : An attacker could achieve arbitrary code execution on the server, leading to full system compromise, data exfiltration, or denial of service.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/src/senaite/core/browser/fields/record.py
+++ b/src/senaite/core/browser/fields/record.py
@@ -253,7 +254,7 @@ def labelFax(self,fax=&#39;&#39;):
     def set(self, instance, value, **kwargs):
         if type(value) in StringTypes:
             try:
-                value = eval(value)
+                value = parse_record_literal(value)</pre>
</details>
<p><b>Fix</b> : The patch replaces all instances of `eval()` with `ast.literal_eval()`. A new utility function `parse_record_literal` was introduced to encapsulate this safe parsing, ensuring that only Python literal structures (strings, numbers, tuples, lists, dicts, booleans, and None) can be evaluated, preventing arbitrary code execution.</p>
<p>
<a href="https://github.com/advisories/GHSA-jrw6-7x4q-w25j">Advisory</a> · <a href="https://github.com/senaite/senaite.core/commit/a24d65e99a17ac43c5374ed9f0a60d0fe60d2f74">Commit</a>
</p>
<hr>
<h3>GHSA-mw6r-2hvm-4rp2</h3>
<p>
<code>CRITICAL 9.8</code> · 2026-08-25 · Python<br>
<code>qwed-mcp</code> · Pattern: <code>UNSANITIZED_INPUT→COMMAND</code> · 83x across ecosystem
</p>
<p><b>Root cause</b> : The application used SymPy&#39;s `parse_expr()` function to evaluate user-supplied mathematical expressions without sufficient sanitization or a restricted execution environment. This allowed attackers to inject arbitrary Python code, which `parse_expr()` would then execute.</p>
<p><b>Impact</b> : An attacker could execute arbitrary Python code on the server, leading to full system compromise, data exfiltration, or denial of service.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/src/qwed_mcp/engines/math_engine.py
+++ b/src/qwed_mcp/engines/math_engine.py
@@ -17,29 +19,19 @@ def verify_math_expression(
     Returns:
         Verification result with verified status and details
     &#34;&#34;&#34;
     try:
         from sympy import (
-            symbols, sympify, diff, integrate, simplify, solve,
-            Eq, parse_expr, sqrt, sin, cos, exp, log, pi, E
+            symbols, diff, integrate, simplify, solve, Eq,
         )
-        from sympy.parsing.sympy_parser import (
-            parse_expr, standard_transformations,
-            implicit_multiplication_application, convert_xor
-        )
-
         # Common symbol
         x, y, z = symbols(&#39;x y z&#39;)
-
-        # Transformation for parsing
-        transformations = standard_transformations + (
-            implicit_multiplication_application,
-            convert_xor,
-        )
-
         # Parse expression
         try:
-            expr = parse_expr(
-                expression.replace(&#34;^&#34;, &#34;**&#34;),
-                local_dict={&#34;x&#34;: x, &#34;y&#34;: y, &#34;z&#34;: z, &#34;pi&#34;: pi, &#34;e&#34;: E},
-                transformations=transformations
-            )
+            expr = safe_parse_expr(expression.replace(&#34;^&#34;, &#34;**&#34;))
         except Exception as e:
             return {
                 &#34;verified&#34;: False,
                 &#34;message&#34;: f&#34;Could not parse expression: {expression}&#34;,
                 &#34;error&#34;: str(e)
             }
-
         # Parse claimed result
         try:
-            claimed = parse_expr(
-                claimed_result.replace(&#34;^&#34;, &#34;**&#34;),
-                local_dict={&#34;x&#34;: x, &#34;y&#34;: y, &#34;z&#34;: z, &#34;pi&#34;: pi, &#34;e&#34;: E},
-                transformations=transformations
-            )
+            claimed = safe_parse_expr(claimed_result.replace(&#34;^&#34;, &#34;**&#34;))
         except Exception as e:</pre>
</details>
<p><b>Fix</b> : A new `safe_parser.py` module was introduced, containing `safe_parse_expr()`. This function implements a denylist for dangerous keywords, restricts the global and local dictionaries available during parsing, and enforces a maximum expression length. The `math_engine.py` was updated to use this new safe parser.</p>
<p>
<a href="https://github.com/advisories/GHSA-mw6r-2hvm-4rp2">Advisory</a> · <a href="https://github.com/QWED-AI/qwed-mcp/commit/362e61892052e250c56cb1ee852024d6f98c467b">Commit</a>
</p>
<hr>
<h3>GHSA-w3fx-mc44-mf6j</h3>
<p>
<code>CRITICAL 9.8</code> · 2026-08-25 · Python<br>
<code>chainlit</code> · Pattern: <code>UNSANITIZED_INPUT→COMMAND</code> · 83x across ecosystem
</p>
<p><b>Root cause</b> : The application allowed user-controlled input to be directly executed as a command via `shlex.split` without sufficient validation of the executable itself. While it attempted to restrict executables, an attacker could craft a command string that bypassed these checks, leading to arbitrary command execution.</p>
<p><b>Impact</b> : An unauthenticated attacker could achieve remote code execution on the server, gaining full control over the system where Chainlit is running.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/backend/chainlit/mcp.py
+++ b/backend/chainlit/mcp.py
@@ -1,10 +1,9 @@
-import shlex
-from typing import Dict, Literal, Optional, Union
+from typing import Callable, Dict, Literal, Optional, Union
+from urllib.parse import unquote, urlparse
 
+import httpx
 from pydantic import BaseModel
 
-from chainlit.config import config
-
 
 class StdioMcpConnection(BaseModel):
     name: str
@@ -29,71 +28,277 @@ class HttpMcpConnection(BaseModel):
 
 McpConnection = Union[StdioMcpConnection, SseMcpConnection, HttpMcpConnection]
 
-# Headers that must never be forwarded from the browser to the MCP transport.
-#
-# Note: ``Authorization`` is deliberately absent — forwarding a user-supplied
-# token is the point of user-provided servers. The allowlist scopes where it
-# can be sent, and redirects are disabled so that destination cannot move.
-_RESTRICTED_HEADERS = frozenset(
-    {
-        &#34;host&#34;,
-        &#34;content-length&#34;,
-        &#34;transfer-encoding&#34;,
-        &#34;connection&#34;,
-        &#34;upgrade&#34;,
-        &#34;proxy-authorization&#34;,
-        &#34;te&#34;,
-        &#34;trailer&#34;,
-        # Session credentials — must not be replayed to a third-party server.
-        &#34;cookie&#34;,
-        # Spoofable client/origin identity, used to bypass upstream ACLs.
-        &#34;forwarded&#34;,
-        &#34;via&#34;,
-        &#34;x-forwarded-by&#34;,
-        &#34;x-forwarded-for&#34;,
-        &#34;x-forwarded-host&#34;,
-        &#34;x-forwarded-port&#34;,
-        &#34;x-forwarded-proto&#34;,
-        &#34;x-forwarded-server&#34;,
-        &#34;x-real-ip&#34;,
-        # Routing/method overrides honoured by some proxies and frameworks,
-        # which can reach endpoints the literal request line would not.
-        &#34;x-http-method-override&#34;,
-        &#34;x-method-override&#34;,
-        &#34;x-original-url&#34;,
-        &#34;x-rewrite-url&#34;,
-    }
-)
-
-
-def _effective_port(parsed) -&gt; int:
-    &#34;&#34;&#34;Return the TCP port for a parsed URL, inferring defaults for http/https.&#34;&#34;&#34;
-    if parsed.port is not None:
-        return parsed.port
-    return 443 if parsed.scheme == &#34;https&#34; else 80
-
 
-def validate_mcp_command(command_string: str):
-    &#34;&#34;&#34;
-    Validates that a command string uses command in the allowed list as the executable and returns
-    the executable and list of arguments suitable for subprocess calls.
-
-    This function handles potential command prefixes, flags, and options
-    to ensure only commands in allowed list are allowed.
-
-    Args:
-        command_string (str): The full command string to validate
-
-    Returns:
-        tuple: (env, executable, args_list) where:
-            - env (dict): Environment variables as a dictionary
-            - executable (str): The executable name or path
-            - args_list (list): List of command arguments
-
-    Raises:
-        ValueError: If the command doesn&#39;t use an allowed executable
-    &#34;&#34;&#34;
-    # Split the command string into parts while respecting quotes and escapes
-    # Using shlex.split provides POSIX-compatible parsing so that arguments
-    # wrapped in quotes (e.g. &#34;--header \&#34;Authorization: Bearer TOKEN\&#34;&#34;)
-    # or environment variable assignments such as
-    # MY_VAR=&#34;value with spaces&#34; are preserved as single list items.
-    # On Windows, shlex also works as long as posix=False is not required for
-    # our use-case (Chainlit targets POSIX-style shells for the MCP command).
-    try:
-        parts = shlex.split(command_string, posix=True)
-    except ValueError as exc:
-        # Provide a clearer error message when the command cannot be parsed
-        raise ValueError(f&#34;Invalid command string: {exc}&#34;) from exc
-
-    if not parts:
-        raise ValueError(&#34;Empty command string&#34;)
-
-    # Look for the actual executable in the command
-    executable = None
-    executable_index = None
-    allowed_executables = config.features.mcp.stdio.allowed_executables
-    for i, part in enumerate(parts):
-        # Remove any path components to get the base executable name
-        base_exec = part.split(&#34;/&#34;)[-1].split(&#34;\\&#34;)[-1]
-        if allowed_executables is None or base_exec in allowed_executables:
-            executable = part
-            executable_index = i
-            break
-
-    if executable is None or executable_index is None:
-        raise ValueError(
-            f&#34;Only commands in ({&#39;, &#39;.join(allowed_exe
+def _path_matches(req_path: str, allowed_path: str) -&gt; bool:
+    &#34;&#34;&#34;True if req_path equals or is a sub-path of allowed_path.
+
+    Normalises allowed_path to end with &#39;/&#39; before the startswith check so
+    that &#39;/v1&#39; does not accidentally match &#39;/v1-evil&#39;.
+
+    Note: if allowed_path is empty (i.e. the allowlist entry is an origin with
+    no path component, e.g. &#34;https://example.com&#34;), all sub-paths on that host
+    are permitted. Use a path-restricted entry (e.g. &#34;https://example.com/api&#34;)
+    to limit access to a sub-tree.
+    &#34;&#34;&#34;
+    norm = allowed_path.rstrip(&#34;/&#34;) + &#34;/&#34;
+    return req_path == norm.rstrip(&#34;/&#34;) or req_path.startswith(norm)
+
+
+def _has_ambiguous_path(raw_path: str) -&gt; bool:
+    &#34;&#34;&#34;True if raw_path contains constructs that could change meaning in transit.
+
+    We reject rather than normalise. Decoding first would let ``%2f`` create
+    path-segment boundaries that were not in the original URI, manufacturing a
+    passing path from a malicious one, and re-implementing RFC 3986 dot-segment
+    removal would leave us permanently obliged to match httpx byte for byte.
+    None of these constructs belong in a configured MCP endpoint.
+
+    Deliberately operates on the *raw* percent-encoded path rather than
+    ``httpx.URL(url).path``: httpx pre-decodes ``%2e``/``%2f``, which would make
+    the marker check below blind to exactly the sequences it exists to catch.
+    &#34;&#34;&#34;
+    lowered = raw_path.lower()
+    # %2e -&gt; &#39;.&#39;, %2f -&gt; &#39;/&#39;, %5c -&gt; &#39;\&#39;, %25 -&gt; a second decoding pass
+    # downstream. Backslash is a separator on some origin servers and is left
+    # untouched by httpx.
+    if any(marker in lowered for marker in (&#34;%2e&#34;, &#34;%2f&#34;, &#34;%5c&#34;, &#34;%25&#34;)):
+        return True
+    if &#34;\&#34; in raw_path:
+        return True
+    if any(segment in (&#34;.&#34;, &#34;..&#34;) for segment in raw_path.split(&#34;/&#34;)):
+        return True
+
+    # Non-ASCII characters are rejected outright, before and after a single
+    # decode. Many code points fold to &#39;.&#39;, &#39;/&#39; or &#39;\&#39; under the normalisation
+    # some origin servers and proxies apply (U+FF0E, U+2024, U+FF0F, U+2215,
+    # U+2044, ...), which would reopen traversal at the destination. Enumerating
+    # them is a denylist that keeps coming up short, so we require the path to
+    # be ASCII instead — a positive rule, and no real MCP endpoint needs more.
+    if not raw_path.isascii():
+        return True
+    try:
+        decoded = unquote(raw_path, errors=&#34;strict&#34;)
+    except UnicodeDecodeError:
+        return True
+    return not decoded.isascii()
+
+
+def validate_mcp_url(url: str, allowed_urls: list[str]) -&gt; None:
+    &#34;&#34;&#34;Validate that a user-provided MCP URL is in the allowlist.
+
+    Raises ValueError if the URL is not permitted.
+    &#34;&#34;&#34;
+    if not allowed_urls:
+        raise ValueError(
+            f&#34;URL {url!r} is not in the allowed MCP URL list. &#34;
+            &#34;Configure features.mcp.user_servers.allowed_urls in your config.&#34;
+        )
+
+    # Parse the request URL through httpx, which is what the MCP transports
+    # dispatch with. Validating anything else risks approving a URL that
+    # differs from the one that actually goes on the wire.
+    try:
+        parsed = httpx.URL(url)
+    except Exception as exc:
+        raise ValueError(
+            f&#34;URL {url!r} is not in the allowed MCP URL list. It could not be parsed.&#34;
+        ) from exc
+
+    if parsed.scheme not in (&#34;http&#34;, &#34;https&#34;):
+        raise ValueError(
+            f&#34;URL {url!r} is not in the allowed MCP URL list. &#34;
+            &#34;Only http and https URLs are supported.&#34;
+        )
+
+    if _has_ambiguous_path(urlparse(url).path):
+        raise ValueError(
+            f&#34;URL {url!r} is not in the allowed MCP URL list. &#34;
+            &#34;It contains ambiguous path components (e.g. &#39;.&#39;, &#39;..&#39;, or percent-encoded slashes).&#34;
+        )</pre>
</details>
<p><b>Fix</b> : The patch removes the `validate_mcp_command` function, which was responsible for validating and executing commands, and replaces it with `validate_mcp_url`. This new function strictly validates URLs against an allowlist, disallows ambiguous path components, and restricts schemes and headers, preventing arbitrary command execution and SSRF.</p>
<p>
<a href="https://github.com/advisories/GHSA-w3fx-mc44-mf6j">Advisory</a> · <a href="https://github.com/Chainlit/chainlit/commit/0565fd0eccb915fce159929598b053ed79f6e0c9">Commit</a>
</p>
<hr>
<h3>GHSA-mqjf-5f49-2fjh</h3>
<p>
<code>CRITICAL 9.8</code> · 2026-08-21 · Java<br>
<code>org.geotools.jdbc:gt-jdbc-postgis</code> · Pattern: <code>UNSANITIZED_INPUT→SQL</code> · 27x across ecosystem
</p>
<p><b>Root cause</b> : The vulnerability stemmed from the `jsonArrayContains` filter function in GeoTools, which directly embedded user-controlled values into a SQL query without proper escaping. Specifically, when constructing an equality comparison for JSON values, string literals were enclosed in double quotes but not sanitized, allowing an attacker to inject arbitrary SQL.</p>
<p><b>Impact</b> : An unauthenticated attacker could execute arbitrary SQL commands against the PostGIS database, potentially leading to data exfiltration, modification, or deletion, and could even achieve remote code execution depending on the database configuration and privileges.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/modules/plugin/jdbc/jdbc-postgis/src/main/java/org/geotools/data/postgis/FilterToSqlHelper.java
+++ b/modules/plugin/jdbc/jdbc-postgis/src/main/java/org/geotools/data/postgis/FilterToSqlHelper.java
@@ -800,7 +800,8 @@ private String constructEquality(String[] jsonPath, Expression expected) {
         } else if (value instanceof Double double1) {
             return &#34;(@.%s == %f)&#34;.formatted(jsonPath[lastIndex], double1);
         }
-        return &#34;(@.%s == \&#34;%s\&#34;)&#34;.formatted(jsonPath[lastIndex], value);
+        String literal = escapeJsonLiteral(String.valueOf(value));
+        return &#34;(@.%s == \&#34;%s\&#34;)&#34;.formatted(jsonPath[lastIndex], literal);</pre>
</details>
<p><b>Fix</b> : The patch introduces a new `escapeJsonLiteral` function. This function is now used to sanitize user-provided values before they are embedded into the SQL query string for JSON equality comparisons. This prevents malicious input from breaking out of the string literal and injecting SQL.</p>
<p>
<a href="https://github.com/advisories/GHSA-mqjf-5f49-2fjh">Advisory</a> · <a href="https://github.com/geotools/geotools/commit/d821c4d321dd91c22e31fcd5b1ce676645da5176">Commit</a>
</p>
<hr>
<h3>GHSA-rcr2-hggw-43wm</h3>
<p>
<code>CRITICAL 9.8</code> · 2026-08-18 · Python<br>
<code>surfio</code> · Pattern: <code>BUFFER_OVERFLOW→HEAP</code> · 35x across ecosystem
</p>
<p><b>Root cause</b> : The application calculated the expected number of values (nvalues) based on user-provided ncol and nrow without validating if the input buffer was large enough to contain all these values. This allowed reading beyond the allocated memory region if the declared dimensions exceeded the actual data length.</p>
<p><b>Impact</b> : An attacker could trigger an out-of-bounds read, potentially leading to information disclosure of sensitive memory contents or a denial of service due to a crash.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/src/lib/irap_import_ascii.cpp
+++ b/src/lib/irap_import_ascii.cpp
@@ -52,8 +52,10 @@ std::tuple&lt;irap_header, const char*&gt; get_header(const char* start, const char* e
   return {head, ptr};
 }
 
-std::vector&lt;float&gt; get_values(const char* start, const char* end, int ncol, int nrow) {
+std::vector&lt;float&gt; get_values(const char* start, const char* end, size_t ncol, size_t nrow) {
   const size_t nvalues = ncol * nrow;
+  if (static_cast&lt;size_t&gt;(end - start) / 4 &lt; nvalues)
+    throw std::length_error(&#34;ncol and nrow declared in header exceed length of input&#34;);
   auto values = std::vector&lt;float&gt;(nvalues);</pre>
</details>
<p><b>Fix</b> : The patch adds a check to ensure that the declared number of values (ncol * nrow) does not exceed the actual size of the input buffer. If an overflow is detected, it throws a `std::length_error` exception, preventing the out-of-bounds read.</p>
<p>
<a href="https://github.com/advisories/GHSA-rcr2-hggw-43wm">Advisory</a> · <a href="https://github.com/equinor/surfio/commit/1619750bce28e39c4f378d2fb6d28b72380a12aa">Commit</a>
</p>
<hr>
<h3>GHSA-mmj4-63m4-r6h5</h3>
<p>
<code>CRITICAL 9.8</code> · 2026-08-07 · PHP<br>
<code>codeigniter4/framework</code> · Pattern: <code>UNCLASSIFIED</code> · 476x across ecosystem
</p>
<p><b>Root cause</b> : The vulnerability existed because the file validation rules `is_image` and `mime_in` in CodeIgniter only checked the detected MIME type or the file&#39;s actual content type, but did not adequately validate the client-provided file extension against the actual content or expected image types. This allowed an attacker to upload malicious files with a misleading extension (e.g., a PHP script disguised as an image) if the server relied solely on these rules.</p>
<p><b>Impact</b> : An attacker could bypass file upload restrictions, potentially uploading malicious scripts (e.g., PHP web shells) to the server. If these files were then accessible and executable, it could lead to Remote Code Execution (RCE) on the server, allowing the attacker to take full control.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/system/Validation/StrictRules/FileRules.php
+++ b/system/Validation/StrictRules/FileRules.php
@@ -150,6 +151,10 @@ public function is_image(?string $blank, string $params): bool
             if (mb_strpos($type, &#39;image&#39;) !== 0) {
                 return false;
             }
+
+            if ($this-&gt;hasInvalidImageClientExtension($file)) {
+                return false;
+            }
         }
 
         return true;</pre>
</details>
<p><b>Fix</b> : The patch introduces two new private methods: `hasInvalidImageClientExtension` and `hasMismatchedClientExtension`. These methods are called within the `is_image` and `mime_in` validation rules, respectively. They perform additional checks to ensure that the client-provided file extension is consistent with the file&#39;s detected content type, specifically rejecting non-image extensions for image files and mismatched extensions for MIME type checks.</p>
<p>
<a href="https://github.com/advisories/GHSA-mmj4-63m4-r6h5">Advisory</a> · <a href="https://github.com/codeigniter4/CodeIgniter4/commit/b6e9a4fa1dca2df3d3f261bdf61532df8c6420aa">Commit</a>
</p>
<hr>
<h3>GHSA-v8fg-2rw7-q452</h3>
<p>
<code>CRITICAL 9.8</code> · 2026-08-03 · JavaScript<br>
<code>sequelize</code> · Pattern: <code>UNSANITIZED_INPUT→SQL</code> · 27x across ecosystem
</p>
<p><b>Root cause</b> : The vulnerability stemmed from insufficient validation of user-supplied string values intended for Oracle&#39;s TO_TIMESTAMP_TZ and TO_DATE functions. When a string started with these function names, Sequelize would return the value directly without proper escaping or validation, allowing an attacker to inject arbitrary SQL after the function call.</p>
<p><b>Impact</b> : An attacker could inject malicious SQL queries, potentially leading to unauthorized data access, modification, or deletion, and in some cases, remote code execution depending on the database configuration and privileges.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">-    if (val.startsWith(&#39;TO_TIMESTAMP&#39;) || val.startsWith(&#39;TO_DATE&#39;)) {
+    if (val.startsWith(&#39;TO_TIMESTAMP_TZ&#39;) || val.startsWith(&#39;TO_DATE&#39;)) {
+      const splitVal = val.split(/\(|\)/);
+      if (splitVal.length !== 3 || splitVal[2] !== &#39;&#39;) {
+        throw new Error(&#39;Invalid SQL function call.&#39;);
+      }</pre>
</details>
<p><b>Fix</b> : The patch introduces strict validation for strings starting with &#39;TO_TIMESTAMP_TZ&#39; or &#39;TO_DATE&#39; when the dialect is Oracle. It now parses the function name, parameters, and format string, ensuring they conform to expected patterns and formats using Moment.js for date validation. Any deviation from the expected structure or format now results in an error.</p>
<p>
<a href="https://github.com/advisories/GHSA-v8fg-2rw7-q452">Advisory</a> · <a href="https://github.com/sequelize/sequelize/commit/5deadd2410ae9136a21fb652db206d27bb715f26">Commit</a>
</p>
<hr>
<h3>GHSA-6wcc-39rp-hh9p</h3>
<p>
<code>CRITICAL 9.8</code> · 2026-07-28 · JavaScript<br>
<code>@hypequery/clickhouse</code> · Pattern: <code>UNSANITIZED_INPUT→SQL</code> · 27x across ecosystem
</p>
<p><b>Root cause</b> : The vulnerability existed because the `escapeValue` function, which is responsible for sanitizing string inputs before they are used in SQL queries, did not properly escape backslash characters. While it correctly handled single quotes by doubling them, an attacker could use backslashes to bypass this escaping mechanism and inject arbitrary SQL.</p>
<p><b>Impact</b> : An attacker could inject arbitrary SQL commands into queries, potentially leading to unauthorized data access, modification, or deletion, and even remote code execution on the underlying database server.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">-	    return `&#39;${value.replace(/&#39;/g, &#34;&#39;&#39;&#34;)}&#39;`;
+	    const escaped = value.replace(/\\/g, &#39;\\\\&#39;).replace(/&#39;/g, &#34;&#39;&#39;&#34;);
+	    return `&#39;${escaped}&#39;`;</pre>
</details>
<p><b>Fix</b> : The patch modifies the `escapeValue` function to correctly handle backslash characters in string inputs. It now replaces each backslash with a double backslash (`\\`) before replacing single quotes, ensuring that backslashes cannot be used to escape the single quote delimiter.</p>
<p>
<a href="https://github.com/advisories/GHSA-6wcc-39rp-hh9p">Advisory</a> · <a href="https://github.com/hypequery/hypequery/commit/4dfa9d77d70a08b970e722268b75ca7d13db0bdf">Commit</a>
</p>
<hr>
<h3>GHSA-7gfh-x38p-prh3</h3>
<p>
<code>CRITICAL 9.8</code> · 2026-07-24 · JavaScript<br>
<code>velocityjs</code> · Pattern: <code>PROTOTYPE_POLLUTION→OVERRIDE</code> · 25x across ecosystem
</p>
<p><b>Root cause</b> : The vulnerability stemmed from insufficient prototype chain protection in the Velocity.js template engine. An attacker could craft a template that, when evaluated, would traverse the prototype chain using keys like &#39;constructor&#39; and &#39;prototype&#39; to access and manipulate sensitive JavaScript built-in objects, specifically the Function constructor. This allowed for arbitrary code execution.</p>
<p><b>Impact</b> : An attacker could achieve arbitrary remote code execution within the context of the application running the Velocity.js template engine, leading to full system compromise or data exfiltration.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/src/compile/references.ts
+++ b/src/compile/references.ts
@@ -31,12 +32,12 @@ export class References extends Compile {
     const isSilent = this.silence || ast.leader === &#39;$!&#39;;
     const isFunction = ast.args !== undefined;
     const context = this.context;
-    let ret = context[ast.id];
+    let ret = this.isBlockedPathKey(context, ast.id) ? undefined : context[ast.id];
     const local = this.getLocal(ast);
 
     const text = getRefText(ast);
 
-    if (text in context) {
+    if (hasOwnProperty(context, text)) {
       return ast.prue &amp;&amp; escape ? convert(context[text]) : context[text];
     }</pre>
</details>
<p><b>Fix</b> : The patch introduces a new `prototype-guard.ts` module with functions to explicitly block access to dangerous prototype chain keys like `__proto__`, `constructor`, and `prototype` when they are not own properties or when accessed on a function&#39;s prototype. These new guard functions are integrated into the `set.ts` and `references.ts` compilation logic to prevent malicious prototype chain traversal during template evaluation.</p>
<p>
<a href="https://github.com/advisories/GHSA-7gfh-x38p-prh3">Advisory</a> · <a href="https://github.com/shepherdwind/velocity.js/commit/f8e47a6c4607249b9c967d3a1ced959b4dd64dba">Commit</a>
</p>
<hr>
<h3>GHSA-wg5r-wc3x-39vc</h3>
<p>
<code>CRITICAL 9.8</code> · 2026-07-24 · Java<br>
<code>org.openidentityplatform.openam:openam-core</code> · Pattern: <code>DESERIALIZATION→RCE</code> · 22x across ecosystem
</p>
<p><b>Root cause</b> : The application allowed unauthenticated attackers to control the class name passed to `Class.forName` and subsequently `newInstance()` without proper validation. Additionally, a separate deserialization vulnerability existed where an encrypted but attacker-controlled serialized Java object (Subject) could be deserialized without a class allowlist, leading to gadget-chain execution.</p>
<p><b>Impact</b> : An unauthenticated attacker could achieve remote code execution on the server by specifying a malicious class name or by crafting a malicious serialized object, leading to full compromise of the system.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/openam-core/src/main/java/com/sun/identity/authentication/share/AuthXMLUtils.java
+++ b/openam-core/src/main/java/com/sun/identity/authentication/share/AuthXMLUtils.java
@@ -1609,7 +1611,19 @@ static DSAMECallbackInterface createCustomCallback(
             
             if (callback == null) {
                 if ((className != null) &amp;&amp; (className.length() != 0)) {
-                    Class xmlClass = Class.forName(className);
+                    Class xmlClass = Class.forName(className, false,
+                        AuthXMLUtils.class.getClassLoader());
+                    if (!DSAMECallbackInterface.class.isAssignableFrom(xmlClass)) {
+                        debug.error(&#34;createCustomCallback : class &#34; + className
+                            + &#34; is not a DSAMECallbackInterface implementation&#34;);
+                        return null;
+                    }
                     callback = (DSAMECallbackInterface) xmlClass.newInstance();
                 }
             }
@@ -1784,6 +1836,7 @@ public static Subject getDeSerializedSubject(String subjectSerialized)
             //convert byte to object using streams
             byteIn = new ByteArrayInputStream(byteDecrypted);
             objInStream  = new ObjectInputStream(byteIn);
+            objInStream.setObjectInputFilter(SUBJECT_DESERIALISATION_FILTER);
             tempObject = objInStream.readObject();</pre>
</details>
<p><b>Fix</b> : The patch modifies `Class.forName` to prevent static initializers from running and adds a check to ensure the loaded class implements `DSAMECallbackInterface` before instantiation. It also introduces an `ObjectInputFilter` for `Subject` deserialization, allowing only a predefined set of safe classes (primitives, `Principal` implementations, and specific JDK/security classes) to prevent arbitrary object deserialization.</p>
<p>
<a href="https://github.com/advisories/GHSA-wg5r-wc3x-39vc">Advisory</a> · <a href="https://github.com/OpenIdentityPlatform/OpenAM/commit/edcf968cad91a78b932dba4ad559ef94cbf35f5a">Commit</a>
</p>
<hr>
<h3>GHSA-f75j-4cw6-rmx4</h3>
<p>
<code>CRITICAL 9.8</code> · 2026-07-21 · Go<br>
<code>code.gitea.io/gitea</code> · Pattern: <code>RACE_CONDITION→DOUBLE_SPEND</code> · 2x across ecosystem
</p>
<p><b>Root cause</b> : The Gitea Docker image, when configured with `REVERSE_PROXY_TRUSTED_PROXIES = *`, allowed any source IP to impersonate any user via the `X-WEBAUTH-USER` header. Additionally, the TOTP (Time-based One-Time Password) validation logic was susceptible to replay attacks because it did not atomically consume the passcode after successful validation, allowing the same passcode to be used multiple times within its validity window.</p>
<p><b>Impact</b> : An attacker could bypass two-factor authentication by replaying a valid TOTP passcode. In the context of the Docker image misconfiguration, this could be combined with user impersonation to gain unauthorized access to user accounts.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/models/auth/twofactor.go
+++ b/models/auth/twofactor.go
-func (t *TwoFactor) ValidateTOTP(passcode string) (bool, error) {
+func (t *TwoFactor) ValidateAndConsumeTOTP(ctx context.Context, passcode string) (bool, error) {
 	return totp.Validate(passcode, secretStr), nil
 }
+	// Conditional update: only a row whose stored passcode differs from this one is updated, so a
+	// replay (or a concurrent duplicate) matches zero rows and is rejected. The row lock taken by
+	// the UPDATE serializes racing requests, closing the read-validate-write TOCTOU window.
+	t.LastUsedPasscode = passcode</pre>
</details>
<p><b>Fix</b> : The patch introduces `ValidateAndConsumeTOTP` which atomically validates and consumes a TOTP passcode by updating a `last_used_passcode` field in the database. This prevents replay attacks by ensuring a passcode can only be used once. The web and API authentication flows are updated to use this new atomic validation function.</p>
<p>
<a href="https://github.com/advisories/GHSA-f75j-4cw6-rmx4">Advisory</a> · <a href="https://github.com/go-gitea/gitea/commit/99f8b3d9a1d32f4c39828e07971455a18191e0b9">Commit</a>
</p>
<hr>
<h3>GHSA-px5m-h76g-p7p8</h3>
<p>
<code>CRITICAL 9.8</code> · 2026-07-09 · PHP<br>
<code>yeswiki/yeswiki</code> · Pattern: <code>UNSANITIZED_INPUT→COMMAND</code> · 83x across ecosystem
</p>
<p><b>Root cause</b> : The application used `eval()` on user-supplied input for a formula calculator. While there was a regular expression to validate the formula, it was insufficient to prevent malicious code injection, allowing an attacker to execute arbitrary PHP code.</p>
<p><b>Impact</b> : An attacker could achieve full remote code execution on the server, leading to complete compromise of the application and underlying system, as well as denial of service.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">-            if (preg_match($regexpToCheckIfMathFormula, $formula)) {
-                $formula = preg_replace(&#39;!pi|π!&#39;, &#39;pi()&#39;, $formula);
-                try {
-                    eval(&#34;$value = $formula;&#34;);
-                    $value = $value ?? 0;
-                } catch (Throwable $th) {
-                    $value = 0;
-                }
-            } else {
-                $value = &#39;formula not correct !&#39;;
+            try {
+                $value = $this-&gt;evaluateFormula($formula);
+                if (!is_finite($value)) {
+                    $value = 0;
+                }
+            } catch (Throwable $th) {
+                $value = 0;
            }</pre>
</details>
<p><b>Fix</b> : The `eval()` function has been removed. The application now uses a custom-built parser and evaluator for mathematical formulas, which tokenizes the input and processes it through a defined set of allowed operations and functions, preventing arbitrary code execution.</p>
<p>
<a href="https://github.com/advisories/GHSA-px5m-h76g-p7p8">Advisory</a> · <a href="https://github.com/YesWiki/yeswiki/commit/dd2bd8fb099de0d21504bda8a810693b3fcb8e52">Commit</a>
</p>
<hr>
<h3>GHSA-2gr4-ppc7-7mhx</h3>
<p>
<code>CRITICAL 9.8</code> · 2026-06-11 · PHP<br>
<code>codeigniter4/framework</code> · Pattern: <code>UNCLASSIFIED</code> · 476x across ecosystem
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
<code>vm2</code> · Pattern: <code>TYPE_CONFUSION→BYPASS</code> · 5x across ecosystem
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
<code>verbb/formie</code> · Pattern: <code>UNSANITIZED_INPUT→TEMPLATE</code> · 9x across ecosystem
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
<code>vm2</code> · Pattern: <code>UNCLASSIFIED</code> · 476x across ecosystem
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
             Map to closed taxonomy of 50 normalized pattern IDs
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
<tr><td>Total advisories</td><td>1680</td></tr>
<tr><td>Unique patterns</td><td>50</td></tr>
<tr><td>Pending</td><td>24</td></tr>
<tr><td>Last updated</td><td>2026-08-27</td></tr>
</table>
</details>
<hr>
<sub><a href="https://christbowel.com">christbowel.com</a></sub>
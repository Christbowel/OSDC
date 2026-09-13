<div align="center">
<h1>🎣 Open Source Daily Catch</h1>
<p><b>Automated Patch Intelligence for Security Engineers</b></p>
<p>
<a href="https://github.com/christbowel/osdc/actions/workflows/daily.yml"><img src="https://github.com/christbowel/osdc/actions/workflows/daily.yml/badge.svg" alt="Analysis"></a>
<a href="https://github.com/christbowel/osdc/actions/workflows/render.yml"><img src="https://github.com/christbowel/osdc/actions/workflows/render.yml/badge.svg" alt="Render"></a>
<a href="https://christbowel.github.io/OSDC"><img src="https://img.shields.io/badge/advisories-1961-blue" alt="Advisories"></a>
<a href="https://christbowel.github.io/OSDC"><img src="https://img.shields.io/badge/patterns-50-purple" alt="Patterns"></a>
</p>
<p>
<a href="https://christbowel.github.io/OSDC">Live dashboard</a> · <a href="#how-it-works">How it works</a>
</p>
</div>
<hr>
<h3>GHSA-jrc7-96c5-q579</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-09-08 · JavaScript<br>
<code>maplibre-gl</code> · Pattern: <code>UNSANITIZED_INPUT→XSS</code> · 108x across ecosystem
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
<code>github.com/siyuan-note/siyuan/kernel</code> · Pattern: <code>UNSANITIZED_INPUT→SQL</code> · 32x across ecosystem
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
<code>github.com/siyuan-note/siyuan/kernel</code> · Pattern: <code>UNSANITIZED_INPUT→SQL</code> · 32x across ecosystem
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
<code>github.com/siyuan-note/siyuan/kernel</code> · Pattern: <code>UNCLASSIFIED</code> · 601x across ecosystem
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
<code>xinference</code> · Pattern: <code>UNSANITIZED_INPUT→COMMAND</code> · 94x across ecosystem
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
<code>kobako</code> · Pattern: <code>DESERIALIZATION→RCE</code> · 25x across ecosystem
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
<code>@nocobase/plugin-notification-in-app-message</code> · Pattern: <code>UNCLASSIFIED</code> · 601x across ecosystem
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
<code>flyto-core</code> · Pattern: <code>PATH_TRAVERSAL→FILE_WRITE</code> · 57x across ecosystem
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
<code>github.com/prebid/prebid-server</code> · Pattern: <code>SSRF→INTERNAL_ACCESS</code> · 122x across ecosystem
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
<code>pheditor/pheditor</code> · Pattern: <code>MISSING_AUTH→ENDPOINT</code> · 63x across ecosystem
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
<code>@prompty/core</code> · Pattern: <code>UNSANITIZED_INPUT→TEMPLATE</code> · 20x across ecosystem
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
<code>github.com/nuclio/nuclio</code> · Pattern: <code>UNCLASSIFIED</code> · 601x across ecosystem
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
<code>mcp-pinot-server</code> · Pattern: <code>UNSANITIZED_INPUT→SQL</code> · 32x across ecosystem
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
<code>gogs.io/gogs</code> · Pattern: <code>UNCLASSIFIED</code> · 601x across ecosystem
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
<code>vm2</code> · Pattern: <code>UNCLASSIFIED</code> · 601x across ecosystem
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
<code>vm2</code> · Pattern: <code>UNCLASSIFIED</code> · 601x across ecosystem
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
<code>vm2</code> · Pattern: <code>UNCLASSIFIED</code> · 601x across ecosystem
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
<code>vm2</code> · Pattern: <code>UNCLASSIFIED</code> · 601x across ecosystem
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
<code>@nyariv/sandboxjs</code> · Pattern: <code>TYPE_CONFUSION→BYPASS</code> · 7x across ecosystem
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
<code>github.com/free5gc/smf</code> · Pattern: <code>MISSING_AUTH→ENDPOINT</code> · 63x across ecosystem
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
<code>github.com/enchant97/note-mark/backend</code> · Pattern: <code>INSECURE_DEFAULT→CONFIG</code> · 32x across ecosystem
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
<code>github.com/jkroepke/openvpn-auth-oauth2</code> · Pattern: <code>MISSING_AUTH→ENDPOINT</code> · 63x across ecosystem
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
<code>wwbn/avideo</code> · Pattern: <code>UNSANITIZED_INPUT→XSS</code> · 108x across ecosystem
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
<code>github.com/daptin/daptin</code> · Pattern: <code>PATH_TRAVERSAL→FILE_WRITE</code> · 57x across ecosystem
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
<code>axios</code> · Pattern: <code>UNSANITIZED_INPUT→HEADER</code> · 16x across ecosystem
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
<h3>GHSA-xp7j-h7jc-4w8p</h3>
<p>
<code>CRITICAL 9.9</code> · 2026-09-08 · Go<br>
<code>github.com/semaphoreui/semaphore</code> · Pattern: <code>UNSANITIZED_INPUT→COMMAND</code> · 94x across ecosystem
</p>
<p><b>Root cause</b> : The application directly passed user-controlled Git URLs to the `git` command-line utility without proper sanitization or argument separation. An attacker could craft a Git URL starting with a hyphen (&#39;-&#39;), which `git` would interpret as a command-line option rather than a repository path, leading to arbitrary command execution.</p>
<p><b>Impact</b> : An attacker could execute arbitrary commands on the server where Semaphore U is running, potentially leading to full system compromise, data exfiltration, or denial of service.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/db_lib/CmdGitClient.go
+++ b/db_lib/CmdGitClient.go
@@ -115,6 +115,7 @@ func (c CmdGitClient) Clone(r GitRepository) error {
 		&#34;--recursive&#34;,
 		&#34;--branch&#34;,
 		r.Repository.GitBranch,
+		&#34;--end-of-options&#34;,
 		r.Repository.GetGitURL(false),
 		dirName)
 }</pre>
</details>
<p><b>Fix</b> : The patch introduces a `ValidateGitURL` function that rejects Git URLs starting with a hyphen. This validation is applied when a repository is created or updated. Additionally, the `--end-of-options` argument is added to all `git` commands that take a user-controlled URL, explicitly telling `git` to treat subsequent arguments as positional parameters rather than options.</p>
<p>
<a href="https://github.com/advisories/GHSA-xp7j-h7jc-4w8p">Advisory</a> · <a href="https://github.com/semaphoreui/semaphore/commit/7e8a9434bd81b82cf42220151c74801ea97542d6">Commit</a>
</p>
<hr>
<h3>GHSA-9x44-4gxf-8c25</h3>
<p>
<code>CRITICAL 9.9</code> · 2026-08-28 · PHP<br>
<code>pimcore/pimcore</code> · Pattern: <code>UNSANITIZED_INPUT→SQL</code> · 32x across ecosystem
</p>
<p><b>Root cause</b> : The vulnerability stemmed from insufficient validation of user-supplied field names for DataObject class definitions. These field names were directly incorporated into generated PHP class files (as properties, getters/setters, and constants) and used verbatim in SQL ALTER TABLE DDL statements without proper sanitization or quoting. This allowed an attacker to inject arbitrary PHP code or SQL commands by crafting a malicious field name.</p>
<p><b>Impact</b> : An attacker could achieve remote code execution on the server by injecting PHP code into the generated class files, or execute arbitrary SQL commands, leading to full system compromise, data manipulation, or data exfiltration.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/models/DataObject/ClassDefinition/Data.php
+++ b/models/DataObject/ClassDefinition/Data.php
@@ -166,6 +167,14 @@ public function getPermissions(): array|string|null
      */
     public function setName(string $name): static
     {
+        if ($name !== &#39;&#39; &amp;&amp; !preg_match(&#39;/^[a-zA-Z_][a-zA-Z0-9_]{0,62}$/&#39;, $name)) {
+            throw new InvalidArgumentException(sprintf(&#39;Invalid field name &#34;%s&#34;&#39;, $name));
+        }
+
         $this-&gt;name = $name;
 
         return $this;
--- a/models/DataObject/ClassDefinition/Helper/Dao.php
+++ b/models/DataObject/ClassDefinition/Helper/Dao.php
@@ -39,31 +39,31 @@ protected function addIndexToField(DataObject
                     // multicolumn field
                     foreach ($columnType as $fkey =&gt; $fvalue) {
                         $indexName = $field-&gt;getName().&#39;__&#39;.$fkey;
-                        $columnName = &#39;`&#39; . $indexName . &#39;`&#39;;
+                        $columnName = $this-&gt;db-&gt;quoteIdentifier($indexName);
                         if ($unique) {
                             if ($isLocalized) {
-                                $columnName .= &#39;,`language`&#39;;
+                                $columnName .= &#39;,&#39; . $this-&gt;db-&gt;quoteIdentifier(&#39;language&#39;);
                             } elseif ($isFieldcollection) {
-                                $columnName .= &#39;,`fieldname`&#39;;
+                                $columnName .= &#39;,&#39; . $this-&gt;db-&gt;quoteIdentifier(&#39;fieldname&#39;);
                             }
                         }
                         if ($this-&gt;indexDoesNotExist($table, $prefix, $indexName)) {
-                            $this-&gt;db-&gt;executeQuery(&#39;ALTER TABLE `&#39; . $table . &#39;` ADD &#39; . $uniqueStr . &#39;INDEX `&#39; . $prefix . $indexName . &#39;` (&#39; . $columnName . &#39;);&#39;);
+                            $this-&gt;db-&gt;executeQuery(&#39;ALTER TABLE &#39; . $this-&gt;db-&gt;quoteIdentifier($table) . &#39; ADD &#39; . $uniqueStr . &#39;INDEX &#39; . $this-&gt;db-&gt;quoteIdentifier($prefix . $indexName) . &#39; (&#39; . $columnName . &#39;);&#39;);
                         }
                     }
                 } else {
                     // single -column field
                     $indexName = $field-&gt;getName();
-                    $columnName = &#39;`&#39; . $indexName . &#39;`&#39;;
+                    $columnName = $this-&gt;db-&gt;quoteIdentifier($indexName);
                     if ($unique) {
                         if ($isLocalized) {
-                            $columnName .= &#39;,`language`&#39;;
+                            $columnName .= &#39;,&#39; . $this-&gt;db-&gt;quoteIdentifier(&#39;language&#39;);
                         } elseif ($isFieldcollection) {
-                            $columnName .= &#39;,`fieldname`&#39;;
+                            $columnName .= &#39;,&#39; . $this-&gt;db-&gt;quoteIdentifier(&#39;fieldname&#39;);
                         }
                     }
                     if ($this-&gt;indexDoesNotExist($table, $prefix, $indexName)) {
-                        $this-&gt;db-&gt;executeQuery(&#39;ALTER TABLE `&#39; . $table . &#39;` ADD &#39; . $uniqueStr . &#39;INDEX `&#39; . $prefix . $indexName . &#39;` (&#39; . $columnName . &#39;);&#39;);
+                        $this-&gt;db-&gt;executeQuery(&#39;ALTER TABLE &#39; . $this-&gt;db-&gt;quoteIdentifier($table) . &#39; ADD &#39; . $uniqueStr . &#39;INDEX &#39; . $this-&gt;db-&gt;quoteIdentifier($prefix . $indexName) . &#39; (&#39; . $columnName . &#39;);&#39;);
                     }
                 }
             } else {</pre>
</details>
<p><b>Fix</b> : The patch introduces a regular expression validation for DataObject field names to ensure they adhere to a strict alphanumeric and underscore format, preventing injection of special characters. Additionally, all SQL identifiers (table names, column names, index names) in ALTER TABLE statements are now properly quoted using `db-&gt;quoteIdentifier()` to prevent SQL injection.</p>
<p>
<a href="https://github.com/advisories/GHSA-9x44-4gxf-8c25">Advisory</a> · <a href="https://github.com/pimcore/pimcore/commit/a4f8c3cfee58b7d5fe4873d67782eff58dae9b9d">Commit</a>
</p>
<hr>
<h3>GHSA-c64q-hj4j-375f</h3>
<p>
<code>CRITICAL 9.9</code> · 2026-08-28 · Java<br>
<code>org.yamcs:yamcs-core</code> · Pattern: <code>UNSANITIZED_INPUT→COMMAND</code> · 94x across ecosystem
</p>
<p><b>Root cause</b> : The Yamcs StreamSQL `LIKE` expression directly embedded user-controlled pattern strings into dynamically compiled Java code (via Janino) without proper escaping. This allowed an authenticated attacker to inject arbitrary Java code into the `LikeExpression`&#39;s `fillCode_getValueReturn` method.</p>
<p><b>Impact</b> : An authenticated attacker could execute arbitrary code on the server, leading to full system compromise, data exfiltration, or denial of service.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/yamcs-core/src/main/java/org/yamcs/yarch/streamsql/LikeExpression.java
+++ b/yamcs-core/src/main/java/org/yamcs/yarch/streamsql/LikeExpression.java
@@ -23,5 +23,5 @@ public void fillCode_getValueReturn(StringBuilder code) throws StreamSqlExceptio
         code.append(&#34;org.yamcs.yarch.streamsql.Utils.like(&#34;);
         children[0].fillCode_getValueReturn(code);
         code.append(&#34;, \&#34;&#34;);
-        code.append(likeClause.pattern);
+        ValueExpression.escapeJavaString(likeClause.pattern, code);
         code.append(&#34;\&#34;)&#34;);</pre>
</details>
<p><b>Fix</b> : The patch introduces a static `escapeJavaString` method in `ValueExpression` and applies it to the `likeClause.pattern` before embedding it into the dynamically generated Java code. This ensures that special characters in the user-provided pattern are properly escaped, preventing code injection.</p>
<p>
<a href="https://github.com/advisories/GHSA-c64q-hj4j-375f">Advisory</a> · <a href="https://github.com/yamcs/yamcs/commit/640e1598b7097b521692e89dd47a39b6cb1fc663">Commit</a>
</p>
<hr>
<h3>GHSA-pfvc-3p5h-x7h6</h3>
<p>
<code>CRITICAL 9.9</code> · 2026-07-31 · Go<br>
<code>github.com/pterodactyl/wings</code> · Pattern: <code>UNCLASSIFIED</code> · 601x across ecosystem
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
<code>github.com/kube-logging/logging-operator</code> · Pattern: <code>UNSANITIZED_INPUT→COMMAND</code> · 94x across ecosystem
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
<code>@better-auth/scim</code> · Pattern: <code>MISSING_AUTHZ→RESOURCE</code> · 108x across ecosystem
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
<code>github.com/fission/fission</code> · Pattern: <code>UNCLASSIFIED</code> · 601x across ecosystem
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
<code>github.com/fission/fission</code> · Pattern: <code>PRIVILEGE_ESCALATION→ROLE</code> · 42x across ecosystem
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
<code>github.com/fission/fission</code> · Pattern: <code>UNCLASSIFIED</code> · 601x across ecosystem
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
<code>github.com/fission/fission</code> · Pattern: <code>UNCLASSIFIED</code> · 601x across ecosystem
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
<code>@deepstream/server</code> · Pattern: <code>UNCLASSIFIED</code> · 601x across ecosystem
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
<code>gogs.io/gogs</code> · Pattern: <code>UNCLASSIFIED</code> · 601x across ecosystem
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
<code>paymenter/paymenter</code> · Pattern: <code>UNCLASSIFIED</code> · 601x across ecosystem
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
<code>pheditor/pheditor</code> · Pattern: <code>UNSANITIZED_INPUT→COMMAND</code> · 94x across ecosystem
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
<code>github.com/juev/nebula-mesh</code> · Pattern: <code>PRIVILEGE_ESCALATION→ROLE</code> · 42x across ecosystem
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
<h3>GHSA-xwwr-4h3p-r22c</h3>
<p>
<code>CRITICAL 9.8</code> · 2026-09-10 · Go<br>
<code>github.com/rclone/rclone</code> · Pattern: <code>UNCLASSIFIED</code> · 601x across ecosystem
</p>
<p><b>Root cause</b> : </p>
<p><b>Impact</b> : </p>
<p><b>Fix</b> : </p>
<p>
<a href="https://github.com/advisories/GHSA-xwwr-4h3p-r22c">Advisory</a> · <a href="https://github.com/rclone/rclone/commit/90595f34f27f569be6b27c57fe5ab65057d323bd">Commit</a>
</p>
<hr>
<h3>GHSA-92f5-vc22-8j33</h3>
<p>
<code>CRITICAL 9.8</code> · 2026-09-08 · C#<br>
<code>Microsoft.Native.Quic.MsQuic.Schannel</code> · Pattern: <code>UNCLASSIFIED</code> · 601x across ecosystem
</p>
<p><b>Root cause</b> : The vulnerability existed because the QUIC implementation did not properly validate the state of a network path when processing incoming packets. An attacker could send specially crafted packets that would cause the system to attempt to use an inactive or invalid path, leading to memory corruption.</p>
<p><b>Impact</b> : An attacker could achieve remote code execution on the target system by exploiting the memory corruption, allowing them to execute arbitrary code with the privileges of the QUIC process.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/src/core/connection.c
+++ b/src/core/connection.c
@@ -5458,7 +5458,7 @@ QuicConnRecvPostProcessing(
 
     if (Packet-&gt;HasNonProbingFrame &amp;&amp;
         Packet-&gt;NewLargestPacketNumber &amp;&amp;
-        !(*Path)-&gt;IsActive) {
+        !(*Path)-&gt;IsActive &amp;&amp; (*Path)-&gt;InUse) {</pre>
</details>
<p><b>Fix</b> : The patch adds an additional check to ensure that a network path is not only inactive but also &#39;InUse&#39; before proceeding with path switching logic. This prevents the system from attempting to use a path that is not properly initialized or valid, thereby mitigating the memory corruption vulnerability.</p>
<p>
<a href="https://github.com/advisories/GHSA-92f5-vc22-8j33">Advisory</a> · <a href="https://github.com/microsoft/msquic/commit/583e7d5b509bb0bfa3518482d98879b6eda41ad0">Commit</a>
</p>
<hr>
<h3>GHSA-rcr6-4jqh-j84m</h3>
<p>
<code>CRITICAL 9.8</code> · 2026-09-08 · Go<br>
<code>gitea.dev</code> · Pattern: <code>UNCLASSIFIED</code> · 601x across ecosystem
</p>
<p><b>Root cause</b> : </p>
<p><b>Impact</b> : </p>
<p><b>Fix</b> : </p>
<p>
<a href="https://github.com/advisories/GHSA-rcr6-4jqh-j84m">Advisory</a> · <a href="https://github.com/go-gitea/gitea/commit/470d34b1de87d901bd9135564d5ee18c0d339e82">Commit</a>
</p>
<hr>
<h3>GHSA-w6f5-v2h6-g786</h3>
<p>
<code>CRITICAL 9.8</code> · 2026-09-08 · PHP<br>
<code>predis/predis</code> · Pattern: <code>UNSANITIZED_INPUT→COMMAND</code> · 94x across ecosystem
</p>
<p><b>Root cause</b> : The vulnerability stemmed from how Predis handled pipelined commands, particularly in aggregate connections (like Redis Cluster). It would concatenate all serialized commands into a single buffer and then write this buffer to the connection. This batching, combined with the lack of proper CRLF (carriage return and line feed) sanitization, allowed an attacker to inject arbitrary Redis commands by smuggling CRLF sequences within a command argument, effectively terminating the current command and starting a new one.</p>
<p><b>Impact</b> : An attacker could inject arbitrary Redis commands, leading to data manipulation, unauthorized access, or even remote code execution if the Redis server is configured to load modules or execute Lua scripts. Additionally, by injecting malformed commands or a large number of commands, an attacker could trigger a denial of service condition on the Redis server.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/src/Pipeline/ConnectionErrorProof.php
+++ b/src/Pipeline/ConnectionErrorProof.php
@@ -92,14 +92,12 @@ protected function executeCluster(ClusterInterface $connection, SplQueue $comman
         $responses = [];
         $sizeOfPipe = count($commands);
         $exceptions = [];
-        $buffer = &#39;&#39;;
 
         foreach ($commands as $command) {
-            $buffer .= $command-&gt;serializeCommand();
+            $nodeConnection = $connection-&gt;getConnectionByCommand($command);
+            $nodeConnection-&gt;write($command-&gt;serializeCommand());
         }
 
-        $connection-&gt;write($buffer);
-
         for ($i = 0; $i &lt; $sizeOfPipe; ++$i) {</pre>
</details>
<p><b>Fix</b> : The patch refactors the command writing logic for pipelined commands. Instead of buffering all commands and writing them in one go, it now iterates through each command and writes it individually to the appropriate node connection, especially for aggregate connections. This prevents CRLF smuggling by ensuring each command is sent as a distinct unit, rather than being part of a larger, potentially injectable buffer.</p>
<p>
<a href="https://github.com/advisories/GHSA-w6f5-v2h6-g786">Advisory</a> · <a href="https://github.com/predis/predis/commit/053cb4b6ac7fb1f469ead96a78d059bc0458e408">Commit</a>
</p>
<hr>
<h3>GHSA-2v6v-25fm-p4fg</h3>
<p>
<code>CRITICAL 9.8</code> · 2026-09-02 · Go<br>
<code>github.com/seaweedfs/seaweedfs</code> · Pattern: <code>MISSING_AUTH→ENDPOINT</code> · 63x across ecosystem
</p>
<p><b>Root cause</b> : The SeaweedFS filer&#39;s IAM gRPC service endpoints, which manage S3 users and access keys, lacked any authentication mechanism. This allowed any unauthenticated client to invoke administrative functions.</p>
<p><b>Impact</b> : An attacker could create, modify, or delete S3 users and their access keys, effectively gaining full administrative control over the S3-compatible storage and potentially accessing or manipulating all stored data.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/weed/server/filer_server_handlers_iam_grpc.go
+++ b/weed/server/filer_server_handlers_iam_grpc.go
@@ -32,6 +32,30 @@
 
 func NewIamGrpcServer(credentialManager *credential.CredentialManager) *IamGrpcServer {
 	return &amp;IamGrpcServer{
 		credentialManager: credentialManager,
+		adminSigningKey:   adminSigningKey,
 	}
 }
 
+func (s *IamGrpcServer) checkAdminAuth(ctx context.Context) error {
+	if len(s.adminSigningKey) == 0 {
+		return status.Error(codes.PermissionDenied, &#34;iam admin auth not configured&#34;)
+	}
+	md, ok := metadata.FromIncomingContext(ctx)
+	if !ok {
+		return status.Error(codes.Unauthenticated, &#34;missing metadata&#34;)
+	}
+	authHeaders := md.Get(&#34;authorization&#34;)
+	if len(authHeaders) == 0 {
+		return status.Error(codes.Unauthenticated, &#34;missing authorization metadata&#34;)
+	}
+	raw := strings.TrimSpace(authHeaders[0])
+	parts := strings.Fields(raw)
+	if len(parts) != 2 || !strings.EqualFold(parts[0], &#34;Bearer&#34;) || parts[1] == &#34;&#34; {
+		return status.Error(codes.Unauthenticated, &#34;authorization header must use Bearer scheme&#34;)
+	}
+	token := parts[1]
+	parsed, err := security.DecodeJwt(s.adminSigningKey, security.EncodedJwt(token), &amp;security.SeaweedFilerAdminClaims{})
+	if err != nil || parsed == nil || !parsed.Valid {
+		return status.Error(codes.Unauthenticated, &#34;invalid admin token&#34;)
+	}
+	return nil
+}
+
 //////////////////////////////////////////////////
 // Configuration Management
 
 func (s *IamGrpcServer) GetConfiguration(ctx context.Context, req *iam_pb.GetConfigurationRequest) (*iam_pb.GetConfigurationResponse, error) {
+	if err := s.checkAdminAuth(ctx); err != nil {
+		return nil, err
+	}
+	if req == nil {
+		return nil, status.Errorf(codes.InvalidArgument, &#34;request is required&#34;)
+	}
 	glog.V(4).Infof(&#34;GetConfiguration&#34;)</pre>
</details>
<p><b>Fix</b> : The patch introduces a `checkAdminAuth` method that verifies a Bearer token signed by a pre-configured filer write-signing key. This method is now called at the beginning of every IAM gRPC service handler to ensure only authenticated and authorized requests are processed.</p>
<p>
<a href="https://github.com/advisories/GHSA-2v6v-25fm-p4fg">Advisory</a> · <a href="https://github.com/seaweedfs/seaweedfs/commit/5e8f99f40a8abc7b449aefd260516443377041c7">Commit</a>
</p>
<hr>
<h3>GHSA-m4rf-3fr8-xwx3</h3>
<p>
<code>CRITICAL 9.8</code> · 2026-09-01 · Python<br>
<code>nltk</code> · Pattern: <code>UNSANITIZED_INPUT→COMMAND</code> · 94x across ecosystem
</p>
<p><b>Root cause</b> : The vulnerability stemmed from an incomplete fix for a previous JVM argument injection issue. The `_validate_java_options` function, intended to sanitize JVM arguments, did not adequately restrict per-call options, allowing an attacker to inject dangerous JVM flags like `-XX:OnError` or `-D` system properties. This bypass enabled the execution of arbitrary commands or other malicious actions.</p>
<p><b>Impact</b> : An attacker could achieve arbitrary command execution on the system running the NLTK application by injecting specially crafted JVM arguments. This could lead to full system compromise, data exfiltration, or denial of service.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/nltk/internals.py
+++ b/nltk/internals.py
@@ -43,23 +59,64 @@
     &#34;-xcomp&#34;,  # compile-only mode
     &#34;-xmixed&#34;,  # mixed mode (JVM default)
     &#34;-verbose&#34;,  # diagnostic output: -verbose:gc
-    &#34;-xx:&#34;,  # advanced tuning:  -XX:+UseG1GC
+
 ) 
 
 _SAFE_JVM_EXACT = frozenset({&#34;-server&#34;, &#34;-client&#34;})
 
+# ``--add-modules &lt;module-list&gt;`` is required by CoreNLP on JDK 9-11 (a CoreNLP
+# dependency uses the JAXB module dropped from the default set). The value is a
+# comma-separated list of module names -- it names JDK modules, and because
+# ``--module-path`` / ``-p`` is NOT allowlisted it cannot point at attacker code.
+# Restrict the value to a plain module-list shape so nothing else rides through.
+_MODULE_LIST_RE = re.compile(r&#34;\A[A-Za-z0-9_.,-]+\Z&#34;)
+
+# Every flag the allowlist accepts (heap/stack sizing, -verbose, -server/-client,
+# --add-modules) is a single simple token; none contains whitespace or a shell
+# metacharacter. Rejecting those characters is therefore a free, name-agnostic
+# defense-in-depth layer (it has no false positives now that -D, whose values may
+# legitimately contain them, is not accepted): e.g. a malformed ``-Xmx512m ; rm``
+# token cannot ride through on the ``-xmx`` prefix.
+_UNSAFE_OPTION_CHARS = frozenset(&#34; \t\r\n;|&amp;$`&lt;&gt;()[]*?!&#39;\&#34;\\&#34;)
 
 def _validate_java_options(options):
     &#34;&#34;&#34;
-    Raise ValueError if *options* contains JVM flags that can change
-    the executed program, load agents, or expand argument files.
-
-    Uses an allowlist of safe JVM memory/tuning flags that NLTK&#39;s Java
-    wrapper is known to need.  This is intentionally stricter than a
-    denylist so that -jar, @argfile, and future dangerous flags are
-    rejected without needing to be enumerated (CVE-2026-12841, CWE-88).
+    Raise ValueError if *options* contains JVM flags that can change the
+    executed program, run a command, load agents, or expand argument files.
+
+    Uses a minimal allowlist of exactly the flags NLTK&#39;s Java wrappers and the
+    Stanford CoreNLP documentation use (heap/stack sizing, -verbose,
+    -server/-client, and ``--add-modules``). This is intentionally stricter than
+    a denylist so that -jar, @argfile, ``-XX:OnError=&lt;cmd&gt;``, dangerous ``-D``
+    system properties, and future dangerous flags are all rejected without
+    needing to be enumerated (CVE-2026-12841, CWE-88). Applications needing an
+    unlisted flag use ``java(..., trusted_raw_options=[...])``.
     &#34;&#34;&#34;
-    for flag in options:
+    opts = list(options)
+    i = 0
+    while i &lt; len(opts):
+        flag = opts[i]
+
+        # A JVM flag is a non-empty string; anything else cannot be reasoned
+        # about safely, so reject it rather than call .lower() on it.
+        if not isinstance(flag, str) or not flag:
+            raise ValueError(
+                f&#34;java_options contains an invalid (non-string or empty) entry: &#34;
+                f&#34;{flag!r} (CVE-2026-12841, CWE-88).&#34;
+            )
+
+        # Shape guard: no legitimate allowed flag contains whitespace, a control
+        # character, or a shell metacharacter; reject any that does.
+        if any(
+            c.isspace() or ord(c) &lt; 0x20 or ord(c) == 0x7F or c in _UNSAFE_OPTION_CHARS
+            for c in flag
+        ):
+            raise ValueError(
+                f&#34;java_options contains whitespace, a control character, or a &#34;
+                f&#34;shell metacharacter, which a valid JVM flag never does: &#34;
+                f&#34;{flag!r} (CVE-2026-12841, CWE-88).&#34;
+            )
+
         n = flag.lower()
 
         # @argfile references are expanded by the Java launcher before
@@ -70,21 +127,38 @@ def _validate_java_options(options):
                 f&#34;reference: {flag!r} (CVE-2026-12841, CWE-88).&#34;
             )
 
-        # Allow -Dkey=value system properties. The prefix is always
-        # uppercase -D in valid usage; check the original flag.
-        if flag.startswith(&#34;-D&#34;) and &#34;=&#34; in flag:
+        # --add-modules &lt;modules&gt;  (two tokens) or  --add-modules=&lt;modules&gt;.
+        if n == &#34;--add-modules&#34;:
+            mods = opts[i + 1] if i + 1 &lt; len(opts) else None
+            if not isinstance(mods, str) or not _MODULE_LIST_RE.match(mods):
+                raise ValueError(
+                    f&#34;--add-modules must be followed by a plain module list, got &#34;
+                    f&#34;{mods!r} (CVE-2026-12841, CWE-88).&#34;
+                )
+            i += 2
+            continue
+        if n.startswith(&#34;--add-modules=&#34;):
+            if not _MODULE_LIST_RE.match(flag.split(&#34;=&#34;, 1)[1]):
+                raise ValueError(
+                    f&#34;--add-modules has a non-module-list value: {flag!r} &#34;
+                    &#34;(CVE-2026-12841, CWE-88).&#34;
+                )
+            i += 1
             continue
 
         if n in _SAFE_JVM_EXACT:
+            i += 1
             continue
 
         if n.startswith(_SAFE_JVM_PREFIXES):
+            i += 1
             continue
 
         raise ValueError(
             f&#34;java_options contains a disallowed JVM/launcher flag: {flag!r}. &#34;
-            &#34;Only JVM memory-tuning and safe runtime flags are permitted &#34;
-            &#34;(CVE-2026-12841, CWE-88).&#34;
+            &#34;Only JVM memory/stack tuning, -verbose, -server/-client and &#34;
+            &#34;--add-modules are permitted; pass anything else through &#34;
+            &#34;java(trusted_raw_options=...) (CVE-2026-12841, CWE-88).&#34;
         )
 
 
@@ -209,4 +297,10 @@ def java(
         if isinstance(options, str):
             options = options.split()
         java_options = list(options)
+        # Per-call options reach subprocess.Popen directly, so they must be
+        # validated too -- config_java() alone is not enough (CVE-2026-12841,
+        # CWE-88). Without this a caller-supplied -jav</pre>
</details>
<p><b>Fix</b> : The patch significantly tightens the allowlist for JVM arguments, explicitly removing `-XX:` and `-D` prefixes, which were previously allowed. It also adds new validation checks for unsafe characters and ensures that per-call options are also subjected to the same strict validation as global options, preventing the bypass of the original fix.</p>
<p>
<a href="https://github.com/advisories/GHSA-m4rf-3fr8-xwx3">Advisory</a> · <a href="https://github.com/nltk/nltk/commit/8fa9650b6009aacfdebbc33d2a08d32c0858ea6c">Commit</a>
</p>
<hr>
<h3>GHSA-73mf-m39p-wpm9</h3>
<p>
<code>CRITICAL 9.8</code> · 2026-08-28 · Java<br>
<code>org.yamcs:yamcs-core</code> · Pattern: <code>UNSANITIZED_INPUT→TEMPLATE</code> · 20x across ecosystem
</p>
<p><b>Root cause</b> : The vulnerability stemmed from the Yamcs server processing user-controlled input as part of an instance-template argument, which was then directly fed into a YAML parser. This allowed an attacker to inject arbitrary YAML, including directives that could lead to object instantiation and method invocation, effectively achieving Remote Code Execution.</p>
<p><b>Impact</b> : An attacker could achieve arbitrary code execution on the server running Yamcs, leading to full compromise of the system, including data theft, modification, or denial of service.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/yamcs-core/src/main/java/org/yamcs/templating/Template.java
+++ b/yamcs-core/src/main/java/org/yamcs/templating/Template.java
@@ -47,6 +52,66 @@ public String process(Map&lt;String, Object&gt; args) {
         return templateProcessor.process(args);
     }
 
+    public String processAndSanitizeYaml(Map&lt;String, Object&gt; userArgs) {
+        Map&lt;String, Object&gt; tokenArgs = new HashMap&lt;&gt;();</pre>
</details>
<p><b>Fix</b> : The patch introduces a sanitization layer for YAML processing. It replaces user-provided string arguments with unique UUID tokens before template processing. After the template is rendered, the output is parsed into a YAML object structure, and then the tokens are safely replaced with their original string values. This ensures that user input is treated as data and not as executable YAML directives.</p>
<p>
<a href="https://github.com/advisories/GHSA-73mf-m39p-wpm9">Advisory</a> · <a href="https://github.com/yamcs/yamcs/commit/549f295cf8c5496a5e799d6bec2432ef976c82aa">Commit</a>
</p>
<hr>
<h3>GHSA-jrw6-7x4q-w25j</h3>
<p>
<code>CRITICAL 9.8</code> · 2026-08-26 · Python<br>
<code>senaite.core</code> · Pattern: <code>UNSANITIZED_INPUT→COMMAND</code> · 94x across ecosystem
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
<code>qwed-mcp</code> · Pattern: <code>UNSANITIZED_INPUT→COMMAND</code> · 94x across ecosystem
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
<tr><td>Total advisories</td><td>1961</td></tr>
<tr><td>Unique patterns</td><td>50</td></tr>
<tr><td>Pending</td><td>42</td></tr>
<tr><td>Last updated</td><td>2026-09-13</td></tr>
</table>
</details>
<hr>
<sub><a href="https://christbowel.com">christbowel.com</a></sub>
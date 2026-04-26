<div align="center">
<h1>🎣 Open Source Daily Catch</h1>
<p><b>Automated Patch Intelligence for Security Engineers</b></p>
<p>
<a href="https://github.com/christbowel/osdc/actions/workflows/daily.yml"><img src="https://github.com/christbowel/osdc/actions/workflows/daily.yml/badge.svg" alt="Analysis"></a>
<a href="https://github.com/christbowel/osdc/actions/workflows/render.yml"><img src="https://github.com/christbowel/osdc/actions/workflows/render.yml/badge.svg" alt="Render"></a>
<a href="https://christbowel.github.io/OSDC"><img src="https://img.shields.io/badge/advisories-321-blue" alt="Advisories"></a>
<a href="https://christbowel.github.io/OSDC"><img src="https://img.shields.io/badge/patterns-43-purple" alt="Patterns"></a>
</p>
<p>
<a href="https://christbowel.github.io/OSDC">Live dashboard</a> · <a href="#how-it-works">How it works</a>
</p>
</div>
<hr>
<h3>GHSA-246w-jgmq-88fg</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-04-22 · Go<br>
<code>github.com/jkroepke/openvpn-auth-oauth2</code> · Pattern: <code>MISSING_AUTH→ENDPOINT</code> · 12x across ecosystem
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
<code>wwbn/avideo</code> · Pattern: <code>UNSANITIZED_INPUT→XSS</code> · 19x across ecosystem
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
<code>github.com/daptin/daptin</code> · Pattern: <code>PATH_TRAVERSAL→FILE_WRITE</code> · 13x across ecosystem
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
<code>axios</code> · Pattern: <code>UNSANITIZED_INPUT→HEADER</code> · 3x across ecosystem
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
<h3>GHSA-8x35-hph8-37hq</h3>
<p>
<code>CRITICAL 9.8</code> · 2026-04-24 · JavaScript<br>
<code>electerm</code> · Pattern: <code>UNSANITIZED_INPUT→COMMAND</code> · 22x across ecosystem
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
<code>github.com/woven-planet/go-zserio</code> · Pattern: <code>DOS→RESOURCE_EXHAUSTION</code> · 10x across ecosystem
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
<code>praisonai</code> · Pattern: <code>UNSANITIZED_INPUT→COMMAND</code> · 22x across ecosystem
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
<code>Microsoft.Native.Quic.MsQuic.OpenSSL</code> · Pattern: <code>UNCLASSIFIED</code> · 51x across ecosystem
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
<code>uefi-firmware</code> · Pattern: <code>BUFFER_OVERFLOW→HEAP</code> · 19x across ecosystem
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
<code>upsonic</code> · Pattern: <code>UNCLASSIFIED</code> · 51x across ecosystem
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
<code>changedetection.io</code> · Pattern: <code>MISSING_AUTH→ENDPOINT</code> · 12x across ecosystem
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
<h3>GHSA-v529-vhwc-wfc5</h3>
<p>
<code>CRITICAL 9.6</code> · 2026-04-23 · Ruby<br>
<code>openc3</code> · Pattern: <code>UNSANITIZED_INPUT→SQL</code> · 7x across ecosystem
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
<code>nimiq-block</code> · Pattern: <code>INTEGER_OVERFLOW→BOUNDARY</code> · 5x across ecosystem
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
<code>lollms</code> · Pattern: <code>UNSANITIZED_INPUT→XSS</code> · 19x across ecosystem
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
<h3>GHSA-j98m-w3xp-9f56</h3>
<p>
<code>CRITICAL 9.4</code> · 2026-04-14 · Python<br>
<code>excel-mcp-server</code> · Pattern: <code>PATH_TRAVERSAL→FILE_READ</code> · 20x across ecosystem
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
<code>@delmaredigital/payload-puck</code> · Pattern: <code>MISSING_AUTH→ENDPOINT</code> · 12x across ecosystem
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
<h3>GHSA-m5gr-86j6-99jp</h3>
<p>
<code>CRITICAL 9.1</code> · 2026-04-10 · Python<br>
<code>gramps-webapi</code> · Pattern: <code>PATH_TRAVERSAL→FILE_WRITE</code> · 13x across ecosystem
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
<h3>GHSA-6g38-8j4p-j3pr</h3>
<p>
<code>CRITICAL 0.0</code> · 2026-04-18 · Go<br>
<code>github.com/nhost/nhost</code> · Pattern: <code>IDOR→DATA_ACCESS</code> · 5x across ecosystem
</p>
<p><b>Root cause</b> : The code did not properly verify the email verification status of the user profile.</p>
<p><b>Impact</b> : An attacker could bypass the email verification process and take over an account.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before: profile.EmailVerified
After: profile.EmailVerified.IsVerified()</pre>
</details>
<p><b>Fix</b> : The patch ensures that the email verification status is checked using a method that returns a boolean value, preventing potential IDOR vulnerabilities.</p>
<p>
<a href="https://github.com/advisories/GHSA-6g38-8j4p-j3pr">Advisory</a> · <a href="https://github.com/nhost/nhost/commit/ec8dab3f2cf46e1131ddaf893d56c37aa00380b2">Commit</a>
</p>
<hr>
<h3>GHSA-xh72-v6v9-mwhc</h3>
<p>
<code>CRITICAL 0.0</code> · 2026-04-17 · JavaScript<br>
<code>openclaw</code> · Pattern: <code>MISSING_AUTH→ENDPOINT</code> · 12x across ecosystem
</p>
<p><b>Root cause</b> : The code did not validate the presence of an encryptKey before processing requests.</p>
<p><b>Impact</b> : An attacker could bypass authentication by sending a request without an encryptKey, allowing unauthorized access to webhook and card-action endpoints.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before:
-    return true;
After:
+    return false;</pre>
</details>
<p><b>Fix</b> : The patch ensures that an encryptKey is required for webhook and card-action requests, throwing an error if it is missing.</p>
<p>
<a href="https://github.com/advisories/GHSA-xh72-v6v9-mwhc">Advisory</a> · <a href="https://github.com/openclaw/openclaw/commit/c8003f1b33ed2924be5f62131bd28742c5a41aae">Commit</a>
</p>
<hr>
<h3>GHSA-wvhv-qcqf-f3cx</h3>
<p>
<code>CRITICAL 0.0</code> · 2026-04-10 · Go<br>
<code>github.com/patrickhener/goshs</code> · Pattern: <code>MISSING_AUTHZ→RESOURCE</code> · 22x across ecosystem
</p>
<p><b>Root cause</b> : The application&#39;s file-based Access Control List (ACL) mechanism, which uses &#39;.goshs&#39; files, was not consistently applied across all state-changing operations (delete, mkdir, put, upload). Specifically, the ACL check only looked for a &#39;.goshs&#39; file in the immediate directory, failing to consider ACLs defined in parent directories, and some operations lacked any ACL enforcement.</p>
<p><b>Impact</b> : An attacker could bypass intended access restrictions to delete, create, or modify files and directories, including potentially sensitive ones, even if a parent directory&#39;s &#39;.goshs&#39; file explicitly denied such actions.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/httpserver/handler.go
+++ b/httpserver/handler.go
@@ -83,8 +83,8 @@ func (fs *FileServer) doDir(file *os.File, w http.ResponseWriter, req *http.Requ
 		}
 	}
 
-	// Check if the dir has a .goshs ACL file
-	config, err := fs.findSpecialFile(file.Name())
+	// Check for effective .goshs ACL (walks up to webroot so parent configs apply recursively)
+	config, err := fs.findEffectiveACL(file.Name())
 	if err != nil
 		logger.Errorf(&#34;error reading file based access config: %+v&#34;, err)
 	}</pre>
</details>
<p><b>Fix</b> : The patch introduces a new `findEffectiveACL` function that recursively walks up the directory tree to find the nearest applicable &#39;.goshs&#39; ACL file. This function is now consistently used across all file and directory operations (doDir, doFile, deleteFile, handleMkdir, put, upload) to ensure proper authorization. Additionally, explicit checks were added to prevent the deletion or overwriting of &#39;.goshs&#39; ACL files themselves.</p>
<p>
<a href="https://github.com/advisories/GHSA-wvhv-qcqf-f3cx">Advisory</a> · <a href="https://github.com/patrickhener/goshs/commit/f212c4f4a126556bab008f79758e21a839ef2c0f">Commit</a>
</p>
<hr>
<h3>GHSA-3p68-rc4w-qgx5</h3>
<p>
<code>CRITICAL 0.0</code> · 2026-04-09 · JavaScript<br>
<code>axios</code> · Pattern: <code>SSRF→INTERNAL_ACCESS</code> · 35x across ecosystem
</p>
<p><b>Root cause</b> : The code does not properly validate or sanitize the hostname in the `no_proxy` environment variable, allowing attackers to bypass proxy settings and potentially access internal services.</p>
<p><b>Impact</b> : An attacker could use this vulnerability to perform SSRF attacks, accessing internal network resources without proper authorization.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">- 
+ +const normalizeNoProxyHost = (hostname) =&gt; {
+  if (!hostname) {
+    return hostname;
+  }
+
+  if (hostname.charAt(0) === &#39;[&#39; &amp;&amp; hostname.charAt(hostname.length - 1) === &#39;]&#39;) {
+    hostname = hostname.slice(1, -1);
+  }
+
+  return hostname.replace(/\.+$/, &#39;&#39;);
+};</pre>
</details>
<p><b>Fix</b> : The patch introduces a function to normalize and parse the `no_proxy` entries, ensuring that only valid hostnames are considered for bypassing proxy settings.</p>
<p>
<a href="https://github.com/advisories/GHSA-3p68-rc4w-qgx5">Advisory</a> · <a href="https://github.com/axios/axios/commit/fb3befb6daac6cad26b2e54094d0f2d9e47f24df">Commit</a>
</p>
<hr>
<h3>GHSA-2679-6mx9-h9xc</h3>
<p>
<code>CRITICAL 0.0</code> · 2026-04-08 · Python<br>
<code>marimo</code> · Pattern: <code>MISSING_AUTH→ENDPOINT</code> · 12x across ecosystem
</p>
<p><b>Root cause</b> : The WebSocket endpoint was not properly authenticated before processing requests.</p>
<p><b>Impact</b> : An attacker could bypass authentication and execute arbitrary code on the server.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before:
    await websocket.close(
        code=1008, reason=&#34;Terminal only available in edit mode&#34;
    )
After:
    if app_state.enable_auth and not validate_auth(websocket):
        await websocket.close(
            WebSocketCodes.UNAUTHORIZED, &#34;MARIMO_UNAUTHORIZED&#34;
        )
        return</pre>
</details>
<p><b>Fix</b> : Added a validation step to check for proper authentication before allowing WebSocket connections.</p>
<p>
<a href="https://github.com/advisories/GHSA-2679-6mx9-h9xc">Advisory</a> · <a href="https://github.com/marimo-team/marimo/commit/c24d4806398f30be6b12acd6c60d1d7c68cfd12a">Commit</a>
</p>
<hr>
<h3>GHSA-2cqq-rpvq-g5qj</h3>
<p>
<code>CRITICAL 0.0</code> · 2026-04-07 · Java<br>
<code>org.openidentityplatform.openam:openam</code> · Pattern: <code>DESERIALIZATION→RCE</code> · 3x across ecosystem
</p>
<p><b>Root cause</b> : The code uses `ObjectInputStream` to deserialize data without proper validation or sanitization, allowing an attacker to execute arbitrary code.</p>
<p><b>Impact</b> : An attacker could exploit this vulnerability to execute arbitrary code on the server, potentially leading to full control of the system.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before:
- ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
After:
+ if (data.startsWith(&#34;com.sun.identity&#34;)) {
+     ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
+ } else {
+     throw new SecurityException(&#34;Invalid class name in deserialized data&#34;);
+ }</pre>
</details>
<p><b>Fix</b> : The patch adds a check for the class name during deserialization to prevent untrusted objects from being deserialized.</p>
<p>
<a href="https://github.com/advisories/GHSA-2cqq-rpvq-g5qj">Advisory</a> · <a href="https://github.com/OpenIdentityPlatform/OpenAM/commit/014007c63cacc834cc795a89fac0e611aebc4a32">Commit</a>
</p>
<hr>
<h3>GHSA-8h25-q488-4hxw</h3>
<p>
<code>HIGH 8.8</code> · 2026-04-23 · JavaScript<br>
<code>openlearnx</code> · Pattern: <code>UNSANITIZED_INPUT→COMMAND</code> · 22x across ecosystem
</p>
<p><b>Root cause</b> : The application allowed users to execute arbitrary code in a sandboxed environment (Docker containers). However, the initial sandbox implementation for Python lacked robust static analysis to prevent the import of dangerous modules or the use of sensitive functions, enabling an attacker to escape the sandbox and execute arbitrary commands on the host system.</p>
<p><b>Impact</b> : An attacker could escape the Docker container and execute arbitrary commands on the underlying host system, leading to full system compromise, data exfiltration, or further network penetration.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/backend/services/real_compiler_service.py
+++ b/backend/services/real_compiler_service.py
@@ -36,6 +36,68 @@
                 &#39;cpu_limit&#39;: &#39;1.0&#39;
             }
         }
-        
-        # Start execution worker
+        self.blocked_python_modules = {
+            &#34;os&#34;,
+            &#34;socket&#34;,
+            &#34;subprocess&#34;,
+            &#34;pty&#34;,
+            &#34;multiprocessing&#34;,
+            &#34;ctypes&#34;,
+            &#34;resource&#34;,
+            &#34;pwd&#34;,
+            &#34;grp&#34;,
+            &#34;signal&#34;,
+            &#34;fcntl&#34;,
+            &#34;selectors&#34;,
+            &#34;pathlib&#34;,
+            &#34;shutil&#34;,
+        }
+        self.blocked_python_calls = {
+            &#34;eval&#34;,
+            &#34;exec&#34;,
+            &#34;compile&#34;,
+            &#34;__import__&#34;,
+            &#34;open&#34;,
+            &#34;input&#34;,
+            &#34;globals&#34;,
+            &#34;locals&#34;,
+            &#34;vars&#34;,
+            &#34;getattr&#34;,
+            &#34;setattr&#34;,
+            &#34;delattr&#34;,
+        }
+        self.blocked_python_attrs = {
+            &#34;fork&#34;,
+            &#34;forkpty&#34;,
+            &#34;spawn&#34;,
+            &#34;spawnl&#34;,
+            &#34;spawnlp&#34;,
+            &#34;spawnv&#34;,
+            &#34;spawnvp&#34;,
+            &#34;system&#34;,
+            &#34;popen&#34;,
+            &#34;execl&#34;,
+            &#34;execle&#34;,
+            &#34;execlp&#34;,
+            &#34;execv&#34;,
+            &#34;execve&#34;,
+            &#34;execvp&#34;,
+            &#34;setsid&#34;,
+            &#34;dup2&#34;,
+        }
+        self.blocked_patterns = {
+            &#34;javascript&#34;: [
+                r&#34;require\s*\(\s*[&#39;\&#34;]child_process[&#39;\&#34;]\s*\)&#34;,
+                r&#34;require\s*\(\s*[&#39;\&#34;]net[&#39;\&#34;]\s*\)&#34;,
+                r&#34;require\s*\(\s*[&#39;\&#34;]dgram[&#39;\&#34;]\s*\)&#34;,
+                r&#34;process\.env&#34;,
+                r&#34;process\.binding&#34;,
+                r&#34;fs\.readFile|fs\.writeFile</pre>
</details>
<p><b>Fix</b> : The patch introduces static analysis for Python code to block dangerous modules (e.g., os, subprocess) and functions (e.g., eval, exec, open) that could be used for sandbox escape. It also adds regex-based blocking for dangerous patterns in JavaScript and other languages, and generally tightens resource limits and timeouts for all language executions.</p>
<p>
<a href="https://github.com/advisories/GHSA-8h25-q488-4hxw">Advisory</a> · <a href="https://github.com/th30d4y/OpenLearnX/commit/14765d7d1856d564747c55c5412e2f38feab079e">Commit</a>
</p>
<hr>
<h3>GHSA-2gw9-c2r2-f5qf</h3>
<p>
<code>HIGH 8.8</code> · 2026-04-21 · Go<br>
<code>github.com/m1k1o/neko/server</code> · Pattern: <code>PRIVILEGE_ESCALATION→ROLE</code> · 7x across ecosystem
</p>
<p><b>Root cause</b> : The application allowed authenticated users to update their profile without proper authorization checks on all fields. Specifically, the `IsAdmin` field within the user&#39;s session profile could be modified by a non-admin user through the `UpdateProfile` API endpoint.</p>
<p><b>Impact</b> : An authenticated non-admin user could elevate their privileges to that of an administrator, gaining full control over the application and potentially sensitive data or functionality.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">- 	data := session.Profile()
- 	if err := utils.HttpJsonRequest(w, r, &amp;data); err != nil {
- 		return err
+ 	profile := session.Profile()
+ 	if !profile.IsAdmin {
+ 		// Name is the only updatable field in the profile for non-admins
+ 		var payload types.MemberProfile
+ 		if err := utils.HttpJsonRequest(w, r, &amp;payload); err != nil {
+ 			return err
+ 		}
+ 		profile.Name = payload.Name
+ 	} else {
+ 		if err := utils.HttpJsonRequest(w, r, &amp;profile); err != nil {
+ 			return err
+ 		}
  	}
- 	err := api.sessions.Update(session.ID(), data)
+ 	err := api.sessions.Update(session.ID(), profile)</pre>
</details>
<p><b>Fix</b> : The patch introduces an authorization check in the `UpdateProfile` function. Non-admin users are now restricted to only updating their `Name` field, while the `IsAdmin` field and other sensitive profile attributes are protected from unauthorized modification.</p>
<p>
<a href="https://github.com/advisories/GHSA-2gw9-c2r2-f5qf">Advisory</a> · <a href="https://github.com/m1k1o/neko/commit/6b561feb9016badea99ae7305091c0ff55e1d114">Commit</a>
</p>
<hr>
<h3>GHSA-29qv-4j9f-fjw5</h3>
<p>
<code>HIGH 8.8</code> · 2026-04-16 · JavaScript<br>
<code>mathjs</code> · Pattern: <code>UNCLASSIFIED</code> · 51x across ecosystem
</p>
<p><b>Root cause</b> : The patch changes the function `isSafeProperty` to `isSafeObjectProperty`, which may not cover all cases as intended.</p>
<p><b>Impact</b> : An attacker could potentially access unsafe properties or methods of objects, leading to potential security vulnerabilities.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before:
- if (isSafeProperty(object, prop)) {
After:
+ if (isSafeObjectProperty(object, prop) || isSafeArrayProperty(object, prop)) {</pre>
</details>
<p><b>Fix</b> : The patch updates the function name and logic to ensure that only safe object properties are accessed, preventing potential security issues.</p>
<p>
<a href="https://github.com/advisories/GHSA-29qv-4j9f-fjw5">Advisory</a> · <a href="https://github.com/josdejong/mathjs/commit/513ab2a0e01004af91b31aada68fae8a821326ad">Commit</a>
</p>
<hr>
<h3>GHSA-66hx-chf7-3332</h3>
<p>
<code>HIGH 8.8</code> · 2026-04-14 · Python<br>
<code>pyload-ng</code> · Pattern: <code>PRIVILEGE_ESCALATION→ROLE</code> · 7x across ecosystem
</p>
<p><b>Root cause</b> : The application did not invalidate user sessions when a user&#39;s password, role, or permissions were changed. This allowed users to retain their old privileges until their session naturally expired or they manually logged out, even after an administrator had downgraded their access.</p>
<p><b>Impact</b> : An attacker or a malicious insider could maintain elevated privileges or access to resources that should have been revoked, potentially leading to unauthorized actions or data access.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/src/pyload/webui/app/blueprints/json_blueprint.py
+++ b/src/pyload/webui/app/blueprints/json_blueprint.py
@@ -9,7 +9,7 @@
 from pyload.core.api import Role
 from pyload.core.utils import format, fs
 
-from ..helpers import get_permission, login_required, permlist, render_template, set_permission
+from ..helpers import clear_all_user_sessions, get_permission, login_required, permlist, render_template, set_permission
 
 bp = flask.Blueprint(&#34;json&#34;, __name__)
 
@@ -360,6 +360,7 @@ def change_password(user_login, user_curpw, user_newpw):
     if not done:
         return jsonify(False), 403  #: Wrong password
 
+    clear_all_user_sessions(user_login)
     return jsonify(True)</pre>
</details>
<p><b>Fix</b> : The patch introduces a `clear_all_user_sessions` function and calls it whenever a user&#39;s password is changed, or their role or permissions are updated. This ensures that any active sessions for the affected user are immediately invalidated, forcing them to re-authenticate with their new, updated privileges.</p>
<p>
<a href="https://github.com/advisories/GHSA-66hx-chf7-3332">Advisory</a> · <a href="https://github.com/pyload/pyload/commit/e95804fb0d06cbb07d2ba380fc494d9ff89b68c1">Commit</a>
</p>
<hr>
<h3>GHSA-3p24-9x7v-7789</h3>
<p>
<code>HIGH 8.8</code> · 2026-04-13 · Java<br>
<code>gov.nsa.emissary:emissary</code> · Pattern: <code>UNSANITIZED_INPUT→COMMAND</code> · 22x across ecosystem
</p>
<p><b>Root cause</b> : The application allowed user-controlled input for IN_FILE_ENDING and OUT_FILE_ENDING configuration parameters to be used directly in shell commands without proper sanitization. This enabled attackers to inject arbitrary shell commands by crafting malicious file ending values.</p>
<p><b>Impact</b> : An attacker could execute arbitrary operating system commands on the server, potentially leading to full system compromise, data exfiltration, or denial of service.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- this.inFileEnding = configG.findStringEntry(&#34;IN_FILE_ENDING&#34;, &#34;&#34;);
+++ this.inFileEnding = cleanFileEnding(configG.findStringEntry(&#34;IN_FILE_ENDING&#34;, &#34;&#34;));
--- this.outFileEnding = configG.findStringEntry(&#34;OUT_FILE_ENDING&#34;, this.inFileEnding.isEmpty() ? &#34;.out&#34; : &#34;&#34;);
+++ this.outFileEnding = cleanFileEnding(configG.findStringEntry(&#34;OUT_FILE_ENDING&#34;, this.inFileEnding.isEmpty() ? &#34;.out&#34; : &#34;&#34;));</pre>
</details>
<p><b>Fix</b> : The patch introduces a new `cleanFileEnding` method that sanitizes the `IN_FILE_ENDING` and `OUT_FILE_ENDING` parameters. This method uses a regular expression to remove any characters that are not alphanumeric, underscore, hyphen, or a leading dot, preventing command injection.</p>
<p>
<a href="https://github.com/advisories/GHSA-3p24-9x7v-7789">Advisory</a> · <a href="https://github.com/NationalSecurityAgency/emissary/commit/1faf33f2494c0128f250d7d2e8f2da99bbd32ae8">Commit</a>
</p>
<hr>
<h3>GHSA-4f3f-g24h-fr8m</h3>
<p>
<code>HIGH 8.8</code> · 2026-04-13 · Python<br>
<code>keras</code> · Pattern: <code>DESERIALIZATION→RCE</code> · 3x across ecosystem
</p>
<p><b>Root cause</b> : The code did not properly sanitize input during deserialization, allowing an attacker to execute arbitrary code.</p>
<p><b>Impact</b> : An attacker could potentially execute arbitrary code on the server, leading to a complete compromise of the system.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Added `safe_mode` parameter and check in `from_config` method:
- Added: `effective_safe_mode = (safe_mode if safe_mode is not None else serialization_lib.in_safe_mode())`
- Added: `if effective_safe_mode is not False:`
- Added: `raise ValueError(...)`</pre>
</details>
<p><b>Fix</b> : The patch adds a `safe_mode` parameter that disallows deserializing `TFSMLayer` objects by default, preventing potential arbitrary code execution.</p>
<p>
<a href="https://github.com/advisories/GHSA-4f3f-g24h-fr8m">Advisory</a> · <a href="https://github.com/keras-team/keras/commit/b6773d3decaef1b05d8e794458e148cb362f163f">Commit</a>
</p>
<hr>
<h3>GHSA-jvff-x2qm-6286</h3>
<p>
<code>HIGH 8.8</code> · 2026-04-10 · JavaScript<br>
<code>mathjs</code> · Pattern: <code>UNCLASSIFIED</code> · 51x across ecosystem
</p>
<p><b>Root cause</b> : The code did not validate that the index parameter was an array, allowing attackers to manipulate object attributes improperly.</p>
<p><b>Impact</b> : An attacker could potentially modify or delete arbitrary properties of objects, leading to unauthorized data manipulation or loss.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before:
if (!Array.isArray(array)) { throw new Error(&#39;Array expected&#39;) }

After:
if (!Array.isArray(index)) {
  throw new Error(&#39;Array expected for index&#39;)
}</pre>
</details>
<p><b>Fix</b> : The patch ensures that the index parameter is always treated as an array, preventing improper modifications of object attributes.</p>
<p>
<a href="https://github.com/advisories/GHSA-jvff-x2qm-6286">Advisory</a> · <a href="https://github.com/josdejong/mathjs/commit/0aee2f61866e35ffa0aef915221cdf6b026ffdd4">Commit</a>
</p>
<hr>
<h3>GHSA-5gfj-64gh-mgmw</h3>
<p>
<code>HIGH 8.8</code> · 2026-04-08 · Python<br>
<code>agixt</code> · Pattern: <code>PATH_TRAVERSAL→FILE_READ</code> · 20x across ecosystem
</p>
<p><b>Root cause</b> : The `safe_join` function did not properly validate the resolved path to ensure it stayed within the agent&#39;s WORKING_DIRECTORY.</p>
<p><b>Impact</b> : An attacker could exploit this vulnerability to read or write files outside of the intended directory, potentially leading to unauthorized access or data corruption.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before:
new_path = os.path.normpath(
    os.path.join(self.WORKING_DIRECTORY, *paths.split(&#34;/&#34;))
)

After:
base = os.path.realpath(self.WORKING_DIRECTORY)
new_path = os.path.realpath(
    os.path.normpath(os.path.join(self.WORKING_DIRECTORY, *paths.split(&#34;/&#34;)))
)
if not (new_path.startswith(base + os.sep) or new_path == base):
    raise PermissionError(
        f&#34;Path traversal detected: refusing to access path outside workspace&#34;
    )</pre>
</details>
<p><b>Fix</b> : The patch uses `os.path.realpath` to resolve symlinks and relative paths, and then checks if the resolved path is within the agent&#39;s WORKING_DIRECTORY. If not, it raises a `PermissionError`.</p>
<p>
<a href="https://github.com/advisories/GHSA-5gfj-64gh-mgmw">Advisory</a> · <a href="https://github.com/Josh-XT/AGiXT/commit/2079ea5a88fa671a921bf0b5eba887a5a1b73d5f">Commit</a>
</p>
<hr>
<h3>GHSA-qxpc-96fq-wwmg</h3>
<p>
<code>HIGH 8.8</code> · 2026-04-07 · Java<br>
<code>org.apache.cassandra:cassandra-all</code> · Pattern: <code>PRIVILEGE_ESCALATION→ROLE</code> · 7x across ecosystem
</p>
<p><b>Root cause</b> : The patch fails to properly validate the user&#39;s permissions before allowing them to drop an identity, potentially escalating their privileges.</p>
<p><b>Impact</b> : An attacker could exploit this vulnerability to escalate their privileges within the Cassandra environment by dropping identities and assuming roles they are not authorized to.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before:
checkPermission(state, Permission.DROP, state.getUser().getPrimaryRole());

After:
String roleForIdentity = DatabaseDescriptor.getRoleManager().roleForIdentity(identity);
if (roleForIdentity == null)
{
    checkPermission(state, Permission.DROP, RoleResource.root());
}
else
{
    checkPermission(state, Permission.DROP, RoleResource.role(roleForIdentity));
}</pre>
</details>
<p><b>Fix</b> : The patch adds checks to ensure that only users with appropriate permissions can drop identities. It verifies that the user has permission to drop the target role before allowing the operation.</p>
<p>
<a href="https://github.com/advisories/GHSA-qxpc-96fq-wwmg">Advisory</a> · <a href="https://github.com/apache/cassandra/commit/b584a435970e5125e1def5148d943c39569dc7af">Commit</a>
</p>
<hr>
<h3>GHSA-855c-r2vq-c292</h3>
<p>
<code>HIGH 8.7</code> · 2026-04-16 · JavaScript<br>
<code>apostrophe</code> · Pattern: <code>UNSANITIZED_INPUT→XSS</code> · 19x across ecosystem
</p>
<p><b>Root cause</b> : Untrusted data in SEO fields was being embedded directly into a `&lt;script&gt;` tag without proper sanitization.</p>
<p><b>Impact</b> : An attacker could inject arbitrary HTML/JS, leading to potential session hijacking or other malicious activities.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">- // No changes before this point
+ module.exports = function safeJsonForScript(data) {
  return JSON.stringify(data, null, 2)
    .replace(/&lt;/g, &#39;\u003c&#39;)
    .replace(/ /g, &#39;\u2028&#39;)
    .replace(/ /g, &#39;\u2029&#39;);
};</pre>
</details>
<p><b>Fix</b> : The patch introduces a `safeJsonForScript` function that escapes critical characters to prevent XSS attacks by ensuring the JSON string is safe to embed in an HTML `&lt;script&gt;` tag.</p>
<p>
<a href="https://github.com/advisories/GHSA-855c-r2vq-c292">Advisory</a> · <a href="https://github.com/apostrophecms/apostrophe/commit/0e57dd07a56ae1ba1e3af646ba026db4d0ab5bb3">Commit</a>
</p>
<hr>
<h3>GHSA-9pr4-rf97-79qh</h3>
<p>
<code>HIGH 8.7</code> · 2026-04-13 · Go<br>
<code>github.com/enchant97/note-mark/backend</code> · Pattern: <code>UNSANITIZED_INPUT→XSS</code> · 19x across ecosystem
</p>
<p><b>Root cause</b> : The application allowed unrestricted upload of assets and served them with their original Content-Type, including &#39;text/html&#39; and &#39;image/svg+xml&#39;. This enabled an attacker to upload malicious HTML or SVG files containing JavaScript, which would then execute in the victim&#39;s browser when the asset was viewed.</p>
<p><b>Impact</b> : An attacker could execute arbitrary JavaScript in the context of the victim&#39;s browser, leading to session hijacking, defacement, or redirection to malicious sites.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">- ctx.SetHeader(&#34;Content-Type&#34;, info.MimeType)
+ if info.MimeType == &#34;&#34; || info.MimeType == &#34;text/html&#34; || info.MimeType == &#34;image/svg+xml&#34; {
+ 	ctx.SetHeader(&#34;Content-Type&#34;, &#34;application/octet-stream&#34;)
+ } else {
+ 	ctx.SetHeader(&#34;Content-Type&#34;, info.MimeType)</pre>
</details>
<p><b>Fix</b> : The patch introduces a check for &#39;text/html&#39; and &#39;image/svg+xml&#39; MIME types. If an uploaded asset matches these types or has an empty MIME type, it is now served with &#39;application/octet-stream&#39; and &#39;Content-Disposition: attachment&#39; to force a download instead of inline rendering, mitigating the XSS risk. It also adds &#39;X-Content-Type-Options: nosniff&#39;.</p>
<p>
<a href="https://github.com/advisories/GHSA-9pr4-rf97-79qh">Advisory</a> · <a href="https://github.com/enchant97/note-mark/commit/6bb62842ccb956870b9bf183629eba95e326e5e3">Commit</a>
</p>
<hr>
<h3>GHSA-c3h8-g69v-pjrg</h3>
<p>
<code>HIGH 8.6</code> · 2026-04-22 · JavaScript<br>
<code>i18next-http-middleware</code> · Pattern: <code>UNSANITIZED_INPUT→HEADER</code> · 3x across ecosystem
</p>
<p><b>Root cause</b> : The application failed to properly sanitize user-controlled input, specifically the &#39;Content-Language&#39; header and language/namespace identifiers. This allowed attackers to inject control characters into HTTP headers, leading to response splitting, and to use specially crafted strings (e.g., &#39;__proto__&#39;, &#39;..&#39;, &#39;/&#39;, &#39;\&#39;) to trigger prototype pollution, path traversal, or denial-of-service conditions when these values were used in internal operations or forwarded to backend connectors.</p>
<p><b>Impact</b> : An attacker could inject arbitrary HTTP headers, potentially leading to HTTP response splitting, cache poisoning, or cross-site scripting. They could also achieve prototype pollution to alter application behavior, perform path traversal to access or manipulate files, or cause a denial of service by triggering crashes or resource exhaustion.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/lib/index.js
+++ b/lib/index.js
@@ -69,7 +69,7 @@ export function handle (i18next, options = {}) {
       }
 
       if (lng &amp;&amp; options.getHeader(res, &#39;Content-Language&#39;) !== lng) {
-        options.setHeader(res, &#39;Content-Language&#39;, utils.escape(lng))
+        options.setHeader(res, &#39;Content-Language&#39;, utils.sanitizeHeaderValue(lng))
       }
 
       req.languages = i18next.services.languageUtils.toResolveHierarchy(lng)</pre>
</details>
<p><b>Fix</b> : The patch introduces several new utility functions: `isSafeIdentifier` to validate language codes and namespace identifiers against known dangerous patterns (e.g., prototype pollution keys, path separators, control characters), and `sanitizeHeaderValue` to strip control characters from values before they are written to HTTP headers. These sanitization functions are applied to user-supplied language and namespace inputs, and to the &#39;Content-Language&#39; header value.</p>
<p>
<a href="https://github.com/advisories/GHSA-c3h8-g69v-pjrg">Advisory</a> · <a href="https://github.com/i18next/i18next-http-middleware/commit/65301c194593d46a84623b64e5fde2f51d3550f6">Commit</a>
</p>
<hr>
<h3>GHSA-chqc-8p9q-pq6q</h3>
<p>
<code>HIGH 8.6</code> · 2026-04-08 · JavaScript<br>
<code>basic-ftp</code> · Pattern: <code>UNSANITIZED_INPUT→COMMAND</code> · 22x across ecosystem
</p>
<p><b>Root cause</b> : The code did not sanitize input for control characters, allowing attackers to inject CRLF sequences that could manipulate FTP commands.</p>
<p><b>Impact</b> : An attacker could use this vulnerability to execute arbitrary FTP commands on the server, potentially leading to unauthorized access or data manipulation.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before:
if (!path.startsWith(&#34; &#34;)) {
    return path
}
After:
if (/[\r\n\0]/.test(path)) {
    throw new Error(&#34;Invalid path: Contains control characters&#34;);
}</pre>
</details>
<p><b>Fix</b> : The patch adds a regex check to reject paths containing control characters, preventing command injection attacks.</p>
<p>
<a href="https://github.com/advisories/GHSA-chqc-8p9q-pq6q">Advisory</a> · <a href="https://github.com/patrickjuchli/basic-ftp/commit/2ecc8e2c500c5234115f06fd1dbde1aa03d70f4b">Commit</a>
</p>
<hr>
<h3>GHSA-4ggg-h7ph-26qr</h3>
<p>
<code>HIGH 8.5</code> · 2026-04-08 · JavaScript<br>
<code>n8n-mcp</code> · Pattern: <code>SSRF→INTERNAL_ACCESS</code> · 35x across ecosystem
</p>
<p><b>Root cause</b> : The code did not properly sanitize the `instance-URL` header, allowing attackers to perform SSRF attacks.</p>
<p><b>Impact</b> : An attacker could use this vulnerability to access internal resources or perform actions on behalf of other users within the same network.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">- this.baseUrl = baseUrl;
+ let normalizedBase: string;
try {
  const parsed = new URL(baseUrl);
  parsed.hash = &#39;&#39;;
  parsed.username = &#39;&#39;;
  parsed.password = &#39;&#39;;
  normalizedBase = parsed.toString().replace(//$/, &#39;&#39;);
} catch {
  // Unparseable input falls through to raw; downstream axios call will
  // fail cleanly. Preserves backward compat for tests that pass
  // placeholder strings.
  normalizedBase = baseUrl;
}
this.baseUrl = normalizedBase;</pre>
</details>
<p><b>Fix</b> : The patch normalizes the `baseUrl` by removing any embedded credentials and ensuring it does not end with a trailing slash, enhancing defense-in-depth against SSRF attacks.</p>
<p>
<a href="https://github.com/advisories/GHSA-4ggg-h7ph-26qr">Advisory</a> · <a href="https://github.com/czlonkowski/n8n-mcp/commit/d9d847f230923d96e0857ccecf3a4dedcc9b0096">Commit</a>
</p>
<hr>
<h3>GHSA-m6rx-7pvw-2f73</h3>
<p>
<code>HIGH 8.4</code> · 2026-04-21 · JavaScript<br>
<code>@gitlawb/openclaude</code> · Pattern: <code>UNCLASSIFIED</code> · 51x across ecosystem
</p>
<p><b>Root cause</b> : The vulnerability existed because the sandbox permission check logic had an early-exit flaw. It only explicitly handled &#39;passthrough&#39; behavior, allowing &#39;deny&#39; or &#39;ask&#39; behaviors to implicitly bypass the intended security checks and proceed as if permission was granted.</p>
<p><b>Impact</b> : An attacker could bypass the sandbox restrictions, potentially leading to unauthorized file system access (path traversal) or execution of arbitrary commands outside the intended secure environment.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/src/tools/BashTool/bashPermissions.ts
+++ b/src/tools/BashTool/bashPermissions.ts
@@ -1814,7 +1814,10 @@ export async function bashToolHasPermission(
       input,
       appState.toolPermissionContext,
     )
-    if (sandboxAutoAllowResult.behavior !== &#39;passthrough&#39;) {
+    if (
+      sandboxAutoAllowResult.behavior === &#39;deny&#39; ||
+      sandboxAutoAllowResult.behavior === &#39;ask&#39;
+    ) {
       return sandboxAutoAllowResult
     }
   }</pre>
</details>
<p><b>Fix</b> : The patch modifies the conditional logic to explicitly check for &#39;deny&#39; or &#39;ask&#39; behaviors from the sandbox auto-allow result. If either of these behaviors is detected, the function now correctly returns the sandbox result, preventing the bypass.</p>
<p>
<a href="https://github.com/advisories/GHSA-m6rx-7pvw-2f73">Advisory</a> · <a href="https://github.com/Gitlawb/openclaude/commit/7002cb302b78ea2a19da3f26226de24e2903fa1d">Commit</a>
</p>
<hr>
<h3>GHSA-vvfw-4m39-fjqf</h3>
<p>
<code>HIGH 8.3</code> · 2026-04-14 · PHP<br>
<code>wwbn/avideo</code> · Pattern: <code>CSRF→STATE_CHANGE</code> · 4x across ecosystem
</p>
<p><b>Root cause</b> : The application&#39;s configuration update endpoint (configurationUpdate.json.php) lacked proper CSRF protection. This allowed an attacker to craft a malicious request that, when triggered by an authenticated administrator, would modify the site&#39;s configuration without the administrator&#39;s explicit consent.</p>
<p><b>Impact</b> : An attacker could trick an administrator into changing critical site configurations, including the encoder URL and SMTP credentials, potentially leading to further compromise like arbitrary code execution or email spoofing.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/objects/configurationUpdate.json.php
+++ b/objects/configurationUpdate.json.php
@@ -15,6 +15,8 @@
 require_once $global[&#39;systemRootPath&#39;] . &#39;objects/configuration.php&#39;;
 require_once $global[&#39;systemRootPath&#39;] . &#39;objects/functions.php&#39;;
 
+forbidIfIsUntrustedRequest(&#39;configurationUpdate&#39;);
+
 _error_log(&#34;save configuration {$_POST[&#39;language&#39;]}&#34;);</pre>
</details>
<p><b>Fix</b> : The patch introduces a call to `forbidIfIsUntrustedRequest(&#39;configurationUpdate&#39;);` at the beginning of the `configurationUpdate.json.php` script. This function likely implements a mechanism to verify the legitimacy of the request, such as checking for a valid CSRF token, thereby preventing unauthorized state changes.</p>
<p>
<a href="https://github.com/advisories/GHSA-vvfw-4m39-fjqf">Advisory</a> · <a href="https://github.com/WWBN/AVideo/commit/f9492f5e6123dff0292d5bb3164fde7665dc36b4">Commit</a>
</p>
<hr>
<h3>GHSA-5835-4gvc-32pc</h3>
<p>
<code>HIGH 8.2</code> · 2026-04-13 · Go<br>
<code>github.com/foxcpp/maddy</code> · Pattern: <code>UNSANITIZED_INPUT→LDAP</code> · 2x across ecosystem
</p>
<p><b>Root cause</b> : The username was not properly sanitized before being used in an LDAP search filter.</p>
<p><b>Impact</b> : An attacker could inject malicious LDAP filters to bypass authentication or retrieve sensitive data.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before:
- strings.ReplaceAll(a.filterTemplate, &#34;{username}&#34;, username),
After:
+ strings.ReplaceAll(a.filterTemplate, &#34;{username}&#34;, ldap.EscapeFilter(username)),

Before:
- userDN = strings.ReplaceAll(a.dnTemplate, &#34;{username}&#34;, username),
After:
+ userDN = strings.ReplaceAll(a.dnTemplate, &#34;{username}&#34;, ldap.EscapeDN(username))</pre>
</details>
<p><b>Fix</b> : The patch sanitizes the username using `ldap.EscapeFilter` and `ldap.EscapeDN` functions, preventing injection attacks.</p>
<p>
<a href="https://github.com/advisories/GHSA-5835-4gvc-32pc">Advisory</a> · <a href="https://github.com/foxcpp/maddy/commit/6a06337eb41fa87a35697366bcb71c3c962c44ba">Commit</a>
</p>
<hr>
<h3>GHSA-6v7q-wjvx-w8wg</h3>
<p>
<code>HIGH 8.2</code> · 2026-04-10 · JavaScript<br>
<code>basic-ftp</code> · Pattern: <code>UNSANITIZED_INPUT→COMMAND</code> · 22x across ecosystem
</p>
<p><b>Root cause</b> : The code did not properly sanitize input for FTP commands, allowing control characters to be injected.</p>
<p><b>Impact</b> : An attacker could execute arbitrary FTP commands using credentials and MKD commands due to the lack of proper input validation.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before:
-        // Reject CRLF injection attempts
-        if (/[
\ ]/.test(path)) {
-            throw new Error(&#34;Invalid path: Contains control characters&#34;);
-        }
After:
+        // Reject control character injection attempts.
+        if (/[
\u0000]/.test(command)) {
+            throw new Error(`Invalid command: Contains control characters. (${command})`);
+        }</pre>
</details>
<p><b>Fix</b> : The patch added a regex check to reject any command containing control characters, preventing injection attacks.</p>
<p>
<a href="https://github.com/advisories/GHSA-6v7q-wjvx-w8wg">Advisory</a> · <a href="https://github.com/patrickjuchli/basic-ftp/commit/20327d35126e57e5fdbaae79a4b65222fbadc53c">Commit</a>
</p>
<hr>
<h3>GHSA-75hx-xj24-mqrw</h3>
<p>
<code>HIGH 8.2</code> · 2026-04-10 · JavaScript<br>
<code>n8n-mcp</code> · Pattern: <code>MISSING_AUTH→ENDPOINT</code> · 12x across ecosystem
</p>
<p><b>Root cause</b> : The code did not handle authentication errors securely, potentially revealing sensitive information in error messages.</p>
<p><b>Impact</b> : An attacker could exploit this vulnerability to gain insights into the system&#39;s internal workings and potentially identify valid usernames or other sensitive data.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before:
-    next();

After:
+    const authLimiter = rateLimit({ ... });
+    app.use(authLimiter);
+    // Root endpoint with API information
+    app.get(&#39;/&#39;, (req, res) =&gt; { ... };</pre>
</details>
<p><b>Fix</b> : The patch introduces rate limiting for authentication endpoints to prevent brute force attacks and DoS. It also enhances error handling to avoid revealing sensitive information in error messages.</p>
<p>
<a href="https://github.com/advisories/GHSA-75hx-xj24-mqrw">Advisory</a> · <a href="https://github.com/czlonkowski/n8n-mcp/commit/ca9d4b3df6419b8338983be98f7940400f78bde3">Commit</a>
</p>
<hr>
<h3>GHSA-wgx6-g857-jjf7</h3>
<p>
<code>HIGH 8.1</code> · 2026-04-22 · Ruby<br>
<code>openc3</code> · Pattern: <code>PRIVILEGE_ESCALATION→ROLE</code> · 7x across ecosystem
</p>
<p><b>Root cause</b> : The `verify_no_service` method, intended to verify either a password or a session token, had a flaw where it would prioritize checking for a session token even when explicitly told to only check for a password. This meant that if an attacker had a valid session token, they could use it in place of a password to perform actions that should require the actual user&#39;s password, such as resetting the password.</p>
<p><b>Impact</b> : An attacker with a hijacked session token could bypass the password verification step and reset the user&#39;s password, gaining persistent access to the account. This effectively allows session hijacking to lead to full account takeover.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">-    def self.verify_no_service(token, no_password: true)
+    def self.verify_no_service(token, mode: :token)
...
-      unless no_password
-        return true if @@pw_hash_cache and (time - @@pw_hash_cache_time) &lt; PW_HASH_CACHE_TIMEOUT and Argon2::Password.verify_password(token, @@pw_hash_cache)
+      unless mode == :password
+        return true if @@session_cache and (time - @@session_cache_time) &lt; SESSION_CACHE_TIMEOUT and @@session_cache[token]</pre>
</details>
<p><b>Fix</b> : The patch refactors the `verify_no_service` method to use a `mode` parameter (password, token, or any) instead of a boolean `no_password`. This ensures that when password verification is explicitly requested, the method strictly checks the provided input against the stored password hash and does not fall back to checking session tokens.</p>
<p>
<a href="https://github.com/advisories/GHSA-wgx6-g857-jjf7">Advisory</a> · <a href="https://github.com/OpenC3/cosmos/commit/2e623714e3426d5ae81b6f8239d4a2a6937ef776">Commit</a>
</p>
<hr>
<h3>GHSA-ccq9-r5cw-5hwq</h3>
<p>
<code>HIGH 8.1</code> · 2026-04-14 · PHP<br>
<code>wwbn/avideo</code> · Pattern: <code>CORS_MISCONFIGURATION→ORIGIN</code> · 3x across ecosystem
</p>
<p><b>Root cause</b> : The application&#39;s CORS policy, specifically in the `allowOrigin` function when `allowAll` was true, would reflect the `Origin` header from the request and set `Access-Control-Allow-Credentials: true`. This was intended for public resources but was applied to sensitive API endpoints, allowing any origin to make credentialed requests.</p>
<p><b>Impact</b> : An attacker could craft a malicious webpage to make cross-origin requests to sensitive API endpoints on the vulnerable AVideo instance. Since `Access-Control-Allow-Credentials: true` was set, the victim&#39;s browser would include session cookies, enabling the attacker to read session-authenticated API responses and potentially achieve account takeover.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">-        if (!empty($requestOrigin)) {
-            header(&#39;Access-Control-Allow-Origin: &#39; . $requestOrigin);
-            header(&#39;Access-Control-Allow-Credentials: true&#39;);
-        } else {
-            header(&#39;Access-Control-Allow-Origin: *&#39;);
+        if (!empty($requestOrigin) &amp;&amp; !empty($siteOriginForAllowAll) &amp;&amp; $requestOrigin === $siteOriginForAllowAll) {
+            header(&#39;Access-Control-Allow-Origin: &#39; . $requestOrigin);
+            header(&#39;Access-Control-Allow-Credentials: true&#39;);
+        } else {
+            header(&#39;Access-Control-Allow-Origin: *&#39;);</pre>
</details>
<p><b>Fix</b> : The patch modifies the `allowOrigin` function to explicitly check if the `requestOrigin` matches the `siteOriginForAllowAll` when `allowAll` is true. If they match, the origin is reflected with credentials. Otherwise, a wildcard origin (`*`) is used without credentials, preventing third-party origins from making credentialed requests.</p>
<p>
<a href="https://github.com/advisories/GHSA-ccq9-r5cw-5hwq">Advisory</a> · <a href="https://github.com/WWBN/AVideo/commit/caf705f38eae0ccfac4c3af1587781355d24495e">Commit</a>
</p>
<hr>
<h3>GHSA-jcxm-m3jx-f287</h3>
<p>
<code>HIGH 8.1</code> · 2026-04-13 · JavaScript<br>
<code>simple-git</code> · Pattern: <code>UNSANITIZED_INPUT→COMMAND</code> · 22x across ecosystem
</p>
<p><b>Root cause</b> : The code did not properly sanitize input for the &#39;clone&#39; operation, allowing attackers to bypass intended restrictions.</p>
<p><b>Impact</b> : An attacker could execute arbitrary commands on the system running the vulnerable application.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Added:
const CLONE_OPTIONS = /^\ *(-|--|--no-)[\\\dlsqvnobucj]+/;

function isCloneSwitch(char: string, arg: string | unknown) {
   return Boolean(typeof arg === &#39;string&#39; &amp;&amp; CLONE_OPTIONS.test(arg) &amp;&amp; arg.includes(char));
}

Changed:
if (method === &#39;clone&#39; &amp;&amp; isCloneSwitch(&#39;u&#39;, arg)) {</pre>
</details>
<p><b>Fix</b> : The patch introduces a new function `isCloneSwitch` to validate command-line options for the &#39;clone&#39; operation, ensuring only safe options are accepted.</p>
<p>
<a href="https://github.com/advisories/GHSA-jcxm-m3jx-f287">Advisory</a> · <a href="https://github.com/steveukx/git-js/commit/1effd8e5012a5da05a9776512fac3e39b11f2d2d">Commit</a>
</p>
<hr>
<h3>GHSA-hc36-c89j-5f4j</h3>
<p>
<code>HIGH 8.1</code> · 2026-04-09 · Ruby<br>
<code>bsv-wallet</code> · Pattern: <code>MISSING_VERIFICATION→SIGNATURE</code> · 7x across ecosystem
</p>
<p><b>Root cause</b> : The code did not verify the certifier signatures before persisting them.</p>
<p><b>Impact</b> : An attacker could potentially bypass security checks by providing unverified signatures, leading to unauthorized access or manipulation of data.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before:
-      REJECTED_STATUSES = %w[REJECTED DOUBLE_SPEND_ATTEMPTED].freeze
After:
+      REJECTED_STATUSES = %w[
+        REJECTED
+        DOUBLE_SPEND_ATTEMPTED
+        INVALID
+        MALFORMED
+        MINED_IN_STALE_BLOCK
+      ].freeze</pre>
</details>
<p><b>Fix</b> : The patch adds verification for certifier signatures, ensuring that only valid signatures are persisted.</p>
<p>
<a href="https://github.com/advisories/GHSA-hc36-c89j-5f4j">Advisory</a> · <a href="https://github.com/sgbett/bsv-ruby-sdk/commit/4992e8a265fd914a7eeb0405c69d1ff0122a84cc">Commit</a>
</p>
<hr>
<h3>GHSA-fpjq-c37h-cqcv</h3>
<p>
<code>HIGH 7.7</code> · 2026-04-24 · Go<br>
<code>github.com/kyverno/kyverno</code> · Pattern: <code>NULL_DEREF→CRASH</code> · 3x across ecosystem
</p>
<p><b>Root cause</b> : The vulnerability existed because the code directly type-asserted an interface value to a string without checking if the assertion would succeed. If the underlying value was not a string, this would cause a panic (runtime error) in the Kyverno controller.</p>
<p><b>Impact</b> : An attacker could craft a malicious policy that, when processed by the Kyverno controller, would cause the controller to crash and enter a restart loop, leading to a denial of service for the Kyverno admission controller.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">-	patcher := NewPatcher(fe[&#34;patchStrategicMerge&#34;], fe[&#34;patchesJson6902&#34;].(string))
+	jsonPatch, _ := fe[&#34;patchesJson6902&#34;].(string)
+	patcher := NewPatcher(fe[&#34;patchStrategicMerge&#34;], jsonPatch)</pre>
</details>
<p><b>Fix</b> : The patch introduces a safe type assertion for &#39;patchesJson6902&#39;. It now explicitly checks if the assertion to a string type is successful. If it fails, the &#39;jsonPatch&#39; variable will be an empty string, preventing the panic.</p>
<p>
<a href="https://github.com/advisories/GHSA-fpjq-c37h-cqcv">Advisory</a> · <a href="https://github.com/kyverno/kyverno/commit/76c8fdbe87328722e099e1fd44c3f21c9f7809cb">Commit</a>
</p>
<hr>
<h3>GHSA-hv99-mxm5-q397</h3>
<p>
<code>HIGH 7.7</code> · 2026-04-16 · Python<br>
<code>weblate</code> · Pattern: <code>PATH_TRAVERSAL→FILE_READ</code> · 20x across ecosystem
</p>
<p><b>Root cause</b> : The code did not properly sanitize input when constructing file paths, allowing attackers to read arbitrary files via symlinks.</p>
<p><b>Impact</b> : An attacker could potentially read sensitive files on the server, leading to data exposure or further exploitation.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before:
-                fullname = os.path.join(translation.component.full_path, filename)
After:
+                try:
+                    fullname = getter()
+                except ValidationError:
+                    continue
+                if fullname and os.path.exists(fullname):</pre>
</details>
<p><b>Fix</b> : The patch introduced a validation step to ensure that file paths are correctly constructed and sanitized before being accessed, preventing symlink attacks.</p>
<p>
<a href="https://github.com/advisories/GHSA-hv99-mxm5-q397">Advisory</a> · <a href="https://github.com/WeblateOrg/weblate/commit/5db3a2a2e047ecaab627a8731cd744a30b2f51d3">Commit</a>
</p>
<hr>
<h3>GHSA-2943-crp8-38xx</h3>
<p>
<code>HIGH 7.7</code> · 2026-04-10 · Go<br>
<code>github.com/patrickhener/goshs</code> · Pattern: <code>PATH_TRAVERSAL→FILE_WRITE</code> · 13x across ecosystem
</p>
<p><b>Root cause</b> : The code directly used the target path from the SFTP request without sanitization, allowing attackers to write files in arbitrary locations on the server.</p>
<p><b>Impact</b> : An attacker could use this vulnerability to overwrite or create files on the server, potentially leading to data loss, unauthorized access, or further exploitation of the system.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before:
err := os.Rename(fullPath, r.Target)

After:
targetPath, err := sanitizePath(r.Target, root)
if err != nil {
	logger.LogSFTPRequestBlocked(r, ip, err)
	sftpServer.HandleWebhookSend(&#34;sftp&#34;, r, ip, true)
	return err
}
err = os.Rename(fullPath, targetPath)</pre>
</details>
<p><b>Fix</b> : The patch introduced a path sanitization function `sanitizePath` to ensure that only valid paths are used for file operations, preventing directory traversal attacks.</p>
<p>
<a href="https://github.com/advisories/GHSA-2943-crp8-38xx">Advisory</a> · <a href="https://github.com/patrickhener/goshs/commit/141c188ce270ffbec087844a50e5e695b7da7744">Commit</a>
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
             Map to closed taxonomy of 43 normalized pattern IDs
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
<tr><td>Total advisories</td><td>321</td></tr>
<tr><td>Unique patterns</td><td>43</td></tr>
<tr><td>Pending</td><td>0</td></tr>
<tr><td>Last updated</td><td>2026-04-26</td></tr>
</table>
</details>
<hr>
<sub><a href="https://christbowel.com">christbowel.com</a></sub>
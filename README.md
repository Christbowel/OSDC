<div align="center">
<h1>🎣 Open Source Daily Catch</h1>
<p><b>Automated Patch Intelligence for Security Engineers</b></p>
<p>
<a href="https://github.com/christbowel/osdc/actions/workflows/daily.yml"><img src="https://github.com/christbowel/osdc/actions/workflows/daily.yml/badge.svg" alt="Analysis"></a>
<a href="https://github.com/christbowel/osdc/actions/workflows/render.yml"><img src="https://github.com/christbowel/osdc/actions/workflows/render.yml/badge.svg" alt="Render"></a>
<a href="https://christbowel.github.io/OSDC"><img src="https://img.shields.io/badge/advisories-381-blue" alt="Advisories"></a>
<a href="https://christbowel.github.io/OSDC"><img src="https://img.shields.io/badge/patterns-45-purple" alt="Patterns"></a>
</p>
<p>
<a href="https://christbowel.github.io/OSDC">Live dashboard</a> · <a href="#how-it-works">How it works</a>
</p>
</div>
<hr>
<h3>GHSA-246w-jgmq-88fg</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-04-22 · Go<br>
<code>github.com/jkroepke/openvpn-auth-oauth2</code> · Pattern: <code>MISSING_AUTH→ENDPOINT</code> · 18x across ecosystem
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
<code>wwbn/avideo</code> · Pattern: <code>UNSANITIZED_INPUT→XSS</code> · 20x across ecosystem
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
<code>github.com/daptin/daptin</code> · Pattern: <code>PATH_TRAVERSAL→FILE_WRITE</code> · 18x across ecosystem
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
<code>axios</code> · Pattern: <code>UNSANITIZED_INPUT→HEADER</code> · 4x across ecosystem
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
<h3>GHSA-8x35-hph8-37hq</h3>
<p>
<code>CRITICAL 9.8</code> · 2026-04-24 · JavaScript<br>
<code>electerm</code> · Pattern: <code>UNSANITIZED_INPUT→COMMAND</code> · 25x across ecosystem
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
<code>github.com/woven-planet/go-zserio</code> · Pattern: <code>DOS→RESOURCE_EXHAUSTION</code> · 18x across ecosystem
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
<code>praisonai</code> · Pattern: <code>UNSANITIZED_INPUT→COMMAND</code> · 25x across ecosystem
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
<code>Microsoft.Native.Quic.MsQuic.OpenSSL</code> · Pattern: <code>UNCLASSIFIED</code> · 54x across ecosystem
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
<code>upsonic</code> · Pattern: <code>UNCLASSIFIED</code> · 54x across ecosystem
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
<code>changedetection.io</code> · Pattern: <code>MISSING_AUTH→ENDPOINT</code> · 18x across ecosystem
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
<code>openc3</code> · Pattern: <code>UNSANITIZED_INPUT→SQL</code> · 8x across ecosystem
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
<code>lollms</code> · Pattern: <code>UNSANITIZED_INPUT→XSS</code> · 20x across ecosystem
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
<code>getgrav/grav</code> · Pattern: <code>PRIVILEGE_ESCALATION→ROLE</code> · 14x across ecosystem
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
<code>nabeel/phpvms</code> · Pattern: <code>MISSING_AUTH→ENDPOINT</code> · 18x across ecosystem
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
<code>excel-mcp-server</code> · Pattern: <code>PATH_TRAVERSAL→FILE_READ</code> · 23x across ecosystem
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
<code>@delmaredigital/payload-puck</code> · Pattern: <code>MISSING_AUTH→ENDPOINT</code> · 18x across ecosystem
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
<h3>GHSA-w48r-jppp-rcfw</h3>
<p>
<code>CRITICAL 9.1</code> · 2026-05-05 · PHP<br>
<code>getgrav/grav</code> · Pattern: <code>PATH_TRAVERSAL→FILE_WRITE</code> · 18x across ecosystem
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
<code>org.openmrs.api:openmrs-api</code> · Pattern: <code>UNSANITIZED_INPUT→TEMPLATE</code> · 1x across ecosystem
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
<code>github.com/go-pkgz/auth/v2</code> · Pattern: <code>PRIVILEGE_ESCALATION→ROLE</code> · 14x across ecosystem
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
<code>sentry</code> · Pattern: <code>MISSING_AUTH→ENDPOINT</code> · 18x across ecosystem
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
<code>gramps-webapi</code> · Pattern: <code>PATH_TRAVERSAL→FILE_WRITE</code> · 18x across ecosystem
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
<code>com.arcadedb:arcadedb-server</code> · Pattern: <code>MISSING_AUTHZ→RESOURCE</code> · 25x across ecosystem
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
<h3>GHSA-2g9v-7mr5-fgjg</h3>
<p>
<code>CRITICAL 0.0</code> · 2026-05-05 · Go<br>
<code>github.com/l3montree-dev/devguard</code> · Pattern: <code>MISSING_AUTH→ENDPOINT</code> · 18x across ecosystem
</p>
<p><b>Root cause</b> : The application allowed an unauthenticated user to assert an arbitrary identity and gain administrative privileges by simply setting the `X-Admin-Token` HTTP header. This header was checked before any other authentication mechanisms, effectively bypassing all security controls.</p>
<p><b>Impact</b> : An attacker could gain full administrative access to the application without any prior authentication, leading to complete compromise of the system and data.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/middlewares/session_middleware.go
+++ b/middlewares/session_middleware.go
@@ -61,8 +61,6 @@ func SessionMiddleware(oryAPIClient shared.PublicClient, verifier shared.Verifie
 			var scopes string
 			var err error
 
-			adminTokenHeader := ctx.Request().Header.Get(&#34;X-Admin-Token&#34;)
-
 			if oryKratosSessionCookie != nil {
 				userID, err = cookieAuth(ctx.Request().Context(), oryAPIClient, oryKratosSessionCookie.String())
 				if err != nil {
@@ -77,10 +75,6 @@ func SessionMiddleware(oryAPIClient shared.PublicClient, verifier shared.Verifie
 				scopesArray := strings.Fields(scopes)
 				ctx.Set(&#34;session&#34;, accesscontrol.NewSession(userID, scopesArray))
 				return next(ctx)
-			} else if adminTokenHeader != &#34;&#34; {
-				slog.Warn(&#34;admin token header is set, using it to create session&#34;)
-				ctx.Set(&#34;session&#34;, accesscontrol.NewSession(adminTokenHeader, []string{}))
-				return next(ctx)
 			} else {
 				userID, scopes, err = verifier.VerifyRequestSignature(ctx.Request().Context(), ctx.Request())
 				if err != nil {</pre>
</details>
<p><b>Fix</b> : The patch removes all code paths that checked for and processed the `X-Admin-Token` header. This eliminates the ability for unauthenticated users to assert administrative identities via this header, enforcing proper authentication flows.</p>
<p>
<a href="https://github.com/advisories/GHSA-2g9v-7mr5-fgjg">Advisory</a> · <a href="https://github.com/l3montree-dev/devguard/commit/6f38310bf93b2a63df3055038f4da82b1f4e6d9a">Commit</a>
</p>
<hr>
<h3>GHSA-vj3m-2g9h-vm4p</h3>
<p>
<code>CRITICAL 0.0</code> · 2026-05-05 · PHP<br>
<code>getgrav/grav</code> · Pattern: <code>UNCLASSIFIED</code> · 54x across ecosystem
</p>
<p><b>Root cause</b> : The system was vulnerable to multiple issues: Zip Slip due to improper validation of archive entry names during extraction, XSS due to insufficient sanitization of user-controlled attribute names in media objects and a weak XSS detection regex, and XXE due to parsing untrusted SVG files without disabling external entity loading.</p>
<p><b>Impact</b> : An attacker could achieve arbitrary file write (Zip Slip), inject malicious scripts (XSS), or read local files and potentially perform server-side requests (XXE). These could lead to remote code execution, data theft, or website defacement.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Zip Slip:
-            Folder::create($destination);
+            for ($i = 0; $i &lt; $numFiles; $i++) {
+                $entryName = (string) $zip-&gt;getNameIndex($i);
+                if (!self::isSafeArchiveEntry($entryName)) {
+                    self::$error = self::ZIP_EXTRACT_ERROR;
+                    $zip-&gt;close();
+                    return false;
+                }
+            }
+            Folder::create($destination);
XSS (attribute):
-        if (!empty($attribute)) {
-            $this-&gt;attributes[$attribute] = $value;
+        if (empty($attribute) || !is_string($attribute)) {
+            return $this;
+        }
+        if (!self::isSafeAttributeName($attribute)) {
+            return $this;
+        }
+        $this-&gt;attributes[$attribute] = $value;
XSS (regex):
-            &#39;on_events&#39; =&gt; &#39;#(&lt;[^&gt;]+[\s\x00-\x20\&#34;\&#39;\/])(on\s*[a-z]+|xmlns)\s*=[&#34;|\&#39;&#34;]?.*[&#34;|\&#39;&#34;]?&gt;#iUu&#39;,
+            &#39;on_events&#39; =&gt; &#39;#&lt;[^&gt;]*?[\s\x00-\x20\&#34;\&#39;\/](on\s*[a-z]+|xmlns)\s*=#iu&#39;,
XXE:
-        $xml = simplexml_load_string(file_get_contents($path));
+        $svg = (string) file_get_contents($path);
+        $svg = preg_replace(&#39;/&lt;!DOCTYPE\b[^&gt;]*(?:\\[[^\\]]*\\])?[^&gt;]*&gt;/is&#39;, &#39;&#39;, $svg) ?? $svg;
+        $svg = preg_replace(&#39;/&lt;!ENTIT</pre>
</details>
<p><b>Fix</b> : The patch introduces `isSafeArchiveEntry` to validate ZIP file entry names, preventing path traversal. It also adds `isSafeAttributeName` to strictly filter attribute names for media objects, and updates the XSS detection regex to be more robust. Additionally, it strips DOCTYPE/ENTITY declarations and uses `LIBXML_NONET` when parsing SVGs to prevent XXE.</p>
<p>
<a href="https://github.com/advisories/GHSA-vj3m-2g9h-vm4p">Advisory</a> · <a href="https://github.com/getgrav/grav/commit/5a12f9be8314682c8713e569e330f11805d0a663">Commit</a>
</p>
<hr>
<h3>GHSA-6g38-8j4p-j3pr</h3>
<p>
<code>CRITICAL 0.0</code> · 2026-04-18 · Go<br>
<code>github.com/nhost/nhost</code> · Pattern: <code>IDOR→DATA_ACCESS</code> · 6x across ecosystem
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
<code>openclaw</code> · Pattern: <code>MISSING_AUTH→ENDPOINT</code> · 18x across ecosystem
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
<code>github.com/patrickhener/goshs</code> · Pattern: <code>MISSING_AUTHZ→RESOURCE</code> · 25x across ecosystem
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
<code>axios</code> · Pattern: <code>SSRF→INTERNAL_ACCESS</code> · 41x across ecosystem
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
<code>marimo</code> · Pattern: <code>MISSING_AUTH→ENDPOINT</code> · 18x across ecosystem
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
<code>org.openidentityplatform.openam:openam</code> · Pattern: <code>DESERIALIZATION→RCE</code> · 5x across ecosystem
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
<h3>GHSA-r945-h4vm-h736</h3>
<p>
<code>HIGH 8.8</code> · 2026-05-05 · PHP<br>
<code>getgrav/grav-plugin-api</code> · Pattern: <code>PRIVILEGE_ESCALATION→ROLE</code> · 14x across ecosystem
</p>
<p><b>Root cause</b> : The API&#39;s user update endpoint allowed users to modify their own &#39;access&#39; field, which controls permissions. While a check existed to prevent unauthorized users from updating *other* users, it did not adequately restrict the fields a user could modify when updating their *own* profile. This oversight meant a user with basic API access could grant themselves &#39;api.super&#39; or &#39;admin.super&#39; privileges.</p>
<p><b>Impact</b> : An attacker with a low-privileged API access token could elevate their account to a Super Admin, gaining full control over the Grav instance, including data manipulation, configuration changes, and potentially remote code execution.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/classes/Api/Controllers/UsersController.php
+++ b/classes/Api/Controllers/UsersController.php
@@ -211,8 +213,23 @@ public function update(ServerRequestInterface $request): ResponseInterface
             throw new ValidationException(&#39;Request body must contain fields to update.&#39;);
         }
 
-        // Partial update - only update provided fields
-        $allowedFields = [&#39;email&#39;, &#39;fullname&#39;, &#39;title&#39;, &#39;state&#39;, &#39;language&#39;, &#39;content_editor&#39;, &#39;access&#39;, &#39;twofa_enabled&#39;];
+        $selfFields  = [&#39;email&#39;, &#39;fullname&#39;, &#39;title&#39;, &#39;language&#39;, &#39;content_editor&#39;, &#39;twofa_enabled&#39;];
+        $adminFields = [&#39;state&#39;, &#39;access&#39;];
+
+        if (!$canManageUsers) {
+            foreach ($adminFields as $field) {
+                if (array_key_exists($field, $body)) {
+                    throw new ForbiddenException(
+                        &#34;Modifying &#39;{$field}&#39; requires the &#39;api.users.write&#39; permission.&#34;
+                    );
+                }
+            }
+        }
+
+        $allowedFields = $canManageUsers ? array_merge($selfFields, $adminFields) : $selfFields;
         foreach ($allowedFields as $field) {
             if (array_key_exists($field, $body)) {
                 $user-&gt;set($field, $body[$field]);</pre>
</details>
<p><b>Fix</b> : The patch introduces a distinction between &#39;self-editable&#39; fields and &#39;admin-only&#39; fields. Users can now only modify privilege-sensitive fields like &#39;state&#39; and &#39;access&#39; if they possess the &#39;api.users.write&#39; permission or are a Super Admin. Attempts to modify these fields without proper authorization are now explicitly blocked.</p>
<p>
<a href="https://github.com/advisories/GHSA-r945-h4vm-h736">Advisory</a> · <a href="https://github.com/getgrav/grav-plugin-api/commit/26f529c7d438c73343e82311fb095caeaf1a6116">Commit</a>
</p>
<hr>
<h3>GHSA-xhw7-j96h-c3g5</h3>
<p>
<code>HIGH 8.8</code> · 2026-05-05 · C#<br>
<code>YAFNET.Core</code> · Pattern: <code>MISSING_AUTH→ENDPOINT</code> · 18x across ecosystem
</p>
<p><b>Root cause</b> : The `PageSecurityCheckAttribute` was removed from the `ForumPage` base class, which meant that the security checks previously performed by this attribute were no longer automatically applied to pages inheriting from `ForumPage`. The logic for checking admin page access was moved into an `OnPageHandlerExecutionAsync` override, but the critical check for `BoardContext.Current.IsAdmin` was not sufficient on its own to prevent unauthorized access to specific admin functionalities like `/Admin/RunSql` without proper `AdminPageUserAccess` verification.</p>
<p><b>Impact</b> : An attacker could bypass authorization checks for admin pages, specifically gaining access to the `/Admin/RunSql` endpoint. This allowed for blind SQL execution, potentially leading to data exfiltration, modification, or other severe database compromises.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/yafsrc/YAFNET.Core/BasePages/ForumPage.cs
+++ b/yafsrc/YAFNET.Core/BasePages/ForumPage.cs
@@ -22,20 +22,25 @@
  * under the License.
  */
 
+using YAF.Core.Model;
+
 namespace YAF.Core.BasePages;
 
+using System.Threading.Tasks;
+
 using Microsoft.AspNetCore.Mvc.RazorPages;
 using Microsoft.AspNetCore.Mvc.Rendering;
 
 using YAF.Core.Filters;
 using YAF.Core.Handlers;
 using YAF.Types.Attributes;
+using YAF.Types.Models;
 
 /// &lt;summary&gt;
 /// The class that all YAF forum pages are derived from.
 /// &lt;/summary&gt;
 [EnableRateLimiting(&#34;fixed&#34;)]
-[PageSecurityCheck]
+//[PageSecurityCheck]
 [UserSuspendCheck]
 public abstract class ForumPage : PageModel,
                                   IHaveServiceLocator,
@@ -47,6 +52,105 @@ public abstract class ForumPage : PageModel,
     /// &lt;/summary&gt;
     private readonly UnicodeEncoder unicodeEncoder;
 
+    /// &lt;summary&gt;
+    /// Called asynchronously before the handler method is invoked, after model binding is complete.
+    /// &lt;/summary&gt;
+    /// &lt;param name=&#34;context&#34;&gt;The &lt;see cref=&#34;T:Microsoft.AspNetCore.Mvc.Filters.PageHandlerExecutingContext&#34; /&gt;.&lt;/param&gt;
+    /// &lt;param name=&#34;next&#34;&gt;The &lt;see cref=&#34;T:Microsoft.AspNetCore.Mvc.Filters.PageHandlerExecutionDelegate&#34; /&gt;. Invoked to execute the next page filter or the handler method itself.&lt;/param&gt;
+    public async override Task OnPageHandlerExecutionAsync(PageHandlerExecutingContext context, PageHandlerExecutionDelegate next)
+    {
+        // no security features for login/logout pages
+        if (BoardContext.Current.CurrentForumPage.IsAccountPage)
+        {
+            await next.Invoke();
+        }
+
+        // check if login is required
+        if (BoardContext.Current.BoardSettings.RequireLogin &amp;&amp; BoardContext.Current.IsGuest &amp;&amp;
+            BoardContext.Current.CurrentForumPage.IsProtected)
+        {
+            // redirect to login page if login is required
+            var result = this.Get&lt;IPermissions&gt;().HandleRequest(ViewPermissions.RegisteredUsers);
+
+            if (result != null)
+            {
+                context.Result = result;
+                return;
+            }
+        }
+
+        // check if it&#39;s a &#34;registered user only page&#34; and check permissions.
+        if (BoardContext.Current.CurrentForumPage.IsRegisteredPage &amp;&amp;
+            BoardContext.Current.CurrentForumPage.AspNetUser == null)
+        {
+            var result = this.Get&lt;IPermissions&gt;().HandleRequest(ViewPermissions.RegisteredUsers);
+
+            if (result != null)
+            {
+                context.Result = result;
+
+                return;
+            }
+        }
+
+        // Handle admin pages
+        if (BoardContext.Current.CurrentForumPage.IsAdminPage)
+        {
+            if (!BoardContext.Current.IsAdmin)
+            {
+                context.Result = this.Get&lt;ILinkBuilder&gt;().AccessDenied();
+                return;
+            }
+
+            // Load the page access list.
+            var hasAccess = this.GetRepository&lt;AdminPageUserAccess&gt;().HasAccess(
+                BoardContext.Current.PageUserID,
+                BoardContext.Current.CurrentForumPage.PageName.ToString());
+
+            // Check access rights to the page.
+            if (!BoardContext.Current.PageUser.UserFlags.IsHostAdmin &amp;&amp;
+                (!BoardContext.Current.CurrentForumPage.PageName.ToString().IsSet() || !hasAccess))
+            {
+                context.Result = this.Get&lt;ILinkBuilder&gt;()
+                    .RedirectInfoPage(InfoMessage.HostAdminPermissionsAreRequired);
+
+                return;
+            }
+        }
+
+        // handle security features...
+        if (BoardContext.Current.CurrentForumPage.PageName == ForumPages.Account_Register &amp;&amp;
+            BoardContext.Current.BoardSettings.DisableRegistrations)
+        {
+            context.Result = this.Get&lt;ILinkBuilder&gt;().AccessDenied();
+
+            return;
+        }
+
+        // check access permissions for specific pages...
+        var resultPermission = BoardContext.Current.CurrentForumPage.PageName switch
+        {
+            ForumPages.ActiveUsers =&gt; this.Get&lt;IPermissions&gt;()
+                .HandleRequest((ViewPermissions)BoardContext.Current.BoardSettings.ActiveUsersViewPermissions),
+            ForumPages.Members =&gt; this.Get&lt;IPermissions&gt;()
+                .HandleRequest((ViewPermissions)BoardContext.Current.BoardSettings.MembersListViewPermissions),
+            ForumPages.UserProfile or ForumPages.Albums or ForumPages.Album =&gt; this.Get&lt;IPermissions&gt;()
+                .HandleRequest((ViewPermissions)BoardContext.Current.BoardSettings.ProfileViewPermissions),
+            ForumPages.Search =&gt; this.Get&lt;IPermissions&gt;()
+                .HandleRequest((ViewPermissions)BoardContext.Current.BoardSettings.SearchPermissions),
+            _ =&gt; null
+        };
+
+        if (resultPermission != null)
+        {
+            context.Result = resultPermission;
+
+            return;
+        }
+
+        await next.Invoke();
+    }</pre>
</details>
<p><b>Fix</b> : The `PageSecurityCheckAttribute` was removed, and its logic was integrated directly into the `OnPageHandlerExecutionAsync` method of the `ForumPage` base class. This ensures that all necessary security checks, including `RequireLogin`, `IsRegisteredPage`, and `IsAdminPage` validations, are performed consistently before page handlers are executed. Specifically, the admin page access logic now correctly verifies both `BoardContext.Current.IsAdmin` and `AdminPageUserAccess` for non-host administrators.</p>
<p>
<a href="https://github.com/advisories/GHSA-xhw7-j96h-c3g5">Advisory</a> · <a href="https://github.com/YAFNET/YAFNET/commit/27f7e671f93698f7e014d5d0fb88320248b8aa20">Commit</a>
</p>
<hr>
<h3>GHSA-q4ph-8x8g-95f8</h3>
<p>
<code>HIGH 8.8</code> · 2026-05-04 · PHP<br>
<code>azuracast/azuracast</code> · Pattern: <code>UNSANITIZED_INPUT→COMMAND</code> · 25x across ecosystem
</p>
<p><b>Root cause</b> : The vulnerability stemmed from an incomplete migration from `cleanUpString` to `toRawString` for handling user-supplied input, specifically the remote relay password. The `cleanUpString` function was removed, but the password field was not consistently passed through the more robust `toRawString` function, allowing special characters to be injected directly into the Liquidsoap configuration.</p>
<p><b>Impact</b> : An attacker could inject arbitrary Liquidsoap code into the configuration, potentially leading to remote code execution or other malicious actions on the server where Liquidsoap is running.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/backend/src/Radio/Backend/Liquidsoap/ConfigWriter.php
+++ b/backend/src/Radio/Backend/Liquidsoap/ConfigWriter.php
@@ -1205,14 +1205,12 @@ private function getOutputString(
             $outputParams[] = &#39;user = &#39; . self::toRawString($source-&gt;username);
         }
 
-        $password = self::cleanUpString($source-&gt;password);
-        $adapterType = $source-&gt;adapterType;
-        if (FrontendAdapters::Shoutcast === $adapterType) {
-            $password .= &#39;:#&#39; . $id;
-        }
-        $outputParams[] = &#39;password = &#34;&#39; . $password . &#39;&#34;&#39;;
+        $password = $source-&gt;password;
+        $adapterType = $source-&gt;adapterType;
+        if (FrontendAdapters::Shoutcast === $adapterType) {
+            $password .= &#39;:#&#39; . $id;
+        }
+        $outputParams[] = &#39;password = &#39; . self::toRawString($password);</pre>
</details>
<p><b>Fix</b> : The patch removes the `cleanUpString` function and ensures that the remote relay password, along with other sensitive parameters, is consistently processed by the `toRawString` function. This function properly escapes special characters, preventing code injection into the Liquidsoap configuration.</p>
<p>
<a href="https://github.com/advisories/GHSA-q4ph-8x8g-95f8">Advisory</a> · <a href="https://github.com/AzuraCast/AzuraCast/commit/d6b8422fc2c36269df9d1adec89dfbba58828915">Commit</a>
</p>
<hr>
<h3>GHSA-vp2f-cqqp-478j</h3>
<p>
<code>HIGH 8.8</code> · 2026-05-04 · PHP<br>
<code>azuracast/azuracast</code> · Pattern: <code>PATH_TRAVERSAL→FILE_WRITE</code> · 18x across ecosystem
</p>
<p><b>Root cause</b> : The application allowed user-controlled input in the `flowIdentifier` parameter to be used in file paths without proper sanitization. This enabled an attacker to use directory traversal sequences (e.g., `../`) to write files outside of the intended upload directory.</p>
<p><b>Impact</b> : An attacker could upload arbitrary files to any location on the server, potentially leading to remote code execution by placing a malicious script in a web-accessible directory.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/backend/src/Service/Flow.php
+++ b/backend/src/Service/Flow.php
@@ -64,7 +65,9 @@ public static function process(
             return self::handleStandardUpload($request, $tempDir);
         }
 
-        $flowIdentifier = $params[&#39;flowIdentifier&#39;];
+        $pathNormalizer = new WhitespacePathNormalizer();
+
+        $flowIdentifier = $pathNormalizer-&gt;normalizePath($params[&#39;flowIdentifier&#39;]);
         $flowChunkNumber = (int)($params[&#39;flowChunkNumber&#39;] ?? 1);</pre>
</details>
<p><b>Fix</b> : The patch introduces a `WhitespacePathNormalizer` to sanitize the `flowIdentifier` parameter, ensuring that path traversal sequences are removed or normalized before being used in file operations. Additionally, the `upload` and `download` methods now explicitly normalize paths before passing them to the underlying adapter.</p>
<p>
<a href="https://github.com/advisories/GHSA-vp2f-cqqp-478j">Advisory</a> · <a href="https://github.com/AzuraCast/AzuraCast/commit/18c793b4427eb49e67a2fea99a89f1c9d9dd808d">Commit</a>
</p>
<hr>
<h3>GHSA-8h25-q488-4hxw</h3>
<p>
<code>HIGH 8.8</code> · 2026-04-23 · JavaScript<br>
<code>openlearnx</code> · Pattern: <code>UNSANITIZED_INPUT→COMMAND</code> · 25x across ecosystem
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
<code>github.com/m1k1o/neko/server</code> · Pattern: <code>PRIVILEGE_ESCALATION→ROLE</code> · 14x across ecosystem
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
<code>mathjs</code> · Pattern: <code>UNCLASSIFIED</code> · 54x across ecosystem
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
<code>pyload-ng</code> · Pattern: <code>PRIVILEGE_ESCALATION→ROLE</code> · 14x across ecosystem
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
<code>gov.nsa.emissary:emissary</code> · Pattern: <code>UNSANITIZED_INPUT→COMMAND</code> · 25x across ecosystem
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
<code>keras</code> · Pattern: <code>DESERIALIZATION→RCE</code> · 5x across ecosystem
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
<code>mathjs</code> · Pattern: <code>UNCLASSIFIED</code> · 54x across ecosystem
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
<code>agixt</code> · Pattern: <code>PATH_TRAVERSAL→FILE_READ</code> · 23x across ecosystem
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
<code>org.apache.cassandra:cassandra-all</code> · Pattern: <code>PRIVILEGE_ESCALATION→ROLE</code> · 14x across ecosystem
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
<code>apostrophe</code> · Pattern: <code>UNSANITIZED_INPUT→XSS</code> · 20x across ecosystem
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
<code>github.com/enchant97/note-mark/backend</code> · Pattern: <code>UNSANITIZED_INPUT→XSS</code> · 20x across ecosystem
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
<h3>GHSA-89g2-xw5c-v95p</h3>
<p>
<code>HIGH 8.6</code> · 2026-05-05 · Python<br>
<code>pptagent</code> · Pattern: <code>DESERIALIZATION→RCE</code> · 5x across ecosystem
</p>
<p><b>Root cause</b> : The application used `eval()` with an insufficiently restricted global scope, allowing LLM-generated code to execute arbitrary Python functions, including builtins. Additionally, file operations did not properly validate user-supplied paths, making them vulnerable to path traversal.</p>
<p><b>Impact</b> : An attacker could execute arbitrary code on the system, potentially leading to full system compromise. They could also read, write, or delete arbitrary files outside the intended workspace.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">--- a/pptagent/apis.py
+++ b/pptagent/apis.py
@@ -182,7 +183,7 @@ def execute_actions(
                 partial_func = partial(self.registered_functions[func], edit_slide)
                 if func == &#34;replace_image&#34;:
                     partial_func = partial(partial_func, doc)
-                eval(line, {}, {func: partial_func})
+                eval(line, SAFE_EVAL_GLOBALS, {func: partial_func})

--- a/pptagent/utils.py
+++ b/pptagent/utils.py
@@ -347,7 +369,8 @@ def get_html_table_image(html: str, output_path: str, css: str = None):
     &#34;&#34;&#34;
     if css is None:
         css = TABLE_CSS
-    parent_dir, base_name = os.path.split(output_path)
+    output_file = resolve_path_in_workspace(output_path)
+    parent_dir, base_name = os.path.split(output_file)</pre>
</details>
<p><b>Fix</b> : The patch restricts the `eval()` function by providing an empty `__builtins__` dictionary in the global scope, preventing access to dangerous built-in functions. It also introduces a `resolve_path_in_workspace` utility function to validate and constrain all file paths to a defined workspace, preventing path traversal.</p>
<p>
<a href="https://github.com/advisories/GHSA-89g2-xw5c-v95p">Advisory</a> · <a href="https://github.com/icip-cas/PPTAgent/commit/418491a9a1c02d9d93194b5973bb58df35cf9d00">Commit</a>
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
             Map to closed taxonomy of 45 normalized pattern IDs
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
<tr><td>Total advisories</td><td>381</td></tr>
<tr><td>Unique patterns</td><td>45</td></tr>
<tr><td>Pending</td><td>0</td></tr>
<tr><td>Last updated</td><td>2026-05-06</td></tr>
</table>
</details>
<hr>
<sub><a href="https://christbowel.com">christbowel.com</a></sub>
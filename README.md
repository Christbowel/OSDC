<div align="center">
<h1>🎣 Open Source Daily Catch</h1>
<p><b>Automated Patch Intelligence for Security Engineers</b></p>
<p>
<a href="https://github.com/christbowel/osdc/actions/workflows/daily.yml"><img src="https://github.com/christbowel/osdc/actions/workflows/daily.yml/badge.svg" alt="Analysis"></a>
<a href="https://github.com/christbowel/osdc/actions/workflows/render.yml"><img src="https://github.com/christbowel/osdc/actions/workflows/render.yml/badge.svg" alt="Render"></a>
<a href="https://christbowel.github.io/OSDC"><img src="https://img.shields.io/badge/advisories-134-blue" alt="Advisories"></a>
<a href="https://christbowel.github.io/OSDC"><img src="https://img.shields.io/badge/patterns-29-purple" alt="Patterns"></a>
</p>
<p>
<a href="https://christbowel.github.io/OSDC">Live dashboard</a> · <a href="#how-it-works">How it works</a>
</p>
</div>
<hr>
<h3>GHSA-9cp7-j3f8-p5jx</h3>
<p>
<code>CRITICAL 10.0</code> · 2026-04-10 · Go<br>
<code>github.com/daptin/daptin</code> · Pattern: <code>PATH_TRAVERSAL→FILE_WRITE</code> · 10x across ecosystem
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
<code>axios</code> · Pattern: <code>UNSANITIZED_INPUT→HEADER</code> · 1x across ecosystem
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
<h3>GHSA-jmrh-xmgh-x9j4</h3>
<p>
<code>CRITICAL 9.8</code> · 2026-04-06 · Python<br>
<code>changedetection.io</code> · Pattern: <code>MISSING_AUTH→ENDPOINT</code> · 5x across ecosystem
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
<h3>GHSA-8wrq-fv5f-pfp2</h3>
<p>
<code>CRITICAL 9.6</code> · 2026-04-10 · Python<br>
<code>lollms</code> · Pattern: <code>UNSANITIZED_INPUT→XSS</code> · 6x across ecosystem
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
<h3>GHSA-65w6-pf7x-5g85</h3>
<p>
<code>CRITICAL 9.4</code> · 2026-04-08 · JavaScript<br>
<code>@delmaredigital/payload-puck</code> · Pattern: <code>MISSING_AUTH→ENDPOINT</code> · 5x across ecosystem
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
<code>gramps-webapi</code> · Pattern: <code>PATH_TRAVERSAL→FILE_WRITE</code> · 10x across ecosystem
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
<h3>GHSA-wvhv-qcqf-f3cx</h3>
<p>
<code>CRITICAL 0.0</code> · 2026-04-10 · Go<br>
<code>github.com/patrickhener/goshs</code> · Pattern: <code>MISSING_AUTHZ→RESOURCE</code> · 9x across ecosystem
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
<code>axios</code> · Pattern: <code>SSRF→INTERNAL_ACCESS</code> · 11x across ecosystem
</p>
<p><b>Root cause</b> : The code does not properly validate or sanitize the hostname in the `no_proxy` environment variable, allowing attackers to bypass proxy settings and potentially access internal services.</p>
<p><b>Impact</b> : An attacker could use this vulnerability to perform SSRF attacks, accessing internal network resources without proper authorization.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">{&#34;before&#34;: &#34;&#34;, &#34;after&#34;: &#34;+const normalizeNoProxyHost = (hostname) =&gt; {\n+  if (!hostname) {\n+    return hostname;\n+  }\n+\n+  if (hostname.charAt(0) === &#39;[&#39; &amp;&amp; hostname.charAt(hostname.length - 1) === &#39;]&#39;) {\n+    hostname = hostname.slice(1, -1);\n+  }\n+\n+  return hostname.replace(/\\.+$/, &#39;&#39;);\n+};&#34;}</pre>
</details>
<p><b>Fix</b> : The patch introduces a function to normalize and parse the `no_proxy` entries, ensuring that only valid hostnames are considered for bypassing proxy settings.</p>
<p>
<a href="https://github.com/advisories/GHSA-3p68-rc4w-qgx5">Advisory</a> · <a href="https://github.com/axios/axios/commit/fb3befb6daac6cad26b2e54094d0f2d9e47f24df">Commit</a>
</p>
<hr>
<h3>GHSA-2679-6mx9-h9xc</h3>
<p>
<code>CRITICAL 0.0</code> · 2026-04-08 · Python<br>
<code>marimo</code> · Pattern: <code>MISSING_AUTH→ENDPOINT</code> · 5x across ecosystem
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
<code>org.openidentityplatform.openam:openam</code> · Pattern: <code>DESERIALIZATION→RCE</code> · 2x across ecosystem
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
<h3>GHSA-jvff-x2qm-6286</h3>
<p>
<code>HIGH 8.8</code> · 2026-04-10 · JavaScript<br>
<code>mathjs</code> · Pattern: <code>UNCLASSIFIED</code> · 32x across ecosystem
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
<code>agixt</code> · Pattern: <code>PATH_TRAVERSAL→FILE_READ</code> · 10x across ecosystem
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
<code>org.apache.cassandra:cassandra-all</code> · Pattern: <code>PRIVILEGE_ESCALATION→ROLE</code> · 1x across ecosystem
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
<h3>GHSA-chqc-8p9q-pq6q</h3>
<p>
<code>HIGH 8.6</code> · 2026-04-08 · JavaScript<br>
<code>basic-ftp</code> · Pattern: <code>UNSANITIZED_INPUT→COMMAND</code> · 12x across ecosystem
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
<code>n8n-mcp</code> · Pattern: <code>SSRF→INTERNAL_ACCESS</code> · 11x across ecosystem
</p>
<p><b>Root cause</b> : The code did not properly sanitize the `instance-URL` header, allowing attackers to perform SSRF attacks.</p>
<p><b>Impact</b> : An attacker could use this vulnerability to access internal resources or perform actions on behalf of other users within the same network.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">{&#34;before&#34;: &#34;this.baseUrl = baseUrl;&#34;, &#34;after&#34;: &#34;let normalizedBase: string;\ntry {\n  const parsed = new URL(baseUrl);\n  parsed.hash = &#39;&#39;;\n  parsed.username = &#39;&#39;;\n  parsed.password = &#39;&#39;;\n  normalizedBase = parsed.toString().replace(//$/, &#39;&#39;);\n} catch {\n  // Unparseable input falls through to raw; downstream axios call will\n  // fail cleanly. Preserves backward compat for tests that pass\n  // placeholder strings.\n  normalizedBase = baseUrl;\n}\nthis.baseUrl = normalizedBase;&#34;}</pre>
</details>
<p><b>Fix</b> : The patch normalizes the `baseUrl` by removing any embedded credentials and ensuring it does not end with a trailing slash, enhancing defense-in-depth against SSRF attacks.</p>
<p>
<a href="https://github.com/advisories/GHSA-4ggg-h7ph-26qr">Advisory</a> · <a href="https://github.com/czlonkowski/n8n-mcp/commit/d9d847f230923d96e0857ccecf3a4dedcc9b0096">Commit</a>
</p>
<hr>
<h3>GHSA-6v7q-wjvx-w8wg</h3>
<p>
<code>HIGH 8.2</code> · 2026-04-10 · JavaScript<br>
<code>basic-ftp</code> · Pattern: <code>UNSANITIZED_INPUT→COMMAND</code> · 12x across ecosystem
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
<code>n8n-mcp</code> · Pattern: <code>MISSING_AUTH→ENDPOINT</code> · 5x across ecosystem
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
<h3>GHSA-hc36-c89j-5f4j</h3>
<p>
<code>HIGH 8.1</code> · 2026-04-09 · Ruby<br>
<code>bsv-wallet</code> · Pattern: <code>MISSING_VERIFICATION→SIGNATURE</code> · 5x across ecosystem
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
<h3>GHSA-2943-crp8-38xx</h3>
<p>
<code>HIGH 7.7</code> · 2026-04-10 · Go<br>
<code>github.com/patrickhener/goshs</code> · Pattern: <code>PATH_TRAVERSAL→FILE_WRITE</code> · 10x across ecosystem
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
<h3>GHSA-hwqh-2684-54fc</h3>
<p>
<code>HIGH 7.5</code> · 2026-04-10 · Java<br>
<code>org.springframework.cloud:spring-cloud-gateway</code> · Pattern: <code>UNCLASSIFIED</code> · 32x across ecosystem
</p>
<p><b>Root cause</b> : The original code did not properly validate the length of the SSL bundle string before checking if it exists in the bundles list.</p>
<p><b>Impact</b> : An attacker could provide a maliciously crafted SSL bundle name that bypasses the validation, potentially leading to unauthorized access or other security issues.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before:
- if (ssl.getSslBundle() == null || ssl.getSslBundle().length() &gt; 0) {
-     return null;
}
After:
+ if (ssl.getSslBundle() != null &amp;&amp; ssl.getSslBundle().length() &gt; 0 &amp;&amp; bundles.getBundleNames().contains(ssl.getSslBundle())) {</pre>
</details>
<p><b>Fix</b> : The patch ensures that the SSL bundle name is not empty and is present in the bundles list before returning it.</p>
<p>
<a href="https://github.com/advisories/GHSA-hwqh-2684-54fc">Advisory</a> · <a href="https://github.com/spring-cloud/spring-cloud-gateway/commit/84009f2ee421e2191f8cc32ce3a84e7fc09e305e">Commit</a>
</p>
<hr>
<h3>GHSA-9hfr-gw99-8rhx</h3>
<p>
<code>HIGH 7.5</code> · 2026-04-09 · Ruby<br>
<code>bsv-sdk</code> · Pattern: <code>MISSING_AUTHZ→RESOURCE</code> · 9x across ecosystem
</p>
<p><b>Root cause</b> : The code did not properly handle responses indicating that a transaction was not accepted, leading to the treatment of INVALID/MALFORMED/ORPHAN responses as successful broadcasts.</p>
<p><b>Impact</b> : An attacker could potentially treat invalid or malformed transactions as successful, allowing for unauthorized use of resources or manipulation of the system.</p>
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
<p><b>Fix</b> : The patch adds support for additional rejected statuses and includes a substring match for orphan detection in txStatus or extraInfo fields. It also introduces optional parameters for deployment ID, callback URL, and callback token to enhance security.</p>
<p>
<a href="https://github.com/advisories/GHSA-9hfr-gw99-8rhx">Advisory</a> · <a href="https://github.com/sgbett/bsv-ruby-sdk/commit/4992e8a265fd914a7eeb0405c69d1ff0122a84cc">Commit</a>
</p>
<hr>
<h3>GHSA-mh2q-q3fh-2475</h3>
<p>
<code>HIGH 7.5</code> · 2026-04-07 · Go<br>
<code>go.opentelemetry.io/otel/propagation</code> · Pattern: <code>UNCLASSIFIED</code> · 32x across ecosystem
</p>
<p><b>Root cause</b> : The code did not properly limit the number of members or bytes in the baggage header, leading to excessive allocations and potential denial-of-service amplification.</p>
<p><b>Impact</b> : An attacker could cause the application to allocate an excessive amount of memory by sending a large number of small baggage headers. This could lead to resource exhaustion and potentially crash the application.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before:
- maxMembers = 180
- maxBytesPerMembers = 4096
After:
+ maxMembers = 64</pre>
</details>
<p><b>Fix</b> : The patch limits the maximum number of members in the baggage header to 64, reducing the risk of excessive allocations and potential denial-of-service amplification.</p>
<p>
<a href="https://github.com/advisories/GHSA-mh2q-q3fh-2475">Advisory</a> · <a href="https://github.com/open-telemetry/opentelemetry-go/commit/aa1894e09e3fe66860c7885cb40f98901b35277f">Commit</a>
</p>
<hr>
<h3>GHSA-3p65-76g6-3w7r</h3>
<p>
<code>HIGH 7.5</code> · 2026-04-06 · Go<br>
<code>github.com/distribution/distribution</code> · Pattern: <code>SSRF→INTERNAL_ACCESS</code> · 11x across ecosystem
</p>
<p><b>Root cause</b> : The code did not validate the &#39;realm&#39; parameter in the &#39;WWW-Authenticate&#39; header, allowing attackers to perform SSRF attacks by manipulating the realm value.</p>
<p><b>Impact</b> : An attacker could use this vulnerability to access internal resources or services that are not supposed to be accessible from outside the network.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before:
	if strings.EqualFold(c.Scheme, &#34;bearer&#34;) {
After:
	if strings.EqualFold(c.Scheme, &#34;bearer&#34;) &amp;&amp; realmAllowed(remote, c.Parameters[&#34;realm&#34;]) {</pre>
</details>
<p><b>Fix</b> : The patch introduces a function `realmAllowed` that checks if the &#39;realm&#39; parameter is allowed based on the remote URL, preventing attackers from manipulating the realm value for SSRF attacks.</p>
<p>
<a href="https://github.com/advisories/GHSA-3p65-76g6-3w7r">Advisory</a> · <a href="https://github.com/distribution/distribution/commit/cc5d5fa4ba02157501e6afa2cc6a903ad0338e7b">Commit</a>
</p>
<hr>
<h3>GHSA-f2g3-hh2r-cwgc</h3>
<p>
<code>HIGH 7.5</code> · 2026-04-06 · Go<br>
<code>github.com/distribution/distribution</code> · Pattern: <code>UNCLASSIFIED</code> · 32x across ecosystem
</p>
<p><b>Root cause</b> : The code did not properly validate or sanitize input when interacting with the Redis cache.</p>
<p><b>Impact</b> : An attacker could potentially manipulate the Redis cache to access stale blob data, leading to unauthorized access or data corruption.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before:
- member, err := rsrbds.upstream.pool.SIsMember(ctx, rsrbds.repositoryBlobSetKey(rsrbds.repo), dgst.String()).Result()
After:
+ pool := rsrbds.upstream.pool
+ member, err := pool.SIsMember(ctx, rsrbds.repositoryBlobSetKey(rsrbds.repo), dgst.String()).Result()</pre>
</details>
<p><b>Fix</b> : The patch ensures that the Redis pool is used consistently and correctly for all operations, preventing potential misuse of the cache.</p>
<p>
<a href="https://github.com/advisories/GHSA-f2g3-hh2r-cwgc">Advisory</a> · <a href="https://github.com/distribution/distribution/commit/078b0783f239b4115d1a979e66f08832084e9d1d">Commit</a>
</p>
<hr>
<h3>GHSA-h6rj-3m53-887h</h3>
<p>
<code>HIGH 7.5</code> · 2026-04-06 · PHP<br>
<code>pocketmine/pocketmine-mp</code> · Pattern: <code>UNCLASSIFIED</code> · 32x across ecosystem
</p>
<p><b>Root cause</b> : The code directly logs the value of an unknown property without sanitizing it.</p>
<p><b>Impact</b> : An attacker could potentially log sensitive information or cause a denial of service by crafting a malicious packet with large complex properties.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before:
- var_export($value, return: true)
After:
+ Utils::printable(substr($name, 0, 80))</pre>
</details>
<p><b>Fix</b> : The patch uses a utility function to print only a portion of the property name, preventing potential log injection and excessive logging.</p>
<p>
<a href="https://github.com/advisories/GHSA-h6rj-3m53-887h">Advisory</a> · <a href="https://github.com/pmmp/PocketMine-MP/commit/87d1c0cea09d972fd4c2fafb84dac2ecab7649f0">Commit</a>
</p>
<hr>
<h3>GHSA-hv3w-m4g2-5x77</h3>
<p>
<code>HIGH 7.5</code> · 2026-04-06 · Python<br>
<code>strawberry-graphql</code> · Pattern: <code>DOS→RESOURCE_EXHAUSTION</code> · 4x across ecosystem
</p>
<p><b>Root cause</b> : The code did not limit the number of WebSocket subscriptions per connection, allowing an attacker to create an unbounded number of subscriptions.</p>
<p><b>Impact</b> : An attacker could cause a denial of service by establishing an excessive number of WebSocket connections and subscriptions, exhausting server resources.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Added `max_subscriptions_per_connection: int | None = None` in the constructor.

Added check `if not self.connection_acknowledged:` before handling a subscription to ensure the connection is authorized.

Added logic to clean up existing operations with the same ID to prevent task leaks.</pre>
</details>
<p><b>Fix</b> : The patch introduces a `max_subscriptions_per_connection` parameter to limit the number of subscriptions per connection, preventing resource exhaustion.</p>
<p>
<a href="https://github.com/advisories/GHSA-hv3w-m4g2-5x77">Advisory</a> · <a href="https://github.com/strawberry-graphql/strawberry/commit/0977a4e6b41b7cfe3e9d8ba84a43458a2b0c54c2">Commit</a>
</p>
<hr>
<h3>GHSA-vpwc-v33q-mq89</h3>
<p>
<code>HIGH 7.5</code> · 2026-04-06 · Python<br>
<code>strawberry-graphql</code> · Pattern: <code>UNCLASSIFIED</code> · 32x across ecosystem
</p>
<p><b>Root cause</b> : The patch adds a new parameter `max_subscriptions_per_connection` but does not enforce any authentication or authorization checks.</p>
<p><b>Impact</b> : An attacker could bypass the authentication mechanism and establish multiple subscriptions on a single connection, potentially leading to resource exhaustion or other unauthorized access issues.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">diff --git a/strawberry/subscriptions/protocols/graphql_ws/handlers.py b/strawberry/subscriptions/protocols/graphql_ws/handlers.py
index 21979ff23d..e0bbc18052 100644
--- a/strawberry/subscriptions/protocols/graphql_ws/handlers.py
+++ b/strawberry/subscriptions/protocols/graphql_ws/handlers.py
@@ -119,6 +122,8 @@ async def handle_connection_init(self, message: ConnectionInitMessage) -&gt; None:
                 {</pre>
</details>
<p><b>Fix</b> : The patch should include proper authentication and authorization checks to ensure that only authenticated users can initiate connections and handle subscriptions.</p>
<p>
<a href="https://github.com/advisories/GHSA-vpwc-v33q-mq89">Advisory</a> · <a href="https://github.com/strawberry-graphql/strawberry/commit/0977a4e6b41b7cfe3e9d8ba84a43458a2b0c54c2">Commit</a>
</p>
<hr>
<h3>GHSA-8jvc-mcx6-r4cg</h3>
<p>
<code>HIGH 7.4</code> · 2026-04-10 · Go<br>
<code>code.vikunja.io/api</code> · Pattern: <code>UNCLASSIFIED</code> · 32x across ecosystem
</p>
<p><b>Root cause</b> : The OIDC login path did not enforce TOTP Two-Factor Authentication for all users, allowing bypass of the authentication mechanism.</p>
<p><b>Impact</b> : An attacker could log in to the system without providing a valid TOTP passcode, potentially gaining unauthorized access to user accounts.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before:
- &lt;Message v-if=&#34;loading&#34;&gt;
+ &lt;Message v-if=&#34;loading &amp;&amp; !needsTotp&#34;&gt;

After:
+ &lt;form
+   v-if=&#34;needsTotp&#34;
+   @submit.prevent=&#34;submitTotpAndRestart&#34;
+ &gt;
+   &lt;FormField
+     id=&#34;openIdTotpPasscode&#34;
+     ref=&#34;totpInput&#34;
+     v-model=&#34;totpPasscode&#34;
+     v-focus
+     :label=&#34;$t(&#39;user.auth.totpTitle&#39;)&#34;
+     autocomplete=&#34;one-time-code&#34;
+     :placeholder=&#34;$t(&#39;user.auth.totpPlaceholder&#39;)&#34;
+     required
+     type=&#34;text&#34;
+     inputmode=&#34;numeric&#34;
+   /&gt;
+   &lt;XButton
+     :loading=&#34;loading&#34;
+     :disabled=&#34;!totpPasscode&#34;
+     class=&#34;mbs-2&#34;
+     @click=&#34;submitTotpAndRestart&#34;
+   &gt;
+     {{ $t(&#39;user.auth.openIdTotpSubmit&#39;) }}
+   &lt;/XButton&gt;
+ &lt;/form&gt;</pre>
</details>
<p><b>Fix</b> : The patch adds a form that requires users to provide a TOTP passcode before being authenticated via OIDC. This ensures that TOTP Two-Factor Authentication is enforced for all users attempting to log in through the OIDC path.</p>
<p>
<a href="https://github.com/advisories/GHSA-8jvc-mcx6-r4cg">Advisory</a> · <a href="https://github.com/go-vikunja/vikunja/commit/b642b2a4536a3846e627a78dce2fdd1be425e6a1">Commit</a>
</p>
<hr>
<h3>GHSA-jfwg-rxf3-p7r9</h3>
<p>
<code>HIGH 7.3</code> · 2026-04-06 · Go<br>
<code>github.com/authorizerdev/authorizer</code> · Pattern: <code>UNSANITIZED_INPUT→NOSQL</code> · 1x across ecosystem
</p>
<p><b>Root cause</b> : The code uses `fmt.Sprintf` for string interpolation to construct SQL queries, which can lead to CQL/N1QL injection if user input is not properly sanitized.</p>
<p><b>Impact</b> : An attacker could execute arbitrary CQL/N1QL commands on the database, potentially leading to data theft, unauthorized access, or other malicious activities.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before:
values := fmt.Sprintf(&#34;&#39;%s&#39;,&#34;, value.(string))

After:
placeholders += &#34;?,&#34;
insertValues = append(insertValues, value)</pre>
</details>
<p><b>Fix</b> : The patch converts map values to appropriate types and uses parameterized queries with placeholders to prevent SQL injection.</p>
<p>
<a href="https://github.com/advisories/GHSA-jfwg-rxf3-p7r9">Advisory</a> · <a href="https://github.com/authorizerdev/authorizer/commit/73679faa53cd215c7524d651046e402c43809786">Commit</a>
</p>
<hr>
<h3>GHSA-pg8g-f2hf-x82m</h3>
<p>
<code>HIGH 6.5</code> · 2026-04-09 · JavaScript<br>
<code>openclaw</code> · Pattern: <code>SSRF→INTERNAL_ACCESS</code> · 11x across ecosystem
</p>
<p><b>Root cause</b> : The original code did not properly sanitize or validate the request body before sending it across cross-origin redirects.</p>
<p><b>Impact</b> : An attacker could exploit this vulnerability to perform SSRF attacks, potentially gaining access to internal resources or leaking sensitive information.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before:
-      const pinned = await resolvePinnedHostnameWithPolicy(parsedUrl.hostname, {
-        lookupFn: params.lookupFn,
-        policy: params.policy,
-      });
After:
+        const pinned = await resolvePinnedHostnameWithPolicy(parsedUrl.hostname, {
+          lookupFn: params.lookupFn,
+          policy: params.policy,
+        });</pre>
</details>
<p><b>Fix</b> : The patch ensures that the request body is sanitized and validated before being sent across cross-origin redirects, mitigating the risk of SSRF vulnerabilities.</p>
<p>
<a href="https://github.com/advisories/GHSA-pg8g-f2hf-x82m">Advisory</a> · <a href="https://github.com/openclaw/openclaw/commit/d7c3210cd6f5fdfdc1beff4c9541673e814354d5">Commit</a>
</p>
<hr>
<h3>GHSA-q5jf-9vfq-h4h7</h3>
<p>
<code>HIGH 0.0</code> · 2026-04-10 · Go<br>
<code>helm.sh/helm/v4</code> · Pattern: <code>MISSING_VERIFICATION→SIGNATURE</code> · 5x across ecosystem
</p>
<p><b>Root cause</b> : The plugin installation process did not check for the presence of a .prov file, allowing unsigned plugins to be installed without verification.</p>
<p><b>Impact</b> : An attacker could install and execute unsigned plugins, potentially gaining unauthorized access or executing malicious code on the system.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before:
- fmt.Fprintf(os.Stderr, &#34;WARNING: No provenance file found for plugin. Plugin is not signed and cannot be verified.\n&#34;)
After:
+ return nil, fmt.Errorf(&#34;plugin verification failed: no provenance file (.prov) found&#34;)</pre>
</details>
<p><b>Fix</b> : The patch ensures that an error is returned if no .prov file is found during plugin installation, preventing the installation of unsigned plugins.</p>
<p>
<a href="https://github.com/advisories/GHSA-q5jf-9vfq-h4h7">Advisory</a> · <a href="https://github.com/helm/helm/commit/05fa37973dc9e42b76e1d2883494c87174b6074f">Commit</a>
</p>
<hr>
<h3>GHSA-vmx8-mqv2-9gmg</h3>
<p>
<code>HIGH 0.0</code> · 2026-04-10 · Go<br>
<code>helm.sh/helm/v4</code> · Pattern: <code>PATH_TRAVERSAL→FILE_WRITE</code> · 10x across ecosystem
</p>
<p><b>Root cause</b> : The code did not validate the plugin version format, allowing an attacker to write files outside the Helm plugin directory.</p>
<p><b>Impact</b> : An attacker could potentially overwrite or create arbitrary files on the server with the privileges of the user running Helm.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before:

After:
+func isValidSemver(v string) bool {
+    _, err := semver.NewVersion(v)
+    return err == nil
+}

-// Validate the plugin version
-if m.Version != &#34;&#34; &amp;&amp; !isValidSemver(m.Version) {
-    return fmt.Errorf(&#34;invalid plugin version %q: must be valid semver&#34;, m.Version)
-}</pre>
</details>
<p><b>Fix</b> : The patch adds a validation function for the plugin version using semantic versioning, ensuring that only valid versions can be used.</p>
<p>
<a href="https://github.com/advisories/GHSA-vmx8-mqv2-9gmg">Advisory</a> · <a href="https://github.com/helm/helm/commit/36c8539e99bc42d7aef9b87d136254662d04f027">Commit</a>
</p>
<hr>
<h3>GHSA-7437-7hg8-frrw</h3>
<p>
<code>HIGH 0.0</code> · 2026-04-09 · JavaScript<br>
<code>openclaw</code> · Pattern: <code>UNSANITIZED_INPUT→COMMAND</code> · 12x across ecosystem
</p>
<p><b>Root cause</b> : The code did not properly sanitize or denylist certain environment variables that could be used for command injection.</p>
<p><b>Impact</b> : An attacker could inject malicious commands into the build environment, potentially leading to remote code execution (RCE).</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before:
-      const pinned = await resolvePinnedHostnameWithPolicy(parsedUrl.hostname, {
-        lookupFn: params.lookupFn,
-        policy: params.policy,
-      });
After:
+        const pinned = await resolvePinnedHostnameWithPolicy(parsedUrl.hostname, {
+          lookupFn: params.lookupFn,
+          policy: params.policy,
+        });</pre>
</details>
<p><b>Fix</b> : The patch ensures that critical environment variables like HGRCPATH, CARGO_BUILD_RUSTC_WRAPPER, RUSTC_WRAPPER, and MAKEFLAGS are properly sanitized or denied from being used in the build process.</p>
<p>
<a href="https://github.com/advisories/GHSA-7437-7hg8-frrw">Advisory</a> · <a href="https://github.com/openclaw/openclaw/commit/d7c3210cd6f5fdfdc1beff4c9541673e814354d5">Commit</a>
</p>
<hr>
<h3>GHSA-h749-fxx7-pwpg</h3>
<p>
<code>HIGH 0.0</code> · 2026-04-09 · Go<br>
<code>github.com/minio/minio</code> · Pattern: <code>DOS→RESOURCE_EXHAUSTION</code> · 4x across ecosystem
</p>
<p><b>Root cause</b> : The code does not properly validate or limit the size of the input data for S3 Select CSV parsing, leading to an unbounded memory allocation.</p>
<p><b>Impact</b> : An attacker could cause a Denial of Service (DoS) by sending specially crafted requests that trigger excessive memory usage on the server.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before:

After:
func (api objectAPIHandlers) SelectObjectContentHandler(w http.ResponseWriter, r *http.Request) {
    ctx := newContext(r, w, &#34;SelectObject&#34;)
    var object, bucket string
    vars := mux.Vars(r)
    bucket = vars[&#34;bucket&#34;]
    object = vars[&#34;object&#34;]

    // Fetch object stat info.
    objectAPI := api.ObjectAPI()
    if objectAPI == nil {
        writeErrorResponse(w, ErrServerNotInitialized, r.URL)
        return
    }

    getObjectInfo := objectAPI.GetObjectInfo
    if api.CacheAPI() != nil {
        getObjectInfo = api.CacheAPI().GetObjectInfo
    }

    if s3Error := checkRequestAuthType(ctx, r, policy.GetObjectAction, bucket, object); s3Error != ErrNone {
        if getRequestAuthType(r) == authTypeAnonymous {
            // As per &#34;Permission&#34; section in
            // https://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectGET.html If
            // the object you request does not exist, the error Amazon S3 returns
            // depends on whether you also have the s3:ListBucket permission. * If you
            // have the s3:ListBucket permission on the bucket, Amazon S3 will re</pre>
</details>
<p><b>Fix</b> : The patch adds validation and limits on the size of the input data for S3 Select CSV parsing, preventing unbounded memory allocation.</p>
<p>
<a href="https://github.com/advisories/GHSA-h749-fxx7-pwpg">Advisory</a> · <a href="https://github.com/minio/minio/commit/7c14cdb60e53dbfdad2be644dfb180cab19fffa7">Commit</a>
</p>
<hr>
<h3>GHSA-qx8j-g322-qj6m</h3>
<p>
<code>HIGH 0.0</code> · 2026-04-09 · JavaScript<br>
<code>openclaw</code> · Pattern: <code>SSRF→INTERNAL_ACCESS</code> · 11x across ecosystem
</p>
<p><b>Root cause</b> : The original code did not properly sanitize or validate the request body before replaying it across cross-origin redirects.</p>
<p><b>Impact</b> : An attacker could use this vulnerability to perform SSRF attacks, potentially accessing internal resources or leaking sensitive information.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before:
-      const pinned = await resolvePinnedHostnameWithPolicy(parsedUrl.hostname, {
-        lookupFn: params.lookupFn,
-        policy: params.policy,
-      });
After:
+        const pinned = await resolvePinnedHostnameWithPolicy(parsedUrl.hostname, {
+          lookupFn: params.lookupFn,
+          policy: params.policy,
+        });</pre>
</details>
<p><b>Fix</b> : The patch ensures that the pinned hostname is resolved correctly and used in the dispatcher creation process, preventing unsafe request bodies from being replayed across cross-origin redirects.</p>
<p>
<a href="https://github.com/advisories/GHSA-qx8j-g322-qj6m">Advisory</a> · <a href="https://github.com/openclaw/openclaw/commit/d7c3210cd6f5fdfdc1beff4c9541673e814354d5">Commit</a>
</p>
<hr>
<h3>GHSA-h259-74h5-4rh9</h3>
<p>
<code>HIGH 0.0</code> · 2026-04-08 · Java<br>
<code>org.xwiki.platform:xwiki-platform-legacy-oldcore</code> · Pattern: <code>UNCLASSIFIED</code> · 32x across ecosystem
</p>
<p><b>Root cause</b> : The code did not properly sanitize or escape user input when rendering Velocity templates.</p>
<p><b>Impact</b> : An attacker could inject malicious scripts into the application, leading to potential data theft, session hijacking, or other attacks.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before:
@@ -80,6 +81,24 @@ public ServletContext getServletContext()
         return null;
     }

+    /**
+     * {@inheritDoc}
+     * &lt;p&gt;
+     * Only allowed to author with programming right because it allows access to the underlying request that doesn&#39;t
+     * enforce any security checks.
+     *
+     * @see javax.servlet.ServletRequestWrapper#getRequest()
+     */
+    @Override
+    public ServletRequest getRequest()
+    {
+        if (this.authorization.hasAccess(Right.PROGRAM)) {
+            return super.getRequest();
+        }
+
+        return null;
+    }
+
     /**
      * {@inheritDoc}
      * &lt;p&gt;
After:
@@ -80,6 +81,24 @@ public ServletContext getServletContext()
         return null;
     }

+    /**
+     * {@inheritDoc}
+     * &lt;p&gt;
+     * Only allowed to author with programming right because it allows access to the underlying request that doesn&#39;t
+     * enforce any security checks.
+     *
+     * @see javax.servlet.ServletRequestWrapper#getRequest()
+     */
+    @Override
+    public ServletRequest getRequest()
+    {
+        if (this.authorization.hasAccess(Right.PROGRAM)) {
+            return super.getRequest();
+        }
+
+        return null;
+    }
+
     /**
      * {@inheritDoc}
      * &lt;p&gt;</pre>
</details>
<p><b>Fix</b> : The patch adds a check to ensure that only users with programming rights can access the underlying request object, which enforces security checks.</p>
<p>
<a href="https://github.com/advisories/GHSA-h259-74h5-4rh9">Advisory</a> · <a href="https://github.com/xwiki/xwiki-platform/commit/9fe84da66184c05953df9466cf3a4acd15a46e63">Commit</a>
</p>
<hr>
<h3>GHSA-hwr4-mq23-wcv5</h3>
<p>
<code>HIGH 0.0</code> · 2026-04-08 · Go<br>
<code>github.com/dunglas/mercure</code> · Pattern: <code>UNCLASSIFIED</code> · 32x across ecosystem
</p>
<p><b>Root cause</b> : The patch does not address a security vulnerability but rather refactors the configuration structure for Topic Selector Cache.</p>
<p><b>Impact</b> : This change does not impact the security of the application; it is purely an internal refactor.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before:
- maxEntriesPerShard := mercure.DefaultTopicSelectorStoreCacheMaxEntriesPerShard
- shardCount := mercure.DefaultTopicSelectorStoreCacheShardCount
After:
+ cacheSize := mercure.DefaultTopicSelectorStoreCacheSize
+ switch {
+ case m.TopicSelectorCache.Size &gt; 0:
+ cacheSize = m.TopicSelectorCache.Size</pre>
</details>
<p><b>Fix</b> : Refactor the cache configuration to use a single &#39;Size&#39; field instead of deprecated &#39;MaxEntriesPerShard&#39; and &#39;ShardCount&#39;.</p>
<p>
<a href="https://github.com/advisories/GHSA-hwr4-mq23-wcv5">Advisory</a> · <a href="https://github.com/dunglas/mercure/commit/4964a69be904fd61e35b5f1e691271663b6fdd64">Commit</a>
</p>
<hr>
<h3>GHSA-jpcj-7wfg-mqxv</h3>
<p>
<code>HIGH 0.0</code> · 2026-04-08 · Python<br>
<code>stata-mcp</code> · Pattern: <code>UNSANITIZED_INPUT→COMMAND</code> · 12x across ecosystem
</p>
<p><b>Root cause</b> : The code did not validate user-supplied Stata do-file content, allowing the execution of shell-escape directives like `!cmd` or `shell cmd`.</p>
<p><b>Impact</b> : An attacker could execute arbitrary operating system commands on the server, leading to potential data loss, privilege escalation, or other malicious activities.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before:
# No validation of do-file content
After:
def _validate_dofile_content(text: str) -&gt; None:
    dangerous_tokens = [&#34;\n!&#34;, &#34;\nshell &#34;]
    for token in dangerous_tokens:
        if token in text:
            raise ValueError(
                &#34;Shell-escape commands (!cmd or shell cmd) are disabled for security reasons.&#34;
            )</pre>
</details>
<p><b>Fix</b> : The patch introduced a security guard that checks for and rejects Stata shell-escape directives to prevent OS command execution.</p>
<p>
<a href="https://github.com/advisories/GHSA-jpcj-7wfg-mqxv">Advisory</a> · <a href="https://github.com/SepineTam/stata-mcp/commit/52413ce">Commit</a>
</p>
<hr>
<h3>GHSA-fmwg-qcqh-m992</h3>
<p>
<code>HIGH 0.0</code> · 2026-04-07 · Go<br>
<code>github.com/gotenberg/gotenberg/v8</code> · Pattern: <code>UNSANITIZED_INPUT→REGEX</code> · 3x across ecosystem
</p>
<p><b>Root cause</b> : The code did not set a timeout for the regex pattern matching, allowing attackers to exploit a ReDoS vulnerability.</p>
<p><b>Impact</b> : An attacker could cause a denial of service by sending a malicious request with a large or complex input that causes the regex engine to consume excessive resources.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before:
scopeRegexp = p
After:
scopeRegexp = p
p.MatchTimeout = 5 * time.Second</pre>
</details>
<p><b>Fix</b> : The patch sets a timeout of 5 seconds for the regex pattern matching, mitigating the risk of ReDoS attacks.</p>
<p>
<a href="https://github.com/advisories/GHSA-fmwg-qcqh-m992">Advisory</a> · <a href="https://github.com/gotenberg/gotenberg/commit/cfb48d9af48cb236244eabe5c67fe1d30fb3fe25">Commit</a>
</p>
<hr>
<h3>GHSA-qmwh-9m9c-h36m</h3>
<p>
<code>HIGH 0.0</code> · 2026-04-07 · Go<br>
<code>github.com/gotenberg/gotenberg/v8</code> · Pattern: <code>PATH_TRAVERSAL→FILE_WRITE</code> · 10x across ecosystem
</p>
<p><b>Root cause</b> : The original code did not properly sanitize user-supplied metadata, allowing attackers to bypass intended restrictions and write arbitrary files using tags like HardLink and SymLink.</p>
<p><b>Impact</b> : An attacker could create hard links or symbolic links to arbitrary files on the server, potentially leading to unauthorized access or data corruption.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before:
	for _, tag := range dangerousTags {
		delete(metadata, tag)
}

After:
	for key := range metadata {
		for _, tag := range dangerousTags {
			if strings.EqualFold(key, tag) {
				delete(metadata, key)
			}
		}
	}</pre>
</details>
<p><b>Fix</b> : The patch adds case-insensitive comparison for dangerous tags to prevent attackers from bypassing the intended restrictions. It also ensures that only safe metadata is written by removing any user-supplied tags that could trigger file operations like renaming, moving, or linking.</p>
<p>
<a href="https://github.com/advisories/GHSA-qmwh-9m9c-h36m">Advisory</a> · <a href="https://github.com/gotenberg/gotenberg/commit/15050a311b73d76d8b9223bafe7fa7ba71240011">Commit</a>
</p>
<hr>
<h3>GHSA-vfw7-6rhc-6xxg</h3>
<p>
<code>HIGH 0.0</code> · 2026-04-07 · JavaScript<br>
<code>openclaw</code> · Pattern: <code>UNSANITIZED_INPUT→COMMAND</code> · 12x across ecosystem
</p>
<p><b>Root cause</b> : The code directly used environment variables from the backend configuration without sanitizing them.</p>
<p><b>Impact</b> : An attacker could inject malicious commands into the environment, potentially leading to arbitrary command execution on the server.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before:
const next = { ...process.env, ...backend.env };

After:
const next = sanitizeHostExecEnv({
  baseEnv: process.env,
  overrides: backend.env,
  blockPathOverrides: true,
});</pre>
</details>
<p><b>Fix</b> : The patch introduces a function `sanitizeHostExecEnv` that ensures environment variables are sanitized before being used in the command execution context.</p>
<p>
<a href="https://github.com/advisories/GHSA-vfw7-6rhc-6xxg">Advisory</a> · <a href="https://github.com/openclaw/openclaw/commit/c2fb7f1948c3226732a630256b5179a60664ec24">Commit</a>
</p>
<hr>
<h3>GHSA-788v-5pfp-93ff</h3>
<p>
<code>HIGH 0.0</code> · 2026-04-06 · PHP<br>
<code>pocketmine/pocketmine-mp</code> · Pattern: <code>UNCLASSIFIED</code> · 32x across ecosystem
</p>
<p><b>Root cause</b> : The application did not limit the size of JSON data it could decode, allowing attackers to send extremely large payloads that could consume excessive memory or cause denial of service.</p>
<p><b>Impact</b> : An attacker could cause a denial of service by sending a very large JSON payload, potentially crashing the server or consuming all available memory.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before:
```php
try{
	$responseData = json_decode($packet-&gt;formData, true, self::MAX_FORM_RESPONSE_DEPTH, JSON_THROW_ON_ERROR);
}
catch(\JsonException $e){
	// Handle exception
}
```
After:
```php
if(strlen($packet-&gt;formData) &gt; self::MAX_FORM_RESPONSE_SIZE){
	throw new PacketHandlingException(&#34;Form response data too large, refusing to decode (received&#34; . strlen($packet-&gt;formData) . &#34; bytes, max &#34; . self::MAX_FORM_RESPONSE_SIZE . &#34; bytes)&#34;);
}
try{
	$responseData = json_decode($packet-&gt;formData, true, self::MAX_FORM_RESPONSE_DEPTH, JSON_THROW_ON_ERROR);
}
catch(\JsonException $e){
	// Handle exception
}</pre>
</details>
<p><b>Fix</b> : The patch introduces a maximum size limit for JSON form response data and throws an exception if the received data exceeds this limit before attempting to decode it. This prevents excessive memory consumption and potential DoS attacks.</p>
<p>
<a href="https://github.com/advisories/GHSA-788v-5pfp-93ff">Advisory</a> · <a href="https://github.com/pmmp/PocketMine-MP/commit/cef1088341e40ee7a6fa079bca47a84f3524d877">Commit</a>
</p>
<hr>
<h3>GHSA-p9ff-h696-f583</h3>
<p>
<code>HIGH 0.0</code> · 2026-04-06 · JavaScript<br>
<code>vite</code> · Pattern: <code>PATH_TRAVERSAL→FILE_READ</code> · 10x across ecosystem
</p>
<p><b>Root cause</b> : The code did not properly sanitize the input `id` before using it to access files, allowing an attacker to read arbitrary files on the server.</p>
<p><b>Impact</b> : An attacker could potentially read sensitive files on the server, such as configuration files or source code, which could lead to further exploitation or data leakage.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before:
if (options.allowId &amp;&amp; !options.allowId(id)) {

After:
if (
  !options.skipFsCheck &amp;&amp;
  id[0] !== &#39;\u0000&#39; &amp;&amp;
isServerAccessDeniedForTransform(config, id)
) {</pre>
</details>
<p><b>Fix</b> : The patch introduced a check to ensure that the `id` does not start with &#39; &#39; and calls a new function `isServerAccessDeniedForTransform` to verify if access is allowed for the given `id`. This prevents attackers from reading arbitrary files.</p>
<p>
<a href="https://github.com/advisories/GHSA-p9ff-h696-f583">Advisory</a> · <a href="https://github.com/vitejs/vite/commit/f02d9fde0b195afe3ea2944414186962fbbe41e0">Commit</a>
</p>
<hr>
<h3>GHSA-v2wj-q39q-566r</h3>
<p>
<code>HIGH 0.0</code> · 2026-04-06 · JavaScript<br>
<code>vite</code> · Pattern: <code>UNCLASSIFIED</code> · 32x across ecosystem
</p>
<p><b>Root cause</b> : The code does not appear to directly address a known security vulnerability based on the provided diff.</p>
<p><b>Impact</b> : No clear impact or vulnerability is evident from the given diff snippet.</p>
<p><b>Fix</b> : The patch introduces a new file `matrixTestResultPlugin.ts` which seems to be part of a testing plugin for Vite&#39;s FS serve functionality. It does not introduce any known security vulnerabilities based on the provided information.</p>
<p>
<a href="https://github.com/advisories/GHSA-v2wj-q39q-566r">Advisory</a> · <a href="https://github.com/vitejs/vite/commit/a9a3df299378d9cbc5f069e3536a369f8188c8ff">Commit</a>
</p>
<hr>
<h3>GHSA-x3f4-v83f-7wp2</h3>
<p>
<code>HIGH 0.0</code> · 2026-04-06 · Go<br>
<code>github.com/authorizerdev/authorizer</code> · Pattern: <code>OPEN_REDIRECT→PHISHING</code> · 3x across ecosystem
</p>
<p><b>Root cause</b> : The application did not validate the `redirect_uri` parameter before using it to redirect users.</p>
<p><b>Impact</b> : An attacker could exploit this vulnerability to perform a phishing attack by tricking users into following malicious URLs.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before:
if params.RedirectURI != nil {
	redirectURL = *params.RedirectURI
}
After:
if !validators.IsValidOrigin(redirectURL, g.Config.AllowedOrigins) {
	log.Debug().Msg(&#34;Invalid redirect URI&#34;)
	return nil, fmt.Errorf(&#34;invalid redirect URI&#34;)
}</pre>
</details>
<p><b>Fix</b> : The patch adds validation to ensure that the `redirect_uri` is within a list of allowed origins, preventing unauthorized redirections.</p>
<p>
<a href="https://github.com/advisories/GHSA-x3f4-v83f-7wp2">Advisory</a> · <a href="https://github.com/authorizerdev/authorizer/commit/6d9bef1aaba3f867f8c769b93eb7fc80e4e7b0a2">Commit</a>
</p>
<hr>
<h3>GHSA-8j7f-g9gv-7jhc</h3>
<p>
<code>MODERATE 7.4</code> · 2026-04-10 · JavaScript<br>
<code>openclaw</code> · Pattern: <code>SSRF→INTERNAL_ACCESS</code> · 11x across ecosystem
</p>
<p><b>Root cause</b> : The code did not validate the target URL before making requests, allowing attackers to perform SSRF attacks.</p>
<p><b>Impact</b> : An attacker could use this vulnerability to access internal network resources or make unauthorized requests to other servers.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before:
const fetchImpl = params.fetchImpl ?? fetch;

After:
const externalFetchImpl = params.fetchImpl;
const guardedFetchImpl: typeof f</pre>
</details>
<p><b>Fix</b> : The patch introduces a guarded fetch implementation that validates the target URL before making requests, preventing SSRF attacks.</p>
<p>
<a href="https://github.com/advisories/GHSA-8j7f-g9gv-7jhc">Advisory</a> · <a href="https://github.com/openclaw/openclaw/commit/f92c92515bd439a71bd03eb1bc969c1964f17acf">Commit</a>
</p>
<hr>
<h3>GHSA-p6j4-wvmc-vx2h</h3>
<p>
<code>MODERATE 7.3</code> · 2026-04-10 · JavaScript<br>
<code>openclaw</code> · Pattern: <code>MISSING_AUTHZ→RESOURCE</code> · 9x across ecosystem
</p>
<p><b>Root cause</b> : The code does not properly check if the user has authorization to access or modify certain resources before performing operations on them.</p>
<p><b>Impact</b> : An attacker could potentially perform actions they are not authorized to do, such as accessing or modifying sensitive data.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before:
-      const citedContent = await resolveAllCites(content.content);
After:
+      // Resolve any cited/quoted messages first
+      const citedContent = await resolveAllCites(content.content);</pre>
</details>
<p><b>Fix</b> : The patch ensures that the code checks for proper authorization before performing operations on resources.</p>
<p>
<a href="https://github.com/advisories/GHSA-p6j4-wvmc-vx2h">Advisory</a> · <a href="https://github.com/openclaw/openclaw/commit/3cbf932413e41d1836cb91aed1541a28a3122f93">Commit</a>
</p>
<hr>
<h3>GHSA-wp29-qmvj-frvp</h3>
<p>
<code>MODERATE 7.3</code> · 2026-04-09 · Python<br>
<code>metagpt</code> · Pattern: <code>UNSANITIZED_INPUT→COMMAND</code> · 12x across ecosystem
</p>
<p><b>Root cause</b> : The `run_command` method directly executes user-provided commands without proper sanitization or validation.</p>
<p><b>Impact</b> : An attacker could execute arbitrary operating system commands on the server, potentially leading to unauthorized access, data theft, or system compromise.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before:
```python
await self.run_command(cmd)
```
After:
```python
def run_command(self, cmd) -&gt; str:
    # ... (rest of the method remains unchanged)</pre>
</details>
<p><b>Fix</b> : The patch introduces a background task to read output from the shell process and put it into a queue, preventing direct execution of user-provided commands.</p>
<p>
<a href="https://github.com/advisories/GHSA-wp29-qmvj-frvp">Advisory</a> · <a href="https://github.com/paipeline/MetaGPT/commit/d04ffc8dc67903e8b327f78ec121df5e190ffc7b">Commit</a>
</p>
<hr>
<h3>GHSA-99j8-wv67-4c72</h3>
<p>
<code>MODERATE 6.8</code> · 2026-04-10 · Go<br>
<code>github.com/aiven/aiven-operator</code> · Pattern: <code>UNCLASSIFIED</code> · 32x across ecosystem
</p>
<p><b>Root cause</b> : The code did not validate the namespace of the secret source, allowing cross-namespace secret exfiltration.</p>
<p><b>Impact</b> : An attacker could read secrets from any namespace on the cluster, potentially exposing sensitive information.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">Before:
- sourceNamespace := secretSource.Namespace
- if sourceNamespace == &#34;&#34; {
-     sourceNamespace = resource.GetNamespace()
- }
After:
+ ns := resource.GetNamespace()</pre>
</details>
<p><b>Fix</b> : The patch restricts the secret source to the same namespace as the resource, preventing cross-namespace access.</p>
<p>
<a href="https://github.com/advisories/GHSA-99j8-wv67-4c72">Advisory</a> · <a href="https://github.com/aiven/aiven-operator/commit/032c9ba63257fdd2fddfb7f73f71830e371ff182">Commit</a>
</p>
<hr>
<h3>GHSA-2j53-2c28-g9v2</h3>
<p>
<code>MODERATE 6.5</code> · 2026-04-10 · JavaScript<br>
<code>openclaw</code> · Pattern: <code>UNCLASSIFIED</code> · 32x across ecosystem
</p>
<p><b>Root cause</b> : The code does not enforce sender policy checks before allowing expensive cryptographic operations.</p>
<p><b>Impact</b> : An attacker could trigger unauthenticated crypto work, potentially leading to resource exhaustion or other security issues.</p>
<details>
<summary>Diff</summary>
<pre lang="diff">{&#34;before&#34;: &#34;-    reply: (text: string) =&gt; Promise&lt;void&gt;,\n+    meta: { eventId: string; createdAt: number },\n+  ) =&gt; Promise&lt;void&gt;;&#34;, &#34;after&#34;: &#34;+  /** Called before expensive crypto to allow sender policy checks (optional) */\n+  authorizeSender?: (params: {\n+    senderPubkey: string;\n+    reply: (text: string) =&gt; Promise&lt;void&gt;;\n+  }) =&gt; Promise&lt;&#39;allow&#39; | &#39;block&#39; | &#39;pairing&#39;&gt;;&#34;}</pre>
</details>
<p><b>Fix</b> : The patch introduces a new `authorizeSender` function that allows for sender policy checks before performing expensive cryptographic operations.</p>
<p>
<a href="https://github.com/advisories/GHSA-2j53-2c28-g9v2">Advisory</a> · <a href="https://github.com/openclaw/openclaw/commit/1ee9611079e81b9122f4bed01abb3d9f56206c77">Commit</a>
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
             Map to closed taxonomy of 29 normalized pattern IDs
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
<tr><td>Total advisories</td><td>134</td></tr>
<tr><td>Unique patterns</td><td>29</td></tr>
<tr><td>Pending</td><td>0</td></tr>
<tr><td>Last updated</td><td>2026-04-13</td></tr>
</table>
</details>
<hr>
<sub><a href="https://christbowel.com">christbowel.com</a></sub>
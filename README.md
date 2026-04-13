<div align="center">

# 🎣 Open Source Daily Catch

**Automated Patch Intelligence for Security Engineers**

[![Analysis](https://github.com/christbowel/osdc/actions/workflows/daily.yml/badge.svg)](https://github.com/christbowel/osdc/actions/workflows/daily.yml)
[![Render](https://github.com/christbowel/osdc/actions/workflows/render.yml/badge.svg)](https://github.com/christbowel/osdc/actions/workflows/render.yml)

`134` advisories · `29` unique vuln patterns · updated 3x/day

[Live index](https://christbowel.github.io/OSDC) · [How it works](#how-it-works)

</div>

---

<table><tr><td>

**GHSA-9cp7-j3f8-p5jx** · `CRITICAL 10.0` · 2026-04-10

`github.com/daptin/daptin` · Go · Pattern: `PATH_TRAVERSAL→FILE_WRITE` · 10x across ecosystem

**Root cause** : The application allowed user-supplied filenames and archive entry names to be used directly in file system operations (e.g., `filepath.Join`, `os.OpenFile`, `os.MkdirAll`) without sufficient sanitization. This enabled attackers to manipulate file paths using `../` sequences or absolute paths.

**Impact** : An unauthenticated attacker could write arbitrary files to arbitrary locations on the server's file system, potentially leading to remote code execution, data corruption, or denial of service. In the case of Zip Slip, files within an uploaded archive could be extracted outside the intended directory.

<pre lang="diff">```diff
--- a/server/asset_upload_handler.go
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
 		if !ok || dbResource == nil {
```</pre>

**Fix** : The patch introduces robust path sanitization by using `filepath.Clean` and then iteratively stripping any leading `..` components from user-supplied filenames and archive entry names. This ensures that all file system operations are constrained to the intended directories.

[Advisory](https://github.com/advisories/GHSA-9cp7-j3f8-p5jx) · [Commit](https://github.com/daptin/daptin/commit/8d626bbb14f82160a08cbca53e0749f475f5742c)

</td></tr></table>

<table><tr><td>

**GHSA-fvcv-3m26-pcqx** · `CRITICAL 10.0` · 2026-04-10

`axios` · JavaScript · Pattern: `UNSANITIZED_INPUT→HEADER` · 1x across ecosystem

**Root cause** : The Axios library did not properly sanitize header values, allowing newline characters (CRLF) to be injected. This meant that an attacker could append arbitrary headers or even inject a new HTTP request body by including these characters in a user-controlled header value.

**Impact** : An attacker could inject arbitrary HTTP headers, potentially leading to SSRF (Server-Side Request Forgery) against cloud metadata endpoints or other internal services, and could also manipulate the request body.

<pre lang="diff">```diff
--- a/lib/core/AxiosHeaders.js
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
     }
```</pre>

**Fix** : The patch introduces a `isValidHeaderValue` function to explicitly check for and disallow newline characters (CRLF) in header values. It also adds an `assertValidHeaderValue` function to enforce this validation before header values are set, preventing header injection.

[Advisory](https://github.com/advisories/GHSA-fvcv-3m26-pcqx) · [Commit](https://github.com/axios/axios/commit/363185461b90b1b78845dc8a99a1f103d9b122a1)

</td></tr></table>

<table><tr><td>

**GHSA-jmrh-xmgh-x9j4** · `CRITICAL 9.8` · 2026-04-06

`changedetection.io` · Python · Pattern: `MISSING_AUTH→ENDPOINT` · 5x across ecosystem

**Root cause** : The `login_optionally_required` decorator was moved above the route decorators, allowing unauthenticated access to routes that should be protected.

**Impact** : An attacker could bypass authentication and perform actions they are not authorized to do, such as downloading backups or removing backup files.

<pre lang="diff">Before:
-    @login_optionally_required
    @backups_blueprint.route(&#34;/request-backup&#34;, methods=[&#39;GET&#39;])
After:
+    @backups_blueprint.route(&#34;/request-backup&#34;, methods=[&#39;GET&#39;])
+    @login_optionally_required</pre>

**Fix** : Moved the `login_optionally_required` decorator below all route decorators to ensure proper authentication checks.

[Advisory](https://github.com/advisories/GHSA-jmrh-xmgh-x9j4) · [Commit](https://github.com/dgtlmoon/changedetection.io/commit/31a760c2147e3e73a403baf6d7de34dc50429c85)

</td></tr></table>

<table><tr><td>

**GHSA-8wrq-fv5f-pfp2** · `CRITICAL 9.6` · 2026-04-10

`lollms` · Python · Pattern: `UNSANITIZED_INPUT→XSS` · 6x across ecosystem

**Root cause** : The application did not properly sanitize user-supplied content before storing it in the database and later rendering it. This allowed attackers to inject malicious scripts into posts, comments, and direct messages.

**Impact** : An attacker could inject arbitrary client-side scripts, leading to session hijacking, defacement, redirection to malicious sites, or other client-side attacks against users viewing the compromised content.

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

**Fix** : The patch introduces a `sanitize_content` function using the `bleach` library to clean user input. This function is applied to all user-generated content (posts, comments, direct messages, and group conversation names) before it is stored in the database, stripping or escaping disallowed HTML tags and attributes.

[Advisory](https://github.com/advisories/GHSA-8wrq-fv5f-pfp2) · [Commit](https://github.com/parisneo/lollms/commit/9767b882dbc893c388a286856beeaead69b8292a)

</td></tr></table>

<table><tr><td>

**GHSA-65w6-pf7x-5g85** · `CRITICAL 9.4` · 2026-04-08

`@delmaredigital/payload-puck` · JavaScript · Pattern: `MISSING_AUTH→ENDPOINT` · 5x across ecosystem

**Root cause** : The endpoints were missing proper authorization checks, allowing unauthenticated access to CRUD operations on Puck-registered collections.

**Impact** : An attacker could perform any CRUD operation on the collections without authentication, potentially leading to data leakage or manipulation.

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
+        overrideAccess: false,
</pre>

**Fix** : The patch adds access control by passing `overrideAccess: false` and `req` to Payload's local API, ensuring that collection-level access rules are enforced.

[Advisory](https://github.com/advisories/GHSA-65w6-pf7x-5g85) · [Commit](https://github.com/delmaredigital/payload-puck/commit/9148201c6bbfa140d44546438027a2f8a70f79a4)

</td></tr></table>

<table><tr><td>

**GHSA-m5gr-86j6-99jp** · `CRITICAL 9.1` · 2026-04-10

`gramps-webapi` · Python · Pattern: `PATH_TRAVERSAL→FILE_WRITE` · 10x across ecosystem

**Root cause** : The application extracted files from a user-provided zip archive without validating the paths of the entries within the archive. This allowed an attacker to craft a zip file containing entries with malicious paths (e.g., `../../../../etc/passwd`) that, when extracted, would write files outside the intended temporary directory.

**Impact** : An attacker could write arbitrary files to arbitrary locations on the server's filesystem, potentially leading to remote code execution, data corruption, or denial of service.

<pre lang="diff">temp_dir_real = os.path.realpath(temp_dir)
for member in zip_file.namelist():
    member_path = os.path.realpath(os.path.join(temp_dir_real, member))
    if not member_path.startswith(temp_dir_real + os.sep):
        raise ValueError(f&#34;Zip Slip path traversal detected: {member}&#34;)</pre>

**Fix** : The patch adds a validation step before extraction. It iterates through each member of the zip file, constructs its intended extraction path, and checks if the real path of the member remains within the designated temporary directory. If a path traversal attempt is detected, an error is raised.

[Advisory](https://github.com/advisories/GHSA-m5gr-86j6-99jp) · [Commit](https://github.com/gramps-project/gramps-web-api/commit/3ed4342711e3ec849552df09b1fe2fbf2ca5c29a)

</td></tr></table>

<table><tr><td>

**GHSA-wvhv-qcqf-f3cx** · `CRITICAL 0.0` · 2026-04-10

`github.com/patrickhener/goshs` · Go · Pattern: `MISSING_AUTHZ→RESOURCE` · 9x across ecosystem

**Root cause** : The application's file-based Access Control List (ACL) mechanism, which uses '.goshs' files, was not consistently applied across all state-changing operations (delete, mkdir, put, upload). Specifically, the ACL check only looked for a '.goshs' file in the immediate directory, failing to consider ACLs defined in parent directories, and some operations lacked any ACL enforcement.

**Impact** : An attacker could bypass intended access restrictions to delete, create, or modify files and directories, including potentially sensitive ones, even if a parent directory's '.goshs' file explicitly denied such actions.

<pre lang="diff">```diff
--- a/httpserver/handler.go
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
 	}
```</pre>

**Fix** : The patch introduces a new `findEffectiveACL` function that recursively walks up the directory tree to find the nearest applicable '.goshs' ACL file. This function is now consistently used across all file and directory operations (doDir, doFile, deleteFile, handleMkdir, put, upload) to ensure proper authorization. Additionally, explicit checks were added to prevent the deletion or overwriting of '.goshs' ACL files themselves.

[Advisory](https://github.com/advisories/GHSA-wvhv-qcqf-f3cx) · [Commit](https://github.com/patrickhener/goshs/commit/f212c4f4a126556bab008f79758e21a839ef2c0f)

</td></tr></table>

<table><tr><td>

**GHSA-3p68-rc4w-qgx5** · `CRITICAL 0.0` · 2026-04-09

`axios` · JavaScript · Pattern: `SSRF→INTERNAL_ACCESS` · 11x across ecosystem

**Root cause** : The code does not properly validate or sanitize the hostname in the `no_proxy` environment variable, allowing attackers to bypass proxy settings and potentially access internal services.

**Impact** : An attacker could use this vulnerability to perform SSRF attacks, accessing internal network resources without proper authorization.

<pre lang="diff">{&#34;before&#34;: &#34;&#34;, &#34;after&#34;: &#34;+const normalizeNoProxyHost = (hostname) =&gt; {\n+  if (!hostname) {\n+    return hostname;\n+  }\n+\n+  if (hostname.charAt(0) === &#39;[&#39; &amp;&amp; hostname.charAt(hostname.length - 1) === &#39;]&#39;) {\n+    hostname = hostname.slice(1, -1);\n+  }\n+\n+  return hostname.replace(/\\.+$/, &#39;&#39;);\n+};&#34;}</pre>

**Fix** : The patch introduces a function to normalize and parse the `no_proxy` entries, ensuring that only valid hostnames are considered for bypassing proxy settings.

[Advisory](https://github.com/advisories/GHSA-3p68-rc4w-qgx5) · [Commit](https://github.com/axios/axios/commit/fb3befb6daac6cad26b2e54094d0f2d9e47f24df)

</td></tr></table>

<table><tr><td>

**GHSA-2679-6mx9-h9xc** · `CRITICAL 0.0` · 2026-04-08

`marimo` · Python · Pattern: `MISSING_AUTH→ENDPOINT` · 5x across ecosystem

**Root cause** : The WebSocket endpoint was not properly authenticated before processing requests.

**Impact** : An attacker could bypass authentication and execute arbitrary code on the server.

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

**Fix** : Added a validation step to check for proper authentication before allowing WebSocket connections.

[Advisory](https://github.com/advisories/GHSA-2679-6mx9-h9xc) · [Commit](https://github.com/marimo-team/marimo/commit/c24d4806398f30be6b12acd6c60d1d7c68cfd12a)

</td></tr></table>

<table><tr><td>

**GHSA-2cqq-rpvq-g5qj** · `CRITICAL 0.0` · 2026-04-07

`org.openidentityplatform.openam:openam` · Java · Pattern: `DESERIALIZATION→RCE` · 2x across ecosystem

**Root cause** : The code uses `ObjectInputStream` to deserialize data without proper validation or sanitization, allowing an attacker to execute arbitrary code.

**Impact** : An attacker could exploit this vulnerability to execute arbitrary code on the server, potentially leading to full control of the system.

<pre lang="diff">Before:
- ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
After:
+ if (data.startsWith(&#34;com.sun.identity&#34;)) {
+     ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
+ } else {
+     throw new SecurityException(&#34;Invalid class name in deserialized data&#34;);
+ }
</pre>

**Fix** : The patch adds a check for the class name during deserialization to prevent untrusted objects from being deserialized.

[Advisory](https://github.com/advisories/GHSA-2cqq-rpvq-g5qj) · [Commit](https://github.com/OpenIdentityPlatform/OpenAM/commit/014007c63cacc834cc795a89fac0e611aebc4a32)

</td></tr></table>

<table><tr><td>

**GHSA-jvff-x2qm-6286** · `HIGH 8.8` · 2026-04-10

`mathjs` · JavaScript · Pattern: `UNCLASSIFIED` · 32x across ecosystem

**Root cause** : The code did not validate that the index parameter was an array, allowing attackers to manipulate object attributes improperly.

**Impact** : An attacker could potentially modify or delete arbitrary properties of objects, leading to unauthorized data manipulation or loss.

<pre lang="diff">Before:
if (!Array.isArray(array)) { throw new Error(&#39;Array expected&#39;) }

After:
if (!Array.isArray(index)) {
  throw new Error(&#39;Array expected for index&#39;)
}</pre>

**Fix** : The patch ensures that the index parameter is always treated as an array, preventing improper modifications of object attributes.

[Advisory](https://github.com/advisories/GHSA-jvff-x2qm-6286) · [Commit](https://github.com/josdejong/mathjs/commit/0aee2f61866e35ffa0aef915221cdf6b026ffdd4)

</td></tr></table>

<table><tr><td>

**GHSA-5gfj-64gh-mgmw** · `HIGH 8.8` · 2026-04-08

`agixt` · Python · Pattern: `PATH_TRAVERSAL→FILE_READ` · 10x across ecosystem

**Root cause** : The `safe_join` function did not properly validate the resolved path to ensure it stayed within the agent's WORKING_DIRECTORY.

**Impact** : An attacker could exploit this vulnerability to read or write files outside of the intended directory, potentially leading to unauthorized access or data corruption.

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

**Fix** : The patch uses `os.path.realpath` to resolve symlinks and relative paths, and then checks if the resolved path is within the agent's WORKING_DIRECTORY. If not, it raises a `PermissionError`.

[Advisory](https://github.com/advisories/GHSA-5gfj-64gh-mgmw) · [Commit](https://github.com/Josh-XT/AGiXT/commit/2079ea5a88fa671a921bf0b5eba887a5a1b73d5f)

</td></tr></table>

<table><tr><td>

**GHSA-qxpc-96fq-wwmg** · `HIGH 8.8` · 2026-04-07

`org.apache.cassandra:cassandra-all` · Java · Pattern: `PRIVILEGE_ESCALATION→ROLE` · 1x across ecosystem

**Root cause** : The patch fails to properly validate the user's permissions before allowing them to drop an identity, potentially escalating their privileges.

**Impact** : An attacker could exploit this vulnerability to escalate their privileges within the Cassandra environment by dropping identities and assuming roles they are not authorized to.

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

**Fix** : The patch adds checks to ensure that only users with appropriate permissions can drop identities. It verifies that the user has permission to drop the target role before allowing the operation.

[Advisory](https://github.com/advisories/GHSA-qxpc-96fq-wwmg) · [Commit](https://github.com/apache/cassandra/commit/b584a435970e5125e1def5148d943c39569dc7af)

</td></tr></table>

<table><tr><td>

**GHSA-chqc-8p9q-pq6q** · `HIGH 8.6` · 2026-04-08

`basic-ftp` · JavaScript · Pattern: `UNSANITIZED_INPUT→COMMAND` · 12x across ecosystem

**Root cause** : The code did not sanitize input for control characters, allowing attackers to inject CRLF sequences that could manipulate FTP commands.

**Impact** : An attacker could use this vulnerability to execute arbitrary FTP commands on the server, potentially leading to unauthorized access or data manipulation.

<pre lang="diff">Before:
if (!path.startsWith(&#34; &#34;)) {
    return path
}
After:
if (/[\r\n\0]/.test(path)) {
    throw new Error(&#34;Invalid path: Contains control characters&#34;);
}</pre>

**Fix** : The patch adds a regex check to reject paths containing control characters, preventing command injection attacks.

[Advisory](https://github.com/advisories/GHSA-chqc-8p9q-pq6q) · [Commit](https://github.com/patrickjuchli/basic-ftp/commit/2ecc8e2c500c5234115f06fd1dbde1aa03d70f4b)

</td></tr></table>

<table><tr><td>

**GHSA-4ggg-h7ph-26qr** · `HIGH 8.5` · 2026-04-08

`n8n-mcp` · JavaScript · Pattern: `SSRF→INTERNAL_ACCESS` · 11x across ecosystem

**Root cause** : The code did not properly sanitize the `instance-URL` header, allowing attackers to perform SSRF attacks.

**Impact** : An attacker could use this vulnerability to access internal resources or perform actions on behalf of other users within the same network.

<pre lang="diff">{&#34;before&#34;: &#34;this.baseUrl = baseUrl;&#34;, &#34;after&#34;: &#34;let normalizedBase: string;\ntry {\n  const parsed = new URL(baseUrl);\n  parsed.hash = &#39;&#39;;\n  parsed.username = &#39;&#39;;\n  parsed.password = &#39;&#39;;\n  normalizedBase = parsed.toString().replace(//$/, &#39;&#39;);\n} catch {\n  // Unparseable input falls through to raw; downstream axios call will\n  // fail cleanly. Preserves backward compat for tests that pass\n  // placeholder strings.\n  normalizedBase = baseUrl;\n}\nthis.baseUrl = normalizedBase;&#34;}</pre>

**Fix** : The patch normalizes the `baseUrl` by removing any embedded credentials and ensuring it does not end with a trailing slash, enhancing defense-in-depth against SSRF attacks.

[Advisory](https://github.com/advisories/GHSA-4ggg-h7ph-26qr) · [Commit](https://github.com/czlonkowski/n8n-mcp/commit/d9d847f230923d96e0857ccecf3a4dedcc9b0096)

</td></tr></table>

<table><tr><td>

**GHSA-75hx-xj24-mqrw** · `HIGH 8.2` · 2026-04-10

`n8n-mcp` · JavaScript · Pattern: `MISSING_AUTH→ENDPOINT` · 5x across ecosystem

**Root cause** : The code did not handle authentication errors securely, potentially revealing sensitive information in error messages.

**Impact** : An attacker could exploit this vulnerability to gain insights into the system's internal workings and potentially identify valid usernames or other sensitive data.

<pre lang="diff">Before:
-    next();

After:
+    const authLimiter = rateLimit({ ... });
+    app.use(authLimiter);
+    // Root endpoint with API information
+    app.get(&#39;/&#39;, (req, res) =&gt; { ... };</pre>

**Fix** : The patch introduces rate limiting for authentication endpoints to prevent brute force attacks and DoS. It also enhances error handling to avoid revealing sensitive information in error messages.

[Advisory](https://github.com/advisories/GHSA-75hx-xj24-mqrw) · [Commit](https://github.com/czlonkowski/n8n-mcp/commit/ca9d4b3df6419b8338983be98f7940400f78bde3)

</td></tr></table>

<table><tr><td>

**GHSA-6v7q-wjvx-w8wg** · `HIGH 8.2` · 2026-04-10

`basic-ftp` · JavaScript · Pattern: `UNSANITIZED_INPUT→COMMAND` · 12x across ecosystem

**Root cause** : The code did not properly sanitize input for FTP commands, allowing control characters to be injected.

**Impact** : An attacker could execute arbitrary FTP commands using credentials and MKD commands due to the lack of proper input validation.

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

**Fix** : The patch added a regex check to reject any command containing control characters, preventing injection attacks.

[Advisory](https://github.com/advisories/GHSA-6v7q-wjvx-w8wg) · [Commit](https://github.com/patrickjuchli/basic-ftp/commit/20327d35126e57e5fdbaae79a4b65222fbadc53c)

</td></tr></table>

<table><tr><td>

**GHSA-hc36-c89j-5f4j** · `HIGH 8.1` · 2026-04-09

`bsv-wallet` · Ruby · Pattern: `MISSING_VERIFICATION→SIGNATURE` · 5x across ecosystem

**Root cause** : The code did not verify the certifier signatures before persisting them.

**Impact** : An attacker could potentially bypass security checks by providing unverified signatures, leading to unauthorized access or manipulation of data.

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

**Fix** : The patch adds verification for certifier signatures, ensuring that only valid signatures are persisted.

[Advisory](https://github.com/advisories/GHSA-hc36-c89j-5f4j) · [Commit](https://github.com/sgbett/bsv-ruby-sdk/commit/4992e8a265fd914a7eeb0405c69d1ff0122a84cc)

</td></tr></table>

<table><tr><td>

**GHSA-2943-crp8-38xx** · `HIGH 7.7` · 2026-04-10

`github.com/patrickhener/goshs` · Go · Pattern: `PATH_TRAVERSAL→FILE_WRITE` · 10x across ecosystem

**Root cause** : The code directly used the target path from the SFTP request without sanitization, allowing attackers to write files in arbitrary locations on the server.

**Impact** : An attacker could use this vulnerability to overwrite or create files on the server, potentially leading to data loss, unauthorized access, or further exploitation of the system.

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

**Fix** : The patch introduced a path sanitization function `sanitizePath` to ensure that only valid paths are used for file operations, preventing directory traversal attacks.

[Advisory](https://github.com/advisories/GHSA-2943-crp8-38xx) · [Commit](https://github.com/patrickhener/goshs/commit/141c188ce270ffbec087844a50e5e695b7da7744)

</td></tr></table>

<table><tr><td>

**GHSA-hwqh-2684-54fc** · `HIGH 7.5` · 2026-04-10

`org.springframework.cloud:spring-cloud-gateway` · Java · Pattern: `UNCLASSIFIED` · 32x across ecosystem

**Root cause** : The original code did not properly validate the length of the SSL bundle string before checking if it exists in the bundles list.

**Impact** : An attacker could provide a maliciously crafted SSL bundle name that bypasses the validation, potentially leading to unauthorized access or other security issues.

<pre lang="diff">Before:
- if (ssl.getSslBundle() == null || ssl.getSslBundle().length() &gt; 0) {
-     return null;
}
After:
+ if (ssl.getSslBundle() != null &amp;&amp; ssl.getSslBundle().length() &gt; 0 &amp;&amp; bundles.getBundleNames().contains(ssl.getSslBundle())) {</pre>

**Fix** : The patch ensures that the SSL bundle name is not empty and is present in the bundles list before returning it.

[Advisory](https://github.com/advisories/GHSA-hwqh-2684-54fc) · [Commit](https://github.com/spring-cloud/spring-cloud-gateway/commit/84009f2ee421e2191f8cc32ce3a84e7fc09e305e)

</td></tr></table>

<table><tr><td>

**GHSA-9hfr-gw99-8rhx** · `HIGH 7.5` · 2026-04-09

`bsv-sdk` · Ruby · Pattern: `MISSING_AUTHZ→RESOURCE` · 9x across ecosystem

**Root cause** : The code did not properly handle responses indicating that a transaction was not accepted, leading to the treatment of INVALID/MALFORMED/ORPHAN responses as successful broadcasts.

**Impact** : An attacker could potentially treat invalid or malformed transactions as successful, allowing for unauthorized use of resources or manipulation of the system.

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

**Fix** : The patch adds support for additional rejected statuses and includes a substring match for orphan detection in txStatus or extraInfo fields. It also introduces optional parameters for deployment ID, callback URL, and callback token to enhance security.

[Advisory](https://github.com/advisories/GHSA-9hfr-gw99-8rhx) · [Commit](https://github.com/sgbett/bsv-ruby-sdk/commit/4992e8a265fd914a7eeb0405c69d1ff0122a84cc)

</td></tr></table>

<table><tr><td>

**GHSA-mh2q-q3fh-2475** · `HIGH 7.5` · 2026-04-07

`go.opentelemetry.io/otel/propagation` · Go · Pattern: `UNCLASSIFIED` · 32x across ecosystem

**Root cause** : The code did not properly limit the number of members or bytes in the baggage header, leading to excessive allocations and potential denial-of-service amplification.

**Impact** : An attacker could cause the application to allocate an excessive amount of memory by sending a large number of small baggage headers. This could lead to resource exhaustion and potentially crash the application.

<pre lang="diff">Before:
- maxMembers = 180
- maxBytesPerMembers = 4096
After:
+ maxMembers = 64</pre>

**Fix** : The patch limits the maximum number of members in the baggage header to 64, reducing the risk of excessive allocations and potential denial-of-service amplification.

[Advisory](https://github.com/advisories/GHSA-mh2q-q3fh-2475) · [Commit](https://github.com/open-telemetry/opentelemetry-go/commit/aa1894e09e3fe66860c7885cb40f98901b35277f)

</td></tr></table>

<table><tr><td>

**GHSA-h6rj-3m53-887h** · `HIGH 7.5` · 2026-04-06

`pocketmine/pocketmine-mp` · PHP · Pattern: `UNCLASSIFIED` · 32x across ecosystem

**Root cause** : The code directly logs the value of an unknown property without sanitizing it.

**Impact** : An attacker could potentially log sensitive information or cause a denial of service by crafting a malicious packet with large complex properties.

<pre lang="diff">Before:
- var_export($value, return: true)
After:
+ Utils::printable(substr($name, 0, 80))</pre>

**Fix** : The patch uses a utility function to print only a portion of the property name, preventing potential log injection and excessive logging.

[Advisory](https://github.com/advisories/GHSA-h6rj-3m53-887h) · [Commit](https://github.com/pmmp/PocketMine-MP/commit/87d1c0cea09d972fd4c2fafb84dac2ecab7649f0)

</td></tr></table>

<table><tr><td>

**GHSA-hv3w-m4g2-5x77** · `HIGH 7.5` · 2026-04-06

`strawberry-graphql` · Python · Pattern: `DOS→RESOURCE_EXHAUSTION` · 4x across ecosystem

**Root cause** : The code did not limit the number of WebSocket subscriptions per connection, allowing an attacker to create an unbounded number of subscriptions.

**Impact** : An attacker could cause a denial of service by establishing an excessive number of WebSocket connections and subscriptions, exhausting server resources.

<pre lang="diff">Added `max_subscriptions_per_connection: int | None = None` in the constructor.

Added check `if not self.connection_acknowledged:` before handling a subscription to ensure the connection is authorized.

Added logic to clean up existing operations with the same ID to prevent task leaks.</pre>

**Fix** : The patch introduces a `max_subscriptions_per_connection` parameter to limit the number of subscriptions per connection, preventing resource exhaustion.

[Advisory](https://github.com/advisories/GHSA-hv3w-m4g2-5x77) · [Commit](https://github.com/strawberry-graphql/strawberry/commit/0977a4e6b41b7cfe3e9d8ba84a43458a2b0c54c2)

</td></tr></table>

<table><tr><td>

**GHSA-vpwc-v33q-mq89** · `HIGH 7.5` · 2026-04-06

`strawberry-graphql` · Python · Pattern: `UNCLASSIFIED` · 32x across ecosystem

**Root cause** : The patch adds a new parameter `max_subscriptions_per_connection` but does not enforce any authentication or authorization checks.

**Impact** : An attacker could bypass the authentication mechanism and establish multiple subscriptions on a single connection, potentially leading to resource exhaustion or other unauthorized access issues.

<pre lang="diff">diff --git a/strawberry/subscriptions/protocols/graphql_ws/handlers.py b/strawberry/subscriptions/protocols/graphql_ws/handlers.py
index 21979ff23d..e0bbc18052 100644
--- a/strawberry/subscriptions/protocols/graphql_ws/handlers.py
+++ b/strawberry/subscriptions/protocols/graphql_ws/handlers.py
@@ -119,6 +122,8 @@ async def handle_connection_init(self, message: ConnectionInitMessage) -&gt; None:
                 {</pre>

**Fix** : The patch should include proper authentication and authorization checks to ensure that only authenticated users can initiate connections and handle subscriptions.

[Advisory](https://github.com/advisories/GHSA-vpwc-v33q-mq89) · [Commit](https://github.com/strawberry-graphql/strawberry/commit/0977a4e6b41b7cfe3e9d8ba84a43458a2b0c54c2)

</td></tr></table>

<table><tr><td>

**GHSA-f2g3-hh2r-cwgc** · `HIGH 7.5` · 2026-04-06

`github.com/distribution/distribution` · Go · Pattern: `UNCLASSIFIED` · 32x across ecosystem

**Root cause** : The code did not properly validate or sanitize input when interacting with the Redis cache.

**Impact** : An attacker could potentially manipulate the Redis cache to access stale blob data, leading to unauthorized access or data corruption.

<pre lang="diff">Before:
- member, err := rsrbds.upstream.pool.SIsMember(ctx, rsrbds.repositoryBlobSetKey(rsrbds.repo), dgst.String()).Result()
After:
+ pool := rsrbds.upstream.pool
+ member, err := pool.SIsMember(ctx, rsrbds.repositoryBlobSetKey(rsrbds.repo), dgst.String()).Result()</pre>

**Fix** : The patch ensures that the Redis pool is used consistently and correctly for all operations, preventing potential misuse of the cache.

[Advisory](https://github.com/advisories/GHSA-f2g3-hh2r-cwgc) · [Commit](https://github.com/distribution/distribution/commit/078b0783f239b4115d1a979e66f08832084e9d1d)

</td></tr></table>

<table><tr><td>

**GHSA-3p65-76g6-3w7r** · `HIGH 7.5` · 2026-04-06

`github.com/distribution/distribution` · Go · Pattern: `SSRF→INTERNAL_ACCESS` · 11x across ecosystem

**Root cause** : The code did not validate the 'realm' parameter in the 'WWW-Authenticate' header, allowing attackers to perform SSRF attacks by manipulating the realm value.

**Impact** : An attacker could use this vulnerability to access internal resources or services that are not supposed to be accessible from outside the network.

<pre lang="diff">Before:
	if strings.EqualFold(c.Scheme, &#34;bearer&#34;) {
After:
	if strings.EqualFold(c.Scheme, &#34;bearer&#34;) &amp;&amp; realmAllowed(remote, c.Parameters[&#34;realm&#34;]) {</pre>

**Fix** : The patch introduces a function `realmAllowed` that checks if the 'realm' parameter is allowed based on the remote URL, preventing attackers from manipulating the realm value for SSRF attacks.

[Advisory](https://github.com/advisories/GHSA-3p65-76g6-3w7r) · [Commit](https://github.com/distribution/distribution/commit/cc5d5fa4ba02157501e6afa2cc6a903ad0338e7b)

</td></tr></table>

<table><tr><td>

**GHSA-8jvc-mcx6-r4cg** · `HIGH 7.4` · 2026-04-10

`code.vikunja.io/api` · Go · Pattern: `UNCLASSIFIED` · 32x across ecosystem

**Root cause** : The OIDC login path did not enforce TOTP Two-Factor Authentication for all users, allowing bypass of the authentication mechanism.

**Impact** : An attacker could log in to the system without providing a valid TOTP passcode, potentially gaining unauthorized access to user accounts.

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

**Fix** : The patch adds a form that requires users to provide a TOTP passcode before being authenticated via OIDC. This ensures that TOTP Two-Factor Authentication is enforced for all users attempting to log in through the OIDC path.

[Advisory](https://github.com/advisories/GHSA-8jvc-mcx6-r4cg) · [Commit](https://github.com/go-vikunja/vikunja/commit/b642b2a4536a3846e627a78dce2fdd1be425e6a1)

</td></tr></table>

<table><tr><td>

**GHSA-jfwg-rxf3-p7r9** · `HIGH 7.3` · 2026-04-06

`github.com/authorizerdev/authorizer` · Go · Pattern: `UNSANITIZED_INPUT→NOSQL` · 1x across ecosystem

**Root cause** : The code uses `fmt.Sprintf` for string interpolation to construct SQL queries, which can lead to CQL/N1QL injection if user input is not properly sanitized.

**Impact** : An attacker could execute arbitrary CQL/N1QL commands on the database, potentially leading to data theft, unauthorized access, or other malicious activities.

<pre lang="diff">Before:
values := fmt.Sprintf(&#34;&#39;%s&#39;,&#34;, value.(string))

After:
placeholders += &#34;?,&#34;
insertValues = append(insertValues, value)</pre>

**Fix** : The patch converts map values to appropriate types and uses parameterized queries with placeholders to prevent SQL injection.

[Advisory](https://github.com/advisories/GHSA-jfwg-rxf3-p7r9) · [Commit](https://github.com/authorizerdev/authorizer/commit/73679faa53cd215c7524d651046e402c43809786)

</td></tr></table>

<table><tr><td>

**GHSA-pg8g-f2hf-x82m** · `HIGH 6.5` · 2026-04-09

`openclaw` · JavaScript · Pattern: `SSRF→INTERNAL_ACCESS` · 11x across ecosystem

**Root cause** : The original code did not properly sanitize or validate the request body before sending it across cross-origin redirects.

**Impact** : An attacker could exploit this vulnerability to perform SSRF attacks, potentially gaining access to internal resources or leaking sensitive information.

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

**Fix** : The patch ensures that the request body is sanitized and validated before being sent across cross-origin redirects, mitigating the risk of SSRF vulnerabilities.

[Advisory](https://github.com/advisories/GHSA-pg8g-f2hf-x82m) · [Commit](https://github.com/openclaw/openclaw/commit/d7c3210cd6f5fdfdc1beff4c9541673e814354d5)

</td></tr></table>

<table><tr><td>

**GHSA-q5jf-9vfq-h4h7** · `HIGH 0.0` · 2026-04-10

`helm.sh/helm/v4` · Go · Pattern: `MISSING_VERIFICATION→SIGNATURE` · 5x across ecosystem

**Root cause** : The plugin installation process did not check for the presence of a .prov file, allowing unsigned plugins to be installed without verification.

**Impact** : An attacker could install and execute unsigned plugins, potentially gaining unauthorized access or executing malicious code on the system.

<pre lang="diff">Before:
- fmt.Fprintf(os.Stderr, &#34;WARNING: No provenance file found for plugin. Plugin is not signed and cannot be verified.\n&#34;)
After:
+ return nil, fmt.Errorf(&#34;plugin verification failed: no provenance file (.prov) found&#34;)</pre>

**Fix** : The patch ensures that an error is returned if no .prov file is found during plugin installation, preventing the installation of unsigned plugins.

[Advisory](https://github.com/advisories/GHSA-q5jf-9vfq-h4h7) · [Commit](https://github.com/helm/helm/commit/05fa37973dc9e42b76e1d2883494c87174b6074f)

</td></tr></table>

<table><tr><td>

**GHSA-vmx8-mqv2-9gmg** · `HIGH 0.0` · 2026-04-10

`helm.sh/helm/v4` · Go · Pattern: `PATH_TRAVERSAL→FILE_WRITE` · 10x across ecosystem

**Root cause** : The code did not validate the plugin version format, allowing an attacker to write files outside the Helm plugin directory.

**Impact** : An attacker could potentially overwrite or create arbitrary files on the server with the privileges of the user running Helm.

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

**Fix** : The patch adds a validation function for the plugin version using semantic versioning, ensuring that only valid versions can be used.

[Advisory](https://github.com/advisories/GHSA-vmx8-mqv2-9gmg) · [Commit](https://github.com/helm/helm/commit/36c8539e99bc42d7aef9b87d136254662d04f027)

</td></tr></table>

<table><tr><td>

**GHSA-qx8j-g322-qj6m** · `HIGH 0.0` · 2026-04-09

`openclaw` · JavaScript · Pattern: `SSRF→INTERNAL_ACCESS` · 11x across ecosystem

**Root cause** : The original code did not properly sanitize or validate the request body before replaying it across cross-origin redirects.

**Impact** : An attacker could use this vulnerability to perform SSRF attacks, potentially accessing internal resources or leaking sensitive information.

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

**Fix** : The patch ensures that the pinned hostname is resolved correctly and used in the dispatcher creation process, preventing unsafe request bodies from being replayed across cross-origin redirects.

[Advisory](https://github.com/advisories/GHSA-qx8j-g322-qj6m) · [Commit](https://github.com/openclaw/openclaw/commit/d7c3210cd6f5fdfdc1beff4c9541673e814354d5)

</td></tr></table>

<table><tr><td>

**GHSA-h749-fxx7-pwpg** · `HIGH 0.0` · 2026-04-09

`github.com/minio/minio` · Go · Pattern: `DOS→RESOURCE_EXHAUSTION` · 4x across ecosystem

**Root cause** : The code does not properly validate or limit the size of the input data for S3 Select CSV parsing, leading to an unbounded memory allocation.

**Impact** : An attacker could cause a Denial of Service (DoS) by sending specially crafted requests that trigger excessive memory usage on the server.

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

**Fix** : The patch adds validation and limits on the size of the input data for S3 Select CSV parsing, preventing unbounded memory allocation.

[Advisory](https://github.com/advisories/GHSA-h749-fxx7-pwpg) · [Commit](https://github.com/minio/minio/commit/7c14cdb60e53dbfdad2be644dfb180cab19fffa7)

</td></tr></table>

<table><tr><td>

**GHSA-7437-7hg8-frrw** · `HIGH 0.0` · 2026-04-09

`openclaw` · JavaScript · Pattern: `UNSANITIZED_INPUT→COMMAND` · 12x across ecosystem

**Root cause** : The code did not properly sanitize or denylist certain environment variables that could be used for command injection.

**Impact** : An attacker could inject malicious commands into the build environment, potentially leading to remote code execution (RCE).

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

**Fix** : The patch ensures that critical environment variables like HGRCPATH, CARGO_BUILD_RUSTC_WRAPPER, RUSTC_WRAPPER, and MAKEFLAGS are properly sanitized or denied from being used in the build process.

[Advisory](https://github.com/advisories/GHSA-7437-7hg8-frrw) · [Commit](https://github.com/openclaw/openclaw/commit/d7c3210cd6f5fdfdc1beff4c9541673e814354d5)

</td></tr></table>

<table><tr><td>

**GHSA-hwr4-mq23-wcv5** · `HIGH 0.0` · 2026-04-08

`github.com/dunglas/mercure` · Go · Pattern: `UNCLASSIFIED` · 32x across ecosystem

**Root cause** : The patch does not address a security vulnerability but rather refactors the configuration structure for Topic Selector Cache.

**Impact** : This change does not impact the security of the application; it is purely an internal refactor.

<pre lang="diff">Before:
- maxEntriesPerShard := mercure.DefaultTopicSelectorStoreCacheMaxEntriesPerShard
- shardCount := mercure.DefaultTopicSelectorStoreCacheShardCount
After:
+ cacheSize := mercure.DefaultTopicSelectorStoreCacheSize
+ switch {
+ case m.TopicSelectorCache.Size &gt; 0:
+ cacheSize = m.TopicSelectorCache.Size</pre>

**Fix** : Refactor the cache configuration to use a single 'Size' field instead of deprecated 'MaxEntriesPerShard' and 'ShardCount'.

[Advisory](https://github.com/advisories/GHSA-hwr4-mq23-wcv5) · [Commit](https://github.com/dunglas/mercure/commit/4964a69be904fd61e35b5f1e691271663b6fdd64)

</td></tr></table>

<table><tr><td>

**GHSA-jpcj-7wfg-mqxv** · `HIGH 0.0` · 2026-04-08

`stata-mcp` · Python · Pattern: `UNSANITIZED_INPUT→COMMAND` · 12x across ecosystem

**Root cause** : The code did not validate user-supplied Stata do-file content, allowing the execution of shell-escape directives like `!cmd` or `shell cmd`.

**Impact** : An attacker could execute arbitrary operating system commands on the server, leading to potential data loss, privilege escalation, or other malicious activities.

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

**Fix** : The patch introduced a security guard that checks for and rejects Stata shell-escape directives to prevent OS command execution.

[Advisory](https://github.com/advisories/GHSA-jpcj-7wfg-mqxv) · [Commit](https://github.com/SepineTam/stata-mcp/commit/52413ce)

</td></tr></table>

<table><tr><td>

**GHSA-h259-74h5-4rh9** · `HIGH 0.0` · 2026-04-08

`org.xwiki.platform:xwiki-platform-legacy-oldcore` · Java · Pattern: `UNCLASSIFIED` · 32x across ecosystem

**Root cause** : The code did not properly sanitize or escape user input when rendering Velocity templates.

**Impact** : An attacker could inject malicious scripts into the application, leading to potential data theft, session hijacking, or other attacks.

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
      * &lt;p&gt;
</pre>

**Fix** : The patch adds a check to ensure that only users with programming rights can access the underlying request object, which enforces security checks.

[Advisory](https://github.com/advisories/GHSA-h259-74h5-4rh9) · [Commit](https://github.com/xwiki/xwiki-platform/commit/9fe84da66184c05953df9466cf3a4acd15a46e63)

</td></tr></table>

<table><tr><td>

**GHSA-qmwh-9m9c-h36m** · `HIGH 0.0` · 2026-04-07

`github.com/gotenberg/gotenberg/v8` · Go · Pattern: `PATH_TRAVERSAL→FILE_WRITE` · 10x across ecosystem

**Root cause** : The original code did not properly sanitize user-supplied metadata, allowing attackers to bypass intended restrictions and write arbitrary files using tags like HardLink and SymLink.

**Impact** : An attacker could create hard links or symbolic links to arbitrary files on the server, potentially leading to unauthorized access or data corruption.

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

**Fix** : The patch adds case-insensitive comparison for dangerous tags to prevent attackers from bypassing the intended restrictions. It also ensures that only safe metadata is written by removing any user-supplied tags that could trigger file operations like renaming, moving, or linking.

[Advisory](https://github.com/advisories/GHSA-qmwh-9m9c-h36m) · [Commit](https://github.com/gotenberg/gotenberg/commit/15050a311b73d76d8b9223bafe7fa7ba71240011)

</td></tr></table>

<table><tr><td>

**GHSA-fmwg-qcqh-m992** · `HIGH 0.0` · 2026-04-07

`github.com/gotenberg/gotenberg/v8` · Go · Pattern: `UNSANITIZED_INPUT→REGEX` · 3x across ecosystem

**Root cause** : The code did not set a timeout for the regex pattern matching, allowing attackers to exploit a ReDoS vulnerability.

**Impact** : An attacker could cause a denial of service by sending a malicious request with a large or complex input that causes the regex engine to consume excessive resources.

<pre lang="diff">Before:
scopeRegexp = p
After:
scopeRegexp = p
p.MatchTimeout = 5 * time.Second</pre>

**Fix** : The patch sets a timeout of 5 seconds for the regex pattern matching, mitigating the risk of ReDoS attacks.

[Advisory](https://github.com/advisories/GHSA-fmwg-qcqh-m992) · [Commit](https://github.com/gotenberg/gotenberg/commit/cfb48d9af48cb236244eabe5c67fe1d30fb3fe25)

</td></tr></table>

<table><tr><td>

**GHSA-vfw7-6rhc-6xxg** · `HIGH 0.0` · 2026-04-07

`openclaw` · JavaScript · Pattern: `UNSANITIZED_INPUT→COMMAND` · 12x across ecosystem

**Root cause** : The code directly used environment variables from the backend configuration without sanitizing them.

**Impact** : An attacker could inject malicious commands into the environment, potentially leading to arbitrary command execution on the server.

<pre lang="diff">Before:
const next = { ...process.env, ...backend.env };

After:
const next = sanitizeHostExecEnv({
  baseEnv: process.env,
  overrides: backend.env,
  blockPathOverrides: true,
});</pre>

**Fix** : The patch introduces a function `sanitizeHostExecEnv` that ensures environment variables are sanitized before being used in the command execution context.

[Advisory](https://github.com/advisories/GHSA-vfw7-6rhc-6xxg) · [Commit](https://github.com/openclaw/openclaw/commit/c2fb7f1948c3226732a630256b5179a60664ec24)

</td></tr></table>

<table><tr><td>

**GHSA-788v-5pfp-93ff** · `HIGH 0.0` · 2026-04-06

`pocketmine/pocketmine-mp` · PHP · Pattern: `UNCLASSIFIED` · 32x across ecosystem

**Root cause** : The application did not limit the size of JSON data it could decode, allowing attackers to send extremely large payloads that could consume excessive memory or cause denial of service.

**Impact** : An attacker could cause a denial of service by sending a very large JSON payload, potentially crashing the server or consuming all available memory.

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
}
```</pre>

**Fix** : The patch introduces a maximum size limit for JSON form response data and throws an exception if the received data exceeds this limit before attempting to decode it. This prevents excessive memory consumption and potential DoS attacks.

[Advisory](https://github.com/advisories/GHSA-788v-5pfp-93ff) · [Commit](https://github.com/pmmp/PocketMine-MP/commit/cef1088341e40ee7a6fa079bca47a84f3524d877)

</td></tr></table>

<table><tr><td>

**GHSA-v2wj-q39q-566r** · `HIGH 0.0` · 2026-04-06

`vite` · JavaScript · Pattern: `UNCLASSIFIED` · 32x across ecosystem

**Root cause** : The code does not appear to directly address a known security vulnerability based on the provided diff.

**Impact** : No clear impact or vulnerability is evident from the given diff snippet.


**Fix** : The patch introduces a new file `matrixTestResultPlugin.ts` which seems to be part of a testing plugin for Vite's FS serve functionality. It does not introduce any known security vulnerabilities based on the provided information.

[Advisory](https://github.com/advisories/GHSA-v2wj-q39q-566r) · [Commit](https://github.com/vitejs/vite/commit/a9a3df299378d9cbc5f069e3536a369f8188c8ff)

</td></tr></table>

<table><tr><td>

**GHSA-p9ff-h696-f583** · `HIGH 0.0` · 2026-04-06

`vite` · JavaScript · Pattern: `PATH_TRAVERSAL→FILE_READ` · 10x across ecosystem

**Root cause** : The code did not properly sanitize the input `id` before using it to access files, allowing an attacker to read arbitrary files on the server.

**Impact** : An attacker could potentially read sensitive files on the server, such as configuration files or source code, which could lead to further exploitation or data leakage.

<pre lang="diff">Before:
if (options.allowId &amp;&amp; !options.allowId(id)) {

After:
if (
  !options.skipFsCheck &amp;&amp;
  id[0] !== &#39;\u0000&#39; &amp;&amp;
isServerAccessDeniedForTransform(config, id)
) {</pre>

**Fix** : The patch introduced a check to ensure that the `id` does not start with ' ' and calls a new function `isServerAccessDeniedForTransform` to verify if access is allowed for the given `id`. This prevents attackers from reading arbitrary files.

[Advisory](https://github.com/advisories/GHSA-p9ff-h696-f583) · [Commit](https://github.com/vitejs/vite/commit/f02d9fde0b195afe3ea2944414186962fbbe41e0)

</td></tr></table>

<table><tr><td>

**GHSA-x3f4-v83f-7wp2** · `HIGH 0.0` · 2026-04-06

`github.com/authorizerdev/authorizer` · Go · Pattern: `OPEN_REDIRECT→PHISHING` · 3x across ecosystem

**Root cause** : The application did not validate the `redirect_uri` parameter before using it to redirect users.

**Impact** : An attacker could exploit this vulnerability to perform a phishing attack by tricking users into following malicious URLs.

<pre lang="diff">Before:
if params.RedirectURI != nil {
	redirectURL = *params.RedirectURI
}
After:
if !validators.IsValidOrigin(redirectURL, g.Config.AllowedOrigins) {
	log.Debug().Msg(&#34;Invalid redirect URI&#34;)
	return nil, fmt.Errorf(&#34;invalid redirect URI&#34;)
}</pre>

**Fix** : The patch adds validation to ensure that the `redirect_uri` is within a list of allowed origins, preventing unauthorized redirections.

[Advisory](https://github.com/advisories/GHSA-x3f4-v83f-7wp2) · [Commit](https://github.com/authorizerdev/authorizer/commit/6d9bef1aaba3f867f8c769b93eb7fc80e4e7b0a2)

</td></tr></table>

<table><tr><td>

**GHSA-8j7f-g9gv-7jhc** · `MODERATE 7.4` · 2026-04-10

`openclaw` · JavaScript · Pattern: `SSRF→INTERNAL_ACCESS` · 11x across ecosystem

**Root cause** : The code did not validate the target URL before making requests, allowing attackers to perform SSRF attacks.

**Impact** : An attacker could use this vulnerability to access internal network resources or make unauthorized requests to other servers.

<pre lang="diff">Before:
const fetchImpl = params.fetchImpl ?? fetch;

After:
const externalFetchImpl = params.fetchImpl;
const guardedFetchImpl: typeof f</pre>

**Fix** : The patch introduces a guarded fetch implementation that validates the target URL before making requests, preventing SSRF attacks.

[Advisory](https://github.com/advisories/GHSA-8j7f-g9gv-7jhc) · [Commit](https://github.com/openclaw/openclaw/commit/f92c92515bd439a71bd03eb1bc969c1964f17acf)

</td></tr></table>

<table><tr><td>

**GHSA-p6j4-wvmc-vx2h** · `MODERATE 7.3` · 2026-04-10

`openclaw` · JavaScript · Pattern: `MISSING_AUTHZ→RESOURCE` · 9x across ecosystem

**Root cause** : The code does not properly check if the user has authorization to access or modify certain resources before performing operations on them.

**Impact** : An attacker could potentially perform actions they are not authorized to do, such as accessing or modifying sensitive data.

<pre lang="diff">Before:
-      const citedContent = await resolveAllCites(content.content);
After:
+      // Resolve any cited/quoted messages first
+      const citedContent = await resolveAllCites(content.content);</pre>

**Fix** : The patch ensures that the code checks for proper authorization before performing operations on resources.

[Advisory](https://github.com/advisories/GHSA-p6j4-wvmc-vx2h) · [Commit](https://github.com/openclaw/openclaw/commit/3cbf932413e41d1836cb91aed1541a28a3122f93)

</td></tr></table>

<table><tr><td>

**GHSA-wp29-qmvj-frvp** · `MODERATE 7.3` · 2026-04-09

`metagpt` · Python · Pattern: `UNSANITIZED_INPUT→COMMAND` · 12x across ecosystem

**Root cause** : The `run_command` method directly executes user-provided commands without proper sanitization or validation.

**Impact** : An attacker could execute arbitrary operating system commands on the server, potentially leading to unauthorized access, data theft, or system compromise.

<pre lang="diff">Before:
```python
await self.run_command(cmd)
```
After:
```python
def run_command(self, cmd) -&gt; str:
    # ... (rest of the method remains unchanged)
```</pre>

**Fix** : The patch introduces a background task to read output from the shell process and put it into a queue, preventing direct execution of user-provided commands.

[Advisory](https://github.com/advisories/GHSA-wp29-qmvj-frvp) · [Commit](https://github.com/paipeline/MetaGPT/commit/d04ffc8dc67903e8b327f78ec121df5e190ffc7b)

</td></tr></table>

<table><tr><td>

**GHSA-99j8-wv67-4c72** · `MODERATE 6.8` · 2026-04-10

`github.com/aiven/aiven-operator` · Go · Pattern: `UNCLASSIFIED` · 32x across ecosystem

**Root cause** : The code did not validate the namespace of the secret source, allowing cross-namespace secret exfiltration.

**Impact** : An attacker could read secrets from any namespace on the cluster, potentially exposing sensitive information.

<pre lang="diff">Before:
- sourceNamespace := secretSource.Namespace
- if sourceNamespace == &#34;&#34; {
-     sourceNamespace = resource.GetNamespace()
- }
After:
+ ns := resource.GetNamespace()</pre>

**Fix** : The patch restricts the secret source to the same namespace as the resource, preventing cross-namespace access.

[Advisory](https://github.com/advisories/GHSA-99j8-wv67-4c72) · [Commit](https://github.com/aiven/aiven-operator/commit/032c9ba63257fdd2fddfb7f73f71830e371ff182)

</td></tr></table>

<table><tr><td>

**GHSA-r4fg-73rc-hhh7** · `MODERATE 6.5` · 2026-04-10

`code.vikunja.io/api` · Go · Pattern: `INTEGER_OVERFLOW→BOUNDARY` · 1x across ecosystem

**Root cause** : The code did not validate the `repeat_after` field for task repetition, allowing attackers to set extremely large values that could cause resource exhaustion.

**Impact** : An attacker could exploit this vulnerability by setting a very high value for `repeat_after`, causing the system to repeatedly perform tasks until it exhausts resources and becomes unresponsive.

<pre lang="diff">Before:

func createTask(s *xorm.Session, t *Task, a web.Auth, updateAssignees bool, setBucketIndex bool) error {
	if t.Title == &#34;&#34; {
		return ErrTaskCannotBeEmpty{}
	}

	// Check if the project exists
	p, err := GetProjectSimpleByID(s, t.ProjectID)
	if err != nil {
		return err
	}

	// ... (rest of the function) ...
}

After:

func createTask(s *xorm.Session, t *Task, a web.Auth, updateAssignees bool, setBucketIndex bool) error {
	if t.Title == &#34;&#34; {
		return ErrTaskCannotBeEmpty{}
	}

	if err := validateRepeatAfter(t.RepeatAfter); err != nil {
		return err
	}

	// Check if the project exists
	p, err := GetProjectSimpleByID(s, t.ProjectID)
	if err != nil {
		return err
	}

	// ... (rest of the function) ...
}</pre>

**Fix** : The patch introduces validation for the `repeat_after` field, ensuring it does not exceed a predefined maximum value (10 years). This prevents attackers from causing resource exhaustion through excessive task repetition.

[Advisory](https://github.com/advisories/GHSA-r4fg-73rc-hhh7) · [Commit](https://github.com/go-vikunja/vikunja/commit/6df0d6c8f54b01db6464c42810e40e55f12b481b)

</td></tr></table>


## How it works

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

Three runs per day: `06:00`, `14:00`, `23:00` UTC. Render pipeline runs independently at `07:00`, `15:00`, `00:00` UTC.

<details>
<summary>Stack</summary>

| Component | Tech | Notes |
|-----------|------|-------|
| Automation | GitHub Actions cron | Zero infra |
| Data source | GitHub Advisory DB | GraphQL, filtered on patch commits |
| LLM | Gemini 2.5 Flash | Free tier, JSON-only output |
| DB | SQLite (rebuilt from JSONL) | Git-friendly, versioned |
| Frontend | Static HTML | Client-side search, zero build step |
| Scripting | Python 3.11 | requests, jinja2, sqlite3 |

</details>

<details>
<summary>Stats</summary>

| Metric | Value |
|--------|-------|
| Total advisories | 134 |
| Unique patterns | 29 |
| Pending | 0 |
| Last updated | 2026-04-13 |

</details>

---

*[christbowel.com](https://christbowel.com)*
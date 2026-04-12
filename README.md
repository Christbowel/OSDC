<div align="center">

# 🎣 Open Source Daily Catch

**Automated Patch Intelligence for Security Engineers**

[![Analysis](https://github.com/christbowel/osdc/actions/workflows/daily.yml/badge.svg)](https://github.com/christbowel/osdc/actions/workflows/daily.yml)
[![Render](https://github.com/christbowel/osdc/actions/workflows/render.yml/badge.svg)](https://github.com/christbowel/osdc/actions/workflows/render.yml)

`5` advisories · `4` unique vuln patterns · updated 3x/day

[Live index](https://christbowel.github.io/OSDC) · [How it works](#how-it-works)

</div>

---

<table><tr><td>

**GHSA-9cp7-j3f8-p5jx** · `CRITICAL 10.0` · 2026-04-10

`github.com/daptin/daptin` · Go · Pattern: `PATH_TRAVERSAL→FILE_WRITE` · 2x across ecosystem

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

**GHSA-8wrq-fv5f-pfp2** · `CRITICAL 9.6` · 2026-04-10

`lollms` · Python · Pattern: `UNSANITIZED_INPUT→XSS` · 1x across ecosystem

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

**GHSA-m5gr-86j6-99jp** · `CRITICAL 9.1` · 2026-04-10

`gramps-webapi` · Python · Pattern: `PATH_TRAVERSAL→FILE_WRITE` · 2x across ecosystem

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

`github.com/patrickhener/goshs` · Go · Pattern: `MISSING_AUTHZ→RESOURCE` · 1x across ecosystem

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
             Map to closed taxonomy of 4 normalized pattern IDs
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
| Total advisories | 5 |
| Unique patterns | 4 |
| Pending | 0 |
| Last updated | 2026-04-12 |

</details>

---

*[christbowel.com](https://christbowel.com)*
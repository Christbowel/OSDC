<div align="center">

# 🎣 Open Source Daily Catch

**Automated Patch Intelligence — what got fixed in open source today, and why it matters**

[![Analysis](https://github.com/christbowel/osdc/actions/workflows/daily.yml/badge.svg)](https://github.com/christbowel/osdc/actions/workflows/daily.yml)

5 advisories analyzed · 4 unique patterns tracked

[Browse all patches →](https://christbowel.github.io/osdc)

</div>

---

### GHSA-9cp7-j3f8-p5jx · github.com/daptin/daptin

📅 2026-04-10 · Go · **CRITICAL** 10.0 · Pattern: `PATH_TRAVERSAL→FILE_WRITE` · 2x seen

**Root cause** — The application allowed user-supplied filenames and archive entry names to be used directly in file system operations (e.g., `filepath.Join`, `os.OpenFile`, `os.MkdirAll`) without sufficient sanitization. This enabled attackers to manipulate file paths using `../` sequences or absolute paths.

**Impact** — An unauthenticated attacker could write arbitrary files to arbitrary locations on the server's file system, potentially leading to remote code execution, data corruption, or denial of service. In the case of Zip Slip, files within an uploaded archive could be extracted outside the intended directory.

```diff
```diff
--- a/server/asset_upload_handler.go
+++ b/server/asset_upload_handler.go
@@ -67,6 +67,13 @@ func AssetUploadHandler(cruds map[string]*resource.DbResource) func(c *gin.Conte
 			c.AbortWithError(400, errors.New("filename query parameter is required"))
 			return
 		}
+		// Strip path traversal from filename
+		if fileName != "" {
+			fileName = filepath.Clean(fileName)
+			for strings.HasPrefix(fileName, "..") {
+				fileName = strings.TrimPrefix(strings.TrimPrefix(fileName, ".."), string(filepath.Separator))
+			}
+		}
 		// Validate table and column
 		dbResource, ok := cruds[typeName]
 		if !ok || dbResource == nil {
```
```

**Fix** — The patch introduces robust path sanitization by using `filepath.Clean` and then iteratively stripping any leading `..` components from user-supplied filenames and archive entry names. This ensures that all file system operations are constrained to the intended directories.

🔗 [Advisory](https://github.com/advisories/GHSA-9cp7-j3f8-p5jx) · [Commit](https://github.com/daptin/daptin/commit/8d626bbb14f82160a08cbca53e0749f475f5742c)

---

### GHSA-fvcv-3m26-pcqx · axios

📅 2026-04-10 · JavaScript · **CRITICAL** 10.0 · Pattern: `UNSANITIZED_INPUT→HEADER` · 1x seen

**Root cause** — The Axios library did not properly sanitize header values, allowing newline characters (CRLF) to be injected. This meant that an attacker could append arbitrary headers or even inject a new HTTP request body by including these characters in a user-controlled header value.

**Impact** — An attacker could inject arbitrary HTTP headers, potentially leading to SSRF (Server-Side Request Forgery) against cloud metadata endpoints or other internal services, and could also manipulate the request body.

```diff
```diff
--- a/lib/core/AxiosHeaders.js
+++ b/lib/core/AxiosHeaders.js
@@ -5,18 +5,49 @@ import parseHeaders from '../helpers/parseHeaders.js';
 
 const $internals = Symbol('internals');
 
+const isValidHeaderValue = (value) => !/[
]/.test(value);
+
+function assertValidHeaderValue(value, header) {
+  if (value === false || value == null) {
+    return;
+  }
+
+  if (utils.isArray(value)) {
+    value.forEach((v) => assertValidHeaderValue(v, header));
+    return;
+  }
+
+  if (!isValidHeaderValue(String(value))) {
+    throw new Error(`Invalid character in header content ["${header}"]`);
+  }
+}
 
 function normalizeValue(value) {
   if (value === false || value == null) {
     return value;
   }
 
-  return utils.isArray(value)
-    ? value.map(normalizeValue)
-    : String(value).replace(/[
]+$/, '');
+  return utils.isArray(value) ? value.map(normalizeValue) : stripTrailingCRLF(String(value));
 }
 
 function parseTokens(str) {
@@ -98,6 +129,7 @@ class AxiosHeaders {
         _rewrite === true ||
         (_rewrite === undefined && self[key] !== false)
       ) {
+        assertValidHeaderValue(_value, _header);
         self[key || _header] = normalizeValue(_value);
       }
     }
```
```

**Fix** — The patch introduces a `isValidHeaderValue` function to explicitly check for and disallow newline characters (CRLF) in header values. It also adds an `assertValidHeaderValue` function to enforce this validation before header values are set, preventing header injection.

🔗 [Advisory](https://github.com/advisories/GHSA-fvcv-3m26-pcqx) · [Commit](https://github.com/axios/axios/commit/363185461b90b1b78845dc8a99a1f103d9b122a1)

---

### GHSA-8wrq-fv5f-pfp2 · lollms

📅 2026-04-10 · Python · **CRITICAL** 9.6 · Pattern: `UNSANITIZED_INPUT→XSS` · 1x seen

**Root cause** — The application did not properly sanitize user-supplied content before storing it in the database and later rendering it. This allowed attackers to inject malicious scripts into posts, comments, and direct messages.

**Impact** — An attacker could inject arbitrary client-side scripts, leading to session hijacking, defacement, redirection to malicious sites, or other client-side attacks against users viewing the compromised content.

```diff
--- a/backend/routers/social/__init__.py
+++ b/backend/routers/social/__init__.py
@@ -149,9 +176,12 @@ def create_post(
     moderation_enabled = settings.get("ai_bot_moderation_enabled", False)
     initial_status = "pending" if moderation_enabled else "validated"
 
+    # Sanitize content to prevent Stored XSS
+    clean_content = sanitize_content(post_data.content)
+
     new_post = DBPost(
         author_id=current_user.id,
-        content=post_data.content,
+        content=clean_content,
         visibility=post_data.visibility,
```

**Fix** — The patch introduces a `sanitize_content` function using the `bleach` library to clean user input. This function is applied to all user-generated content (posts, comments, direct messages, and group conversation names) before it is stored in the database, stripping or escaping disallowed HTML tags and attributes.

🔗 [Advisory](https://github.com/advisories/GHSA-8wrq-fv5f-pfp2) · [Commit](https://github.com/parisneo/lollms/commit/9767b882dbc893c388a286856beeaead69b8292a)

---

### GHSA-m5gr-86j6-99jp · gramps-webapi

📅 2026-04-10 · Python · **CRITICAL** 9.1 · Pattern: `PATH_TRAVERSAL→FILE_WRITE` · 2x seen

**Root cause** — The application extracted files from a user-provided zip archive without validating the paths of the entries within the archive. This allowed an attacker to craft a zip file containing entries with malicious paths (e.g., `../../../../etc/passwd`) that, when extracted, would write files outside the intended temporary directory.

**Impact** — An attacker could write arbitrary files to arbitrary locations on the server's filesystem, potentially leading to remote code execution, data corruption, or denial of service.

```diff
temp_dir_real = os.path.realpath(temp_dir)
for member in zip_file.namelist():
    member_path = os.path.realpath(os.path.join(temp_dir_real, member))
    if not member_path.startswith(temp_dir_real + os.sep):
        raise ValueError(f"Zip Slip path traversal detected: {member}")
```

**Fix** — The patch adds a validation step before extraction. It iterates through each member of the zip file, constructs its intended extraction path, and checks if the real path of the member remains within the designated temporary directory. If a path traversal attempt is detected, an error is raised.

🔗 [Advisory](https://github.com/advisories/GHSA-m5gr-86j6-99jp) · [Commit](https://github.com/gramps-project/gramps-web-api/commit/3ed4342711e3ec849552df09b1fe2fbf2ca5c29a)

---

### GHSA-wvhv-qcqf-f3cx · github.com/patrickhener/goshs

📅 2026-04-10 · Go · **CRITICAL** 0.0 · Pattern: `MISSING_AUTHZ→RESOURCE` · 1x seen

**Root cause** — The application's file-based Access Control List (ACL) mechanism, which uses '.goshs' files, was not consistently applied across all state-changing operations (delete, mkdir, put, upload). Specifically, the ACL check only looked for a '.goshs' file in the immediate directory, failing to consider ACLs defined in parent directories, and some operations lacked any ACL enforcement.

**Impact** — An attacker could bypass intended access restrictions to delete, create, or modify files and directories, including potentially sensitive ones, even if a parent directory's '.goshs' file explicitly denied such actions.

```diff
```diff
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
 		logger.Errorf("error reading file based access config: %+v", err)
 	}
```
```

**Fix** — The patch introduces a new `findEffectiveACL` function that recursively walks up the directory tree to find the nearest applicable '.goshs' ACL file. This function is now consistently used across all file and directory operations (doDir, doFile, deleteFile, handleMkdir, put, upload) to ensure proper authorization. Additionally, explicit checks were added to prevent the deletion or overwriting of '.goshs' ACL files themselves.

🔗 [Advisory](https://github.com/advisories/GHSA-wvhv-qcqf-f3cx) · [Commit](https://github.com/patrickhener/goshs/commit/f212c4f4a126556bab008f79758e21a839ef2c0f)

---


<details>
<summary>📊 Stats</summary>

| Metric | Value |
|--------|-------|
| Total advisories | 5 |
| Unique patterns | 4 |
| Pending analysis | 0 |
| Last updated | 2026-04-12 |

</details>

*Built by [Christbowel](https://christbowel.com) · [Full index](https://christbowel.github.io/osdc)*
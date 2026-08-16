=== DoLogin Security ===
Contributors: WPDO
Tags: Login security, 2FA login, Cloudflare Turnstile, limit login attempts, passwordless login
Requires at least: 4.4
Requires PHP: 5.6
Tested up to: 7.1
Stable tag: 5.0.10
License: GPLv3
License URI: http://www.gnu.org/licenses/gpl.html

Login security: KeyLockr SSO scan login, 2FA, passwordless login, Cloudflare Turnstile, GeoLocation/IP limits, whitelist and blacklist.

== Description ==

In one click, your WordPress login page will be pretected with the smart brute force attack protection! Any login attempts more than 6 in 10 minutes (default value) will be limited.

Limit the number of login attempts through both the login and the auth cookies.

* Two-factor Authentication login.

* KeyLockr SSO scan login with encrypted appdata hash verification and session-bound encryption.

* Cloudflare Turnstile (better than Google reCAPTCHA).

* GeoLocation (Continent/Country/City) or IP range to limit login attempts.

* Passwordless login link.

* Support Whitelist and Blacklist.

* GDPR compliant. With this feature turned on, all logged IPs get obfuscated (md5-hashed).

* WooCommerce Login supported.

* XMLRPC gateway protection.

= 🛡️ Security, explained simply =

🔑 **A stolen database should not become a bag of ready-to-use login secrets.**

DoLogin separates stored data from the WordPress authentication salts. If an attacker copies only the database—but does not have the salts from the site configuration—the protected values cannot be used as login links, TOTP seeds, or signing keys.

---------------------------------------

🔗 **Passwordless and child-site tokens: compare without storing the secret**

`Secret in the generated link` ➜ `salt-keyed HMAC` ➜ `database stores only the verifier`

* The raw token is shown when it is created and is never saved in the token table.
* Login recomputes the HMAC and compares it in constant time.
* A copied database verifier cannot be pasted into a URL as a working login token.
* One-time tokens are consumed with an atomic database update, so simultaneous replay attempts cannot both win.

---------------------------------------

🔐 **TOTP and signing keys: encrypted when the server must recover them**

`TOTP seed or private key` ➜ `authenticated encryption + site salt` ➜ `ciphertext in the database`

TOTP verification and digital signatures need the original secret at runtime, so these values cannot use a one-way hash. DoLogin encrypts them instead and rejects modified ciphertext. Existing TOTP seeds and Site Easy Login private keys are migrated automatically.

---------------------------------------

🏠 **Site Easy Login: one signed message, one destination, one use**

`User + trusted public key + destination + issue time + random token ID` ➜ `one Ed25519 signature`

The child site verifies the complete signed message with the public key already saved for that connection. Changing the user or destination breaks the signature, and an atomic consume step blocks replay.

---------------------------------------

📱 **KeyLockr SSO: stable signing and encryption identity**

`Scan QR` ➜ `approve on phone` ➜ `verify Safe + AppData binding` ➜ `WordPress login cookie`

* Fixed per-site signing and encryption keypairs let KeyLockr reuse the same backend-owned connection identity.
* Existing signing-only key storage is upgraded atomically with one persistent encryption keypair.
* The WordPress backend owns all private keys and KPS processing; the browser only opens the short-lived KeyLockr WebSocket and relays opaque signed, encrypted frames to the backend.
* Incoming frames are signed, encrypted, timestamp-checked, replay-checked, rate-limited, and accepted only in the expected protocol phase.
* Bind and Repair write the WordPress account hash to encrypted KeyLockr AppData, then read it back before completing.
* Login requires exactly one WordPress user with the matching Safe ID and binding hash.
* After a QR scan, the phone-unlock and approval prompt is highlighted in green so the next action is clear.

---------------------------------------

🚦 **Force KeyLockr SSO that fails closed**

`Enable force mode after a verified admin binding` ➜ `keep QR-only policy active` ➜ `never reopen older interactive login methods automatically`

DoLogin checks the current administrator binding before force mode can be enabled. After that policy is saved, a missing binding, changed App Tag, broken site identity, or unavailable KeyLockr service does not restore password, passwordless-link, connected-site, or password-reset login paths. The WordPress lost-password link and core password-reset screens are removed while force mode is active; unlinking and site-key reset are also blocked. Existing authenticated sessions can disable force mode from settings; if no session remains, rename the plugin folder through FTP or the hosting file manager before repairing the connection. WordPress Application Passwords remain available for API clients.

= API =

* Call the function `$link = function_exists( 'dologin_gen_link' ) ? dologin_gen_link( 'your plugin name or tag' ) : '';` to generate one passwordless login link for the current user.

* Call the function `$link = function_exists( 'dologin_gen_link' ) ? dologin_gen_link( 'note/tip for this generation', $user_id ) : '';` to generate a passwordless login link for the user which ID is `$user_id`.

The generated one-time used link will be expired after 7 days.

* Define const `SILENCE_INSTALL` to avoid redirecting to setting page after installtion.

= KeyLockr SSO Recovery =

Forced KeyLockr SSO blocks password, passwordless-link, and connected-site interactive logins. Existing authenticated cookies and WordPress Application Passwords remain available.

DoLogin never restores another interactive login method because KeyLockr is unavailable or the saved binding becomes invalid. Use an existing authenticated administrator session to disable force mode. If no such session remains, rename the plugin folder through FTP or the hosting file manager, then repair the connection before enabling force mode again.

= CLI =

* List all passwordless links: `wp dologin list`

* Generate a passwordless link for one username (for the login name `root`): `wp dologin gen root`

* Delete a passwordless link w/ the ID in list (for the record w/ ID 5): `wp dologin del 5`

= How GeoLocation works =

When visitors hit the login page, this plugin will lookup the Geolocation info from API, compare the Geolocation setting (if has) with the whitelist/blacklist to decide if allow login attempts.

== Privacy ==

The online IP lookup service is provided by https://www.doapi.us. The provider's privacy policy is https://www.doapi.us/privacy.

Based on the original code from Limit Login Attemps plugin and Limit Login Attemps Reloaded plugin.

== Screenshots ==

1. Plugin Site Connections
2. Plugin Settings
3. Plugin Passwordless Login
4. Plugin Login Attempts Log
5. Login Page (KeyLockr SSO QR login)
6. Login Page (2 times left)
7. Login Page (Too many failure)
8. Login Page (Blacklist blocked)
9. WooCommerce login protection

== Changelog ==

= 5.0.10 - Aug 15 2026 =
* 🍀 Added verified same-device KeyLockr login, simplified MyDeveloper guidance, and reduced login-page assets.
* 🔐 Hardened KeyLockr SSO, 2FA replay cleanup, and uninstall data removal.
* 🔐 Made only KeyLockr authorization denials and account-identity mismatches consume login retries, preventing protocol or transport errors from locking out an IP.
* 🐞 Fixed stale same-device returns, WooCommerce forced-login flashes, token-error pages, and login-log feedback.

= 4.8.3 - Jul 28 2026 =
* 🐞 Kept valid KeyLockr site-key blobs read-only and limited storage migration to signing-only blobs, preventing avoidable login failures when no key material needs an upgrade.
* 🔐 Restored a fixed per-site KeyLockr encryption keypair and atomically upgraded signing-only storage so repeated QR logins reuse the same backend-owned encryption identity.
* 🐞 Stopped passive visits to the WordPress login page from being counted as failed login attempts while Force KeyLockr SSO is enabled.
* 🍀 Highlighted the post-scan KeyLockr unlock and approval prompt in green so users can see that the next action is on their phone.
* 🔐 Removed lost-password links across supported WordPress versions and blocked both new and pre-issued password-reset keys across core and third-party reset flows while Force KeyLockr SSO keeps username/password login disabled.

= 4.7.7 - Jul 22 2026 =
* 🍀 Made the login-page KeyLockr sign-in start on demand with clear DoLogin branding and a KeyLockr reference link, instead of opening a connection on every login-page visit.
* 🔐 Protected passwordless and site-connection tokens with salt-keyed HMAC verifiers, and encrypted TOTP and Site Easy Login private keys at rest.
* 🐞 Fixed an upgrade fatal error by waiting until WordPress salt APIs are available before running migrations.
* 🔐 Added and hardened KeyLockr SSO QR login with reusable site identity, secure account linking and repair, encrypted AppData verification, bounded decoding, rate-limited replay-resistant sessions, validated redirects, and fail-closed forced login that never restores older interactive methods automatically.
* 🔐 Fixed Site Easy Login assertion tampering and replay by signing the user, public key, destination, issuance time, and token ID together, then atomically consuming each assertion.
* 🔐 Hardened 2FA and token login by failing closed when a forced 2FA secret is missing, enforcing lockouts, binding confirmation nonces, and atomically consuming replay state.
* 🐞 Fixed IPv4/IPv6 allow/deny matching, settings return behavior, deleted-user handling, and multisite table provisioning.
* 🔐 Restricted companion-plugin installation and protected GeoIP and Turnstile requests while reducing unnecessary external traffic.
* 🧹 Removed legacy SMS login, the obsolete mobile-number profile field, and the SMS database table.

= 4.4 - Jul 6 2026 =
* 🐞 Security: Fixed an authentication bypass via insufficient randomness in passwordless and site-connection login tokens (CVE-2026-14495). Login tokens and SMS codes are now generated with a cryptographically secure random source.
* 🐞 Security: Fixed an unauthenticated stored XSS in the Login Attempts log, dashboard widget, and Site Connections tables. All output is now escaped.
* 🐞 Security: The per-IP failure limit is now enforced on the passwordless and easy-login endpoints; token comparison is constant-time.
* 🐞 Security: Enabled TLS verification on outbound API calls, validated the site-connection URL (SSRF), switched to safe redirects, and added a no-referrer policy on the passwordless confirmation page to prevent token leakage.
* 🐞 Cloudflare Turnstile no longer blocks XML-RPC authentication, which cannot present a captcha and is already covered by the login attempt limiter.
* Declared WooCommerce HPOS (High-Performance Order Storage) compatibility.

= 4.3 - Jun 11 2025 =
* Generating passwordless link will redirect to the corresponding tab now.

= 4.2 - May 31 2025 =
* 🍀 Cloudflare Turnstile reCAPTCHA.
* 🐞 Fixed 2FA conflict w/ reCAPTCHA.

= 4.1.1 - May 27 2025 =
* Resolved WooCommerce HPOS feature warning.

= 4.1 - May 27 2025 =
* Showed the easy login confirmation landing page.
* Disallowed reuse of login link to prevent possible replay attack.
* Fixed root site pk/sk clear issue in easy login when saving conf.
* Restored reCAPTCHA to previous version.

= 4.0 - May 26 2025 =
* 🍀 `Easy Login` feature! Allow one root WordPress to easy login to multi child WordPress sites.

= 3.8 =
* Security patch per patchstack report.

= 3.7.1 =
* IP vulnerability patch for dashboard widget. (Bob@Jetpack)

= 3.7 =
* IP vulnerability patch. (Bob@Jetpack)

= 3.6 =
* Fixed Google reCAPTCHA authentication failure. (mandotr)

= 3.5.2 =
* Fixed auto upgrade PHP warning. (lavacano)

= 3.5.1 =
* Banner to install qrcode plugin to enable 2FA.

= 3.5 =
* 🍀 Two-factor Authentication.

= 3.4 =
* Bypassed version check to speed up WP6 loading.

= 3.3 =
* Fixed potential duration value in string conversion issue. (wpcrono)

= 3.2 =
* API `dologin_admin_menu_access` to allow other users to config dologin settings. (franfal)

= 3.1 =
* Compatibility improvement when communication failed between client wordpress and DoAPI.us API. (@matteocuellar @ecomturbo @thesaintindiano)

= 3.0 =
* 🍀 Dashboard widget.
* New API for free text message gateway.

= 2.9.4 =
* Fixed IXR_Error PHP notice for XMLRPC login failure.

= 2.9.3 =
* Support translation for login text message. (@merkwert)

= 2.9.2 =
* More accurate to detect IP.

= 2.9.1 =
* 🍀 New setting Google reCAPTCHA on Lost Password Page.

= 2.9 =
* WordPress v5.5 Rest compatibility.

= 2.8 =
* Avoid duplicated login attempt records for one IP in a short time.
* GUI enhancement.

= 2.7.1 =
* Added API info to GUI.

= 2.7 =
* Login Attempts log can be cleared now.

= 2.6 =
* Codebase reformated.

= 2.5 =
* CLI supported.

= 2.4 =
* Passwordless link can be copied in one click.

= 2.3 =
* 🍀 Reverse Matching w/ `!:` feature. Now can use `!:` to exclude one rule. (@jacklinkers)

= 2.2.2 =
* Better IP detection.
* Supported empty line and single line comments for whitelist and blacklist.

= 2.2.1 =
* Declared WooCommerce support up to 4.0.1.

= 2.2 =
* Whitelist and Blacklist support comments now.

= 2.1 =
* Passwordless login will now have a confirm page to avoid auto-visited when sharing the link.

= 2.0 =
* Fresh New GUI!

= 1.9 =
* 🍀 New option: Show reCAPTCHA on Register page. (@ach1992)

= 1.8 =
* 🍀 Show Phone Number field on Register page if Force SMS Auth setting is ON. (@ach1992)

= 1.7.1 =
* 🐞 Will now honor the timezone setting when showing date of sent. (@ducpl)

= 1.7 =
* Supported DoDebug now.
* Bypassed whitelist check for WooCommerce clients on checkout page.
* 🐞 WooCommerce checkout page can now login correctly.

= 1.6 =
* 🍀 Google reCAPTCHA.
* 🐞 WooCommerce can now use same login strategy settings.

= 1.5 =
* 🍀 Test SMS Message feature under Settings page.

= 1.4.7 =
* Language supported.

= 1.4.5 =
* PHP5.3 supported.

= 1.4.4 =
* Doc updates.

= 1.4.3 =
* *API* Silent install mode to avoid redirecting to settings by defining const `SILENCE_INSTALL`

= 1.4.2 =
* *API* Generated link defaults to expire in 7 days.

= 1.4.1 =
* *API* New function `dologin_gen_link( 'my_plugin' )` API to generate a link for current user.

= 1.4 =
* 🍀 Passwordless login link.

= 1.3.5 =
* SMS PHP Warning fix.

= 1.3.4 =
* REST warning fix.

= 1.3.3 =
* GUI cosmetic.

= 1.3.2 =
* 🐞 Fixed a bug that caused not enabled SMS WP failed to login.

= 1.3.1 =
* PHP Notice fix.

= 1.3 =
* 🍀 SMS login support.

= 1.2.2 =
* Auto redirect to setting page after activation.

= 1.2.1 =
* Doc improvement.

= 1.2 =
* 🍀 XMLRPC protection.

= 1.1.1 =
* 🐞 Auto upgrade can now check latest version correctly.

= 1.1 =
* 🍀 *New* Display login failure log.
* 🍀 *New* GDPR compliance.
* 🍀 *New* Auto upgrade.
* *GUI* Setting link shortcut from plugin page.
* *GUI* Display security status on login page.
* 🐞 Stale settings shown after successfully saved.
* 🐞 Duration setting can now be saved correctly.
* 🐞 Fully saved geo location failure log.

= 1.0 - Sep 27 2019 =
* Initial Release.

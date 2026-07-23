<?php
/**
 * Settings tab template.
 *
 * @package dologin
 */

namespace dologin;

defined( 'WPINC' ) || exit;

$dologin_gui = $this->cls( 'GUI' );

$dologin_current_user_2fa = $this->cls( 'TwoFA' )->current_status();
$dologin_kl_requirements  = KLSso::requirements();
$dologin_kl_server_ips    = KLSso::server_ips();
$dologin_kl_fingerprint   = KLSso::site_key_fingerprint();

?>
<form method="post" action="<?php echo esc_url( menu_page_url( 'dologin', false ) ); ?>" class="dologin-relative">
	<?php wp_nonce_field( 'dologin' ); ?>

	<h3 class="dologin-title-short"><?php esc_html_e( 'Limit Login Attempt Settings', 'dologin' ); ?></h3>

	<table class="wp-list-table striped dologin-table">
		<tbody>
			<tr>
				<th><?php esc_html_e( 'Lockout', 'dologin' ); ?></th>
				<td>
					<p><?php $dologin_gui->build_input( 'max_retries', 'dologin-input-short2' ); ?> <?php esc_html_e( 'Allowed retries', 'dologin' ); ?></p>
					<p><?php $dologin_gui->build_input( 'duration', 'dologin-input-short2' ); ?> <?php esc_html_e( 'minutes lockout', 'dologin' ); ?></p>
					<div class="dologin-desc">
						<?php
						echo wp_kses_post(
							sprintf(
								/* translators: 1: max retries count, 2: lockout duration in minutes. */
								__( 'If hit %1$s maximum retries in %2$s minutes, the login attempt from that IP will be temporarily disabled.', 'dologin' ),
								'<code>' . esc_html( Conf::val( 'max_retries' ) ) . '</code>',
								'<code>' . esc_html( Conf::val( 'duration' ) ) . '</code>'
							)
						);
						?>
					</div>
				</td>
			</tr>
		</tbody>
	</table>

	<h3 class="dologin-title-short"><?php esc_html_e( '2FA Settings', 'dologin' ); ?></h3>

	<table class="wp-list-table striped dologin-table">
		<tbody>
			<tr>
				<th><?php esc_html_e( 'Two-factor Authentication', 'dologin' ); ?></th>
				<td>
					<?php $dologin_gui->build_switch( '2fa' ); ?>
					<div class="dologin-desc">
						<?php esc_html_e( 'Verify 2FA code for each login attempt.', 'dologin' ); ?>
						<?php esc_html_e( 'Users need to finish 2FA validation in their profile.', 'dologin' ); ?>
						<br />
						<?php
						echo wp_kses_post(
							sprintf(
								/* translators: %s: example 2FA app name. */
								__( 'Can use any 2FA app, e.g. %s', 'dologin' ),
								'<code>Google Authenticator</code>'
							)
						);
						?>
					</div>
				</td>
			</tr>

			<tr>
				<th><?php esc_html_e( 'Force 2FA Auth Validation', 'dologin' ); ?></th>
				<td>
					<?php $dologin_gui->build_switch( '2fa_force' ); ?>
					<div class="dologin-desc">
						<?php esc_html_e( 'If enabled this, any user without 2FA setup in profile will not be able to login.', 'dologin' ); ?>
						<a href="profile.php"><?php esc_html_e( 'Click here to manage your 2FA secret', 'dologin' ); ?></a>
						<?php if ( ! $dologin_current_user_2fa && Conf::val( '2fa' ) && Conf::val( '2fa_force' ) ) : ?>
							<div class="dologin-warning-h3">
								<?php esc_html_e( 'You need to setup your 2FA before enabling this setting to avoid yourself being blocked from next time login.', 'dologin' ); ?>
							</div>
						<?php endif; ?>
					</div>
				</td>
			</tr>
		</tbody>
	</table>

	<h3 class="dologin-title-short"><?php esc_html_e( 'KeyLockr SSO Settings', 'dologin' ); ?></h3>

	<table class="wp-list-table striped dologin-table">
		<tbody>
			<tr>
				<th><?php esc_html_e( 'App Tag', 'dologin' ); ?></th>
				<td>
					<?php $dologin_gui->build_input( 'kl_sso_svc_id' ); ?>
					<div class="dologin-desc">
						<?php esc_html_e( 'Copy the effective App Tag from KeyLockr. If no custom App Tag is set, use the decimal Service ID.', 'dologin' ); ?>
					</div>
					<div class="dologin-desc dologin-kl-setup">
						<strong><?php esc_html_e( 'Quick Setup', 'dologin' ); ?></strong>
						<ol>
							<li>
								<a href="<?php echo esc_url( KLSso::DEVELOPER_ADD_URL ); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Create a KeyLockr SSO service', 'dologin' ); ?></a>.
								<?php esc_html_e( 'Keep App Data Storage enabled and add these Server IPs:', 'dologin' ); ?>
								<?php if ( $dologin_kl_server_ips ) : ?>
									<?php foreach ( $dologin_kl_server_ips as $dologin_kl_server_ip ) : ?>
										<code><?php echo esc_html( $dologin_kl_server_ip ); ?></code>
									<?php endforeach; ?>
								<?php else : ?>
									<span class="dologin-warn"><?php esc_html_e( 'Automatic detection failed. Enter this server outbound public IP in KeyLockr manually and reload in a few minutes to retry.', 'dologin' ); ?></span>
								<?php endif; ?>
							</li>
							<li><?php esc_html_e( 'Paste the effective App Tag above and save these settings.', 'dologin' ); ?></li>
							<li><?php esc_html_e( 'Link this WordPress account, enable SSO login, and test it before forcing QR-only login.', 'dologin' ); ?></li>
						</ol>
						<?php if ( $dologin_kl_requirements ) : ?>
							<div class="dologin-warning-h3">
								<?php echo esc_html( implode( ' ', $dologin_kl_requirements ) ); ?>
							</div>
						<?php endif; ?>
					</div>
					<div class="dologin-desc dologin-kl-site-keys">
						<strong><?php esc_html_e( 'Site Key Fingerprint', 'dologin' ); ?>:</strong>
						<?php if ( is_wp_error( $dologin_kl_fingerprint ) ) : ?>
							<code id="dologin-kl-site-key-fingerprint"><?php esc_html_e( 'Unavailable', 'dologin' ); ?></code>
							<span class="dologin-kl-site-key-status dologin-danger"><?php echo esc_html( $dologin_kl_fingerprint->get_error_message() ); ?></span>
						<?php else : ?>
							<code id="dologin-kl-site-key-fingerprint"><?php echo esc_html( $dologin_kl_fingerprint ); ?></code>
							<span class="dologin-kl-site-key-status" aria-live="polite"></span>
						<?php endif; ?>
						<button type="button" class="button dologin-kl-reset-keys" <?php disabled( KLSso::force_enabled() ); ?>><?php esc_html_e( 'Reset Site Keys', 'dologin' ); ?></button>
						<p><?php esc_html_e( 'The signing key keeps this WordPress site on one KeyLockr connection identity, while every handshake uses a fresh encryption key. Reset only to create a new identity; linked accounts must then pass Verify Connection or a successful SSO login.', 'dologin' ); ?></p>
						<?php if ( KLSso::force_enabled() ) : ?>
							<p class="dologin-warn"><?php esc_html_e( 'Disable Force KeyLockr SSO before resetting the site keys.', 'dologin' ); ?></p>
						<?php endif; ?>
					</div>
				</td>
			</tr>

			<tr>
				<th><?php esc_html_e( 'KeyLockr SSO Login', 'dologin' ); ?></th>
				<td>
					<?php $dologin_gui->build_switch( 'kl_sso' ); ?>
					<div class="dologin-desc">
						<?php esc_html_e( 'Show KeyLockr QR login and verify both app_verify and the encrypted appdata hash.', 'dologin' ); ?>
						<div class="dologin-kl-link">
							<strong><?php esc_html_e( 'Link Current Account', 'dologin' ); ?></strong>
							<?php $this->cls( 'KLSso' )->bind_form(); ?>
							<?php if ( empty( KLSso::current_user_status()['bound'] ) ) : ?>
								<p><?php esc_html_e( 'Unlock KeyLockr on your phone when prompted. The account is linked only after app data is written and read back successfully.', 'dologin' ); ?></p>
							<?php endif; ?>
						</div>
					</div>
				</td>
			</tr>

			<tr>
				<th><?php esc_html_e( 'Force KeyLockr SSO', 'dologin' ); ?></th>
				<td>
					<?php $dologin_gui->build_switch( 'kl_sso_force' ); ?>
					<div class="dologin-desc">
						<?php esc_html_e( 'Hide the password form and allow only KeyLockr QR login. DoLogin enables this only after the current administrator has a verified binding for the saved App Tag and site keys. Once enabled, failures never restore other login methods; rename the plugin folder through FTP or the hosting file manager if external recovery is required.', 'dologin' ); ?>
					</div>
				</td>
			</tr>
		</tbody>
	</table>

	<h3 class="dologin-title-short"><?php esc_html_e( 'reCAPTCHA Settings', 'dologin' ); ?></h3>

	<table class="wp-list-table striped dologin-table">
		<tbody>
			<tr>
				<th><?php esc_html_e( 'Cloudflare Turnstile', 'dologin' ); ?></th>
				<td>
					<?php $dologin_gui->build_switch( 'cf' ); ?>
					<div class="dologin-desc">
						<?php
						printf(
							/* translators: %s: page name where the captcha is shown. */
							esc_html__( 'This will enable reCAPTCHA on %s page.', 'dologin' ),
							esc_html__( 'Login', 'dologin' )
						);
						?>
					</div>
				</td>
			</tr>

			<tr>
				<th><?php esc_html_e( 'Cloudflare Turnstile on Register Page', 'dologin' ); ?></th>
				<td>
					<?php $dologin_gui->build_switch( 'recapt_register' ); ?>
					<div class="dologin-desc">
						<?php
						printf(
							/* translators: %s: page name where the captcha is shown. */
							esc_html__( 'This will enable reCAPTCHA on %s page.', 'dologin' ),
							esc_html__( 'Register', 'dologin' )
						);
						?>
					</div>
				</td>
			</tr>

			<!-- https://core.trac.wordpress.org/ticket/49521 -->
			<tr>
				<th><?php esc_html_e( 'Cloudflare Turnstile on Lost Password Page', 'dologin' ); ?></th>
				<td>
					<?php $dologin_gui->build_switch( 'recapt_forget' ); ?>
					<div class="dologin-desc">
						<?php
						printf(
							/* translators: %s: page name where the captcha is shown. */
							esc_html__( 'This will enable reCAPTCHA on %s page.', 'dologin' ),
							esc_html__( 'Lost Password', 'dologin' )
						);
						?>
					</div>
				</td>
			</tr>

			<tr>
				<th><?php esc_html_e( 'Cloudflare Turnstile Keys', 'dologin' ); ?></th>
				<td>
					<div class="dologin-row-flex">
						<div style="margin-right: 50px;">
							<p><label>
									<span class="dologin_text_label_prefix"><?php esc_html_e( 'Site Key', 'dologin' ); ?>:</span>
									<?php $dologin_gui->build_input( 'cf_pub_key', '' ); ?>
								</label></p>
							<p><label>
									<span class="dologin_text_label_prefix"><?php esc_html_e( 'Secret Key', 'dologin' ); ?>:</span>
									<?php $dologin_gui->build_input( 'cf_priv_key', '' ); ?>
								</label></p>
						</div>
						<div>
							<?php
							if ( Conf::val( 'cf' ) || ( Conf::val( 'cf_pub_key' ) && Conf::val( 'cf_priv_key' ) ) ) {
								$this->cls( 'Captcha' )->show();
							}
							?>
						</div>
					</div>

					<div class="dologin-desc">
						<?php
						echo wp_kses_post(
							sprintf(
								/* translators: %s: anchor tag attributes for the Cloudflare dashboard link. */
								__( '<a %s>Click here</a> to generate keys from Cloudflare Turnstile.', 'dologin' ),
								// phpcs:ignore PluginCheck.CodeAnalysis.Offloading.OffloadedContent -- Link to the Cloudflare dashboard where the user obtains their Turnstile keys.
								'href="https://dash.cloudflare.com/?to=/:account/turnstile" target="_blank"'
							)
						);
						?>
						<?php esc_html_e( 'Cloudflare Turnstile is better than Google reCAPTCHA.', 'dologin' ); ?>
					</div>
				</td>
			</tr>
		</tbody>
	</table>

	<h3 class="dologin-title-short"><?php esc_html_e( 'General Settings', 'dologin' ); ?></h3>

	<table class="wp-list-table striped dologin-table">
		<tbody>
			<tr>
				<th><?php esc_html_e( 'Whitelist', 'dologin' ); ?></th>
				<td>
					<div class="field-col">
						<?php $dologin_gui->build_textarea( 'whitelist' ); ?>
					</div>
					<div class="field-col field-col-desc">
						<div class="dologin-desc">
							<?php esc_html_e( 'Format', 'dologin' ); ?>: <code>prefix1:value1, prefix2:value2</code>.
							<?php esc_html_e( 'Both prefix and value are case insensitive.', 'dologin' ); ?>
							<?php esc_html_e( 'Spaces around comma/colon are allowed.', 'dologin' ); ?>
							<?php esc_html_e( 'One rule set per line.', 'dologin' ); ?>
						</div>
						<div class="dologin-desc">
							<?php esc_html_e( 'Prefix list', 'dologin' ); ?>: <code>ip</code>, <code><?php echo wp_kses_post( implode( '</code>, <code>', array_map( 'esc_html', IP::$PREFIX_SET ) ) ); ?></code>.
						</div>
						<div class="dologin-desc"><?php esc_html_e( 'IP prefix with colon is optional. IP value support wildcard (*).', 'dologin' ); ?></div>
						<div class="dologin-desc">
							<?php
							echo wp_kses_post(
								sprintf(
									/* translators: %s: the # comment character. */
									__( 'Use %s to append comments in the end of each line.', 'dologin' ),
									'<code>#</code>'
								)
							);
							?>
							<?php
							echo wp_kses_post(
								sprintf(
									/* translators: %s: the !: exclusion operator. */
									__( 'Use %s to exclude one value.', 'dologin' ),
									'<code>!:</code>'
								)
							);
							?>
						</div>
						<div class="dologin-desc dologin-row-flex">
							<div style="margin-right: 10px;">
								<button type="button" class="button button-primary" id="dologin_get_ip" title="<?php echo esc_attr( sprintf( /* translators: %s: the doapi.us domain. */ __( 'This will send a request to %s to get your public Geolocation info.', 'dologin' ), 'https://doapi.us' ) ); ?>"><?php esc_html_e( 'Check My Geolocation Data', 'dologin' ); ?></button>
							</div>
							<code id="dologin_mygeolocation">-</code>
						</div>
					</div>
				</td>
			</tr>

			<tr>
				<th><?php esc_html_e( 'Blacklist', 'dologin' ); ?></th>
				<td>
					<div class="field-col">
						<?php $dologin_gui->build_textarea( 'blacklist' ); ?>
					</div>
					<div class="field-col field-col-desc">
						<div class="dologin-desc">
							<?php
							echo wp_kses_post(
								sprintf(
									/* translators: %s: the Whitelist section name. */
									__( 'Same format as %s', 'dologin' ),
									'<strong>' . esc_html__( 'Whitelist', 'dologin' ) . '</strong>'
								)
							);
							?>
						</div>
						<div class="dologin-desc"><?php esc_html_e( 'Example', 'dologin' ); ?> 1) <code>ip:1.2.3.*</code></div>
						<div class="dologin-desc"><?php esc_html_e( 'Example', 'dologin' ); ?> 2) <code>42.20.*.*, continent_code: NA</code> (<?php esc_html_e( 'Dropped optional prefix', 'dologin' ); ?> <code>ip:</code>)</div>
						<div class="dologin-desc"><?php esc_html_e( 'Example', 'dologin' ); ?> 3) <code>continent: North America, country_code: US, subdivision_code: NY</code></div>
						<div class="dologin-desc"><?php esc_html_e( 'Example', 'dologin' ); ?> 4) <code>subdivision_code: NY, postal: 10001</code></div>
						<div class="dologin-desc"><?php esc_html_e( 'Example', 'dologin' ); ?> 5) <code>ip: 1.2.3.* # This is my IP</code></div>
						<div class="dologin-desc"><?php esc_html_e( 'Example', 'dologin' ); ?> 6) <code>country_code: US, ip!: 1.2.3.4</code> (<?php esc_html_e( 'Match all visitors from US except the IP 1.2.3.4', 'dologin' ); ?> )</div>
					</div>
				</td>
			</tr>

			<tr>
				<th><?php esc_html_e( 'GDPR Compliance', 'dologin' ); ?></th>
				<td>
					<?php $dologin_gui->build_switch( 'gdpr' ); ?>
					<div class="dologin-desc">
						<?php esc_html_e( 'With this feature turned on, all logged IPs get obfuscated (md5-hashed).', 'dologin' ); ?>
					</div>
				</td>
			</tr>


		</tbody>
	</table>

	<div class='dologin-top20'></div>

	<?php submit_button( __( 'Save Changes', 'dologin' ), 'primary', 'dologin-submit' ); ?>
	<?php submit_button( __( 'Save Changes', 'dologin' ), 'primary dologin-float-submit', 'dologin-float-submit' ); ?>

</form>

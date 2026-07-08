<?php
/**
 * Settings tab template.
 *
 * @package dologin
 */

namespace dologin;

defined( 'WPINC' ) || exit;

$dologin_gui = $this->cls( 'GUI' );

$dologin_current_user_phone = $this->cls( 'SMS' )->current_user_phone();
$dologin_current_user_2fa   = $this->cls( 'TwoFA' )->current_status();

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

	<h3 class="dologin-hide"><?php esc_html_e( 'Short Code Auth Settings', 'dologin' ); ?></h3>

	<table class="dologin-hide wp-list-table striped dologin-table">
		<tbody>
			<tr>
				<th><?php esc_html_e( 'Two Step SMS Auth', 'dologin' ); ?></th>
				<td>
					<?php $dologin_gui->build_switch( 'sms' ); ?>
					<div class="dologin-desc">
						<?php esc_html_e( 'Verify text code for each login attempt.', 'dologin' ); ?>
						<?php esc_html_e( 'Users need to setup the Dologin Phone number in their profile.', 'dologin' ); ?>
						<?php esc_html_e( 'The phone number need to specify the coutry calling codes.', 'dologin' ); ?>
						<?php
						echo wp_kses_post(
							sprintf(
								/* translators: %s: DoAPI.us service link. */
								__( 'Text message is sent by API from %s.', 'dologin' ),
								'<a href="https://www.doapi.us" target="_blank">DoAPI.us</a>'
							)
						);
						?>
					</div>
				</td>
			</tr>

			<tr>
				<th><?php esc_html_e( 'Force SMS Auth Validation', 'dologin' ); ?></th>
				<td>
					<?php $dologin_gui->build_switch( 'sms_force' ); ?>
					<div class="dologin-desc">
						<?php esc_html_e( 'If enabled this, any user without phone set in profile will not be able to login.', 'dologin' ); ?>
						<a href="profile.php"><?php esc_html_e( 'Click here to set your Dologin Security phone number', 'dologin' ); ?></a>
						<?php if ( ! $dologin_current_user_phone && Conf::val( 'sms' ) && Conf::val( 'sms_force' ) ) : ?>
							<div class="dologin-warning-h3">
								<?php esc_html_e( 'You need to setup your Dologin Phone number before enabling this setting to avoid yourself being blocked from next time login.', 'dologin' ); ?>
							</div>
						<?php else : ?>
					</div>
					<div class="dologin-desc">
						<button type="button" class="button button-primary" id="dologin_test_sms"><?php esc_html_e( 'Test SMS message', 'dologin' ); ?></button>
						<span id='dologin_test_sms_res'></span>
							<?php esc_html_e( 'This will send a test text message to your phone number.', 'dologin' ); ?>
					<?php endif; ?>
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

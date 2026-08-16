<?php
/**
 * KeyLockr SSO admin and login UI.
 *
 * @since 4.6.17
 * @package dologin
 */

namespace dologin;

defined( 'WPINC' ) || exit;

trait KLSso_UI {
	/**
	 * Render DoLogin and KeyLockr identity for the login-page component.
	 */
	private function login_identity() {
		?>
		<div class="dologin-kl-brand"><?php esc_html_e( 'DoLogin Security Login', 'dologin' ); ?></div>
		<div class="dologin-kl-title"><?php esc_html_e( 'KeyLockr SSO', 'dologin' ); ?></div>
		<div class="dologin-kl-www">
			<?php esc_html_e( 'Learn more about KeyLockr at', 'dologin' ); ?>
			<a href="<?php echo esc_url( self::WWW_URL ); ?>" target="_blank" rel="noopener noreferrer">keylockr.app</a>
		</div>
		<?php
	}

	/**
	 * Render the login-page QR component.
	 */
	public function login_form() {
		if ( ! self::enabled() ) {
			if ( self::force_enabled() ) {
				?>
				<div id="dologin-kl-sso" class="dologin-kl-sso dologin-kl-sso-login" data-dologin-kl-mode="login" data-dologin-kl-autostart="false">
					<?php $this->login_identity(); ?>
					<div class="dologin-kl-msg dologin-danger" aria-live="polite"><?php esc_html_e( 'KeyLockr SSO is unavailable. Forced login remains active, and other login methods are still blocked.', 'dologin' ); ?></div>
				</div>
				<?php
			}
			return;
		}
		?>
		<div id="dologin-kl-sso" class="dologin-kl-sso dologin-kl-sso-login" data-dologin-kl-mode="login" data-dologin-kl-autostart="false">
			<?php $this->login_identity(); ?>
			<div class="dologin-kl-qr" role="img" aria-label="<?php esc_attr_e( 'KeyLockr SSO QR code', 'dologin' ); ?>"></div>
			<div class="dologin-kl-msg" aria-live="polite"><?php esc_html_e( 'Start KeyLockr verification when you are ready. A QR code and secure connection are created only after you continue.', 'dologin' ); ?></div>
			<button type="button" class="button button-primary dologin-kl-refresh"><?php esc_html_e( 'Start KeyLockr Login', 'dologin' ); ?></button>
			<a class="button button-primary dologin-kl-open" hidden><?php esc_html_e( 'Open KeyLockr on This Device', 'dologin' ); ?></a>
			<span class="dologin-kl-open-note" hidden><?php esc_html_e( 'After approval, KeyLockr returns you to this page automatically.', 'dologin' ); ?></span>
		</div>
		<?php
	}

	/**
	 * Render the admin QR and status controls.
	 */
	private function pairing_panel( $status_message = '', $hidden = false, $show_start = true ) {
		$panel_class = 'dologin-kl-pairing' . ( $hidden ? ' dologin-kl-verify-panel' : '' );
		?>
		<div class="<?php echo esc_attr( $panel_class ); ?>"<?php if ( $hidden ) : ?> hidden id="dologin-kl-verify-panel"<?php endif; ?>>
			<div class="dologin-kl-qr" role="img" aria-label="<?php esc_attr_e( 'KeyLockr SSO QR code', 'dologin' ); ?>"></div>
			<div class="dologin-kl-pairing-controls">
				<?php if ( $status_message ) : ?>
					<div class="dologin-warn"><?php echo esc_html( $status_message ); ?></div>
				<?php endif; ?>
				<div class="dologin-kl-msg" aria-live="polite"></div>
				<?php if ( $show_start ) : ?>
					<button type="button" class="button button-primary dologin-kl-refresh"><?php esc_html_e( 'Start Pairing', 'dologin' ); ?></button>
				<?php endif; ?>
				<a class="button button-primary dologin-kl-open" hidden><?php esc_html_e( 'Open KeyLockr on This Device', 'dologin' ); ?></a>
				<span class="dologin-kl-open-note" hidden><?php esc_html_e( 'After approval, KeyLockr returns you to this page automatically.', 'dologin' ); ?></span>
				<?php if ( $hidden ) : ?>
					<button type="button" class="button button-primary dologin-kl-repair" hidden><?php esc_html_e( 'Repair Connection', 'dologin' ); ?></button>
				<?php endif; ?>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the admin account pairing and verification component.
	 */
	public function bind_form() {
		$status = self::current_user_status();
		if ( ! self::configured() ) {
			echo '<div class="dologin-warn">' . wp_kses_post( __( 'Enter and save the <code>KeyLockr App Tag</code> before linking an account.', 'dologin' ) ) . '</div>';
			return;
		}
		$requirements = self::requirements();
		if ( $requirements ) {
			echo '<div class="dologin-danger">' . esc_html( implode( ' ', $requirements ) ) . '</div>';
			return;
		}
		$bound = ! empty( $status['bound'] );
		$relink = $bound && ! empty( $status['app_tag_changed'] );
		?>
		<div id="dologin-kl-sso-bind" class="dologin-kl-sso dologin-kl-sso-admin" data-dologin-kl-mode="bind" data-dologin-kl-autostart="false">
			<?php if ( $bound ) : ?>
				<div class="dologin-kl-account">
					<div class="dologin-kl-account-main">
						<div class="dologin-success">
							<?php esc_html_e( 'Current account is linked to KeyLockr SSO.', 'dologin' ); ?>
							<?php if ( ! empty( $status['nickname'] ) ) : ?>
								<code class="dologin-code-break"><?php echo esc_html( $status['nickname'] ); ?></code>
							<?php endif; ?>
							<code class="dologin-code-break"><?php echo esc_html( $status['safe_id'] ); ?></code>
						</div>
						<?php if ( $relink ) : ?>
							<button type="button" class="button button-primary dologin-kl-relink" aria-controls="dologin-kl-verify-panel" aria-expanded="false"><?php esc_html_e( 'Relink Connection', 'dologin' ); ?></button>
						<?php else : ?>
							<button type="button" class="button button-primary dologin-kl-verify" aria-controls="dologin-kl-verify-panel" aria-expanded="false"><?php esc_html_e( 'Verify Connection', 'dologin' ); ?></button>
						<?php endif; ?>
					</div>
					<?php if ( ! self::force_enabled() ) : ?>
						<div class="dologin-kl-danger-actions">
							<button type="button" class="button dologin-kl-unlink"><?php esc_html_e( 'Unlink KeyLockr', 'dologin' ); ?></button>
						</div>
					<?php endif; ?>
				</div>
				<?php if ( $relink ) : ?>
					<div class="dologin-warn dologin-kl-key-note"><?php echo wp_kses_post( __( 'The <code>KeyLockr App Tag</code> changed. Select <code>Relink Connection</code> for the current <code>App Tag</code> before relying on it.', 'dologin' ) ); ?></div>
				<?php elseif ( empty( $status['key_current'] ) ) : ?>
					<div class="dologin-warn dologin-kl-key-note"><?php echo wp_kses_post( __( 'This account has not been verified with the current KeyLockr connection identity. Select <code>Verify Connection</code> before relying on it.', 'dologin' ) ); ?></div>
				<?php endif; ?>
				<?php if ( self::force_enabled() ) : ?>
					<div class="dologin-warn dologin-kl-force-note"><?php echo wp_kses_post( __( 'Disable <code>Force KeyLockr SSO</code> before unlinking this account.', 'dologin' ) ); ?></div>
				<?php endif; ?>
				<?php $this->pairing_panel( '', true, false ); ?>
			<?php else : ?>
				<?php $this->pairing_panel( __( 'Current account is not linked to KeyLockr SSO.', 'dologin' ) ); ?>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Render the binding section on the current user's profile page.
	 */
	public function profile_form( $user ) {
		if ( ! $user || (int) $user->ID !== (int) get_current_user_id() ) {
			return;
		}
		?>
		<h2><?php esc_html_e( 'KeyLockr SSO', 'dologin' ); ?></h2>
		<table class="form-table dologin-kl-profile" role="presentation">
			<tbody>
				<tr>
					<th><?php esc_html_e( 'KeyLockr SSO', 'dologin' ); ?></th>
					<td>
						<?php if ( self::configured() ) : ?>
							<?php $this->bind_form(); ?>
							<?php if ( empty( self::current_user_status()['bound'] ) ) : ?>
								<p class="description"><?php echo wp_kses_post( __( 'Select <code>Start Pairing</code>, then scan the QR code with KeyLockr; no <code>KeyLockr ID</code> needs to be entered manually.', 'dologin' ) ); ?></p>
							<?php endif; ?>
						<?php else : ?>
							<p class="description"><?php echo wp_kses_post( __( 'Ask an administrator to configure the <code>KeyLockr App Tag</code> before linking an account.', 'dologin' ) ); ?></p>
						<?php endif; ?>
					</td>
				</tr>
			</tbody>
		</table>
		<?php
	}
}

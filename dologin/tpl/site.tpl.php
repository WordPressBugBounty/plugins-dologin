<?php
/**
 * Site connections template.
 *
 * @package dologin
 */

namespace dologin;

defined( 'WPINC' ) || exit;

?>
<?php if ( KLSso::force_enabled() ) : ?>
	<div class="notice notice-warning inline"><p><?php echo wp_kses_post( __( '<code>Force KeyLockr SSO</code> is enabled. Connected-site login tokens remain manageable here but cannot be used to log in.', 'dologin' ) ); ?></p></div>
<?php endif; ?>
<form method="post" action="<?php echo esc_url( menu_page_url( 'dologin', false ) ); ?>" class="dologin-relative" id="token_form">
	<input type="hidden" name="<?php echo esc_attr( Router::ACTION ); ?>" value="<?php echo esc_attr( Router::ACTION_SITE ); ?>" />
	<input type="hidden" name="<?php echo esc_attr( Router::TYPE ); ?>" value="<?php echo esc_attr( Site::TYPE_CONNECT ); ?>" />
	<?php wp_nonce_field( 'site', Router::NONCE ); ?>

	<h3 class="dologin-title-short"><?php esc_html_e( 'Add Child Site Connection', 'dologin' ); ?></h3>

	<table class="wp-list-table striped dologin-table">
		<tbody>
			<tr>
				<th><?php esc_html_e( 'Token', 'dologin' ); ?></th>
				<td>
					<div class="dologin-textarea-recommended">
						<div>
							<textarea name='token' rows='3' cols='80' id="token_textarea"></textarea>
						</div>
						<div>
							<?php submit_button( esc_html__( 'Add Site', 'dologin' ), 'dologin-btn-success', 'dologin-submit' ); ?>
						</div>
					</div>
					<div class="dologin-desc">
						<?php esc_html_e( "Add the child site's token you want to connect to.", 'dologin' ); ?>
						<?php esc_html_e( 'This will allow you to login to other sites by one click in future.', 'dologin' ); ?><br>
						<?php if ( Conf::val( '_pk' ) ) : ?>
							<?php esc_html_e( 'Your root public key is:', 'dologin' ); ?>
							<code><?php echo esc_html( Conf::val( '_pk' ) ); ?></code>
						<?php endif; ?>
					</div>
				</td>
			</tr>
		</tbody>
	</table>
	<script>
	document.getElementById('token_textarea').addEventListener('keydown', function(event) {
	if (event.key === 'Enter' && !event.shiftKey) { // Submit on Enter, allow Shift+Enter for new line
		event.preventDefault(); // Prevent new line in textarea
		document.getElementById('token_form').submit(); // Submit the form
	}
	});
</script>
</form>

<div class="dologin-relative">
	<h3 class="dologin-title-short">
		<?php esc_html_e( 'Site Connections', 'dologin' ); ?>
	</h3>

	<div class="dologin-float-submit">
		<a href="users.php" class="button button-primary "><?php esc_html_e( 'Generate Child Site Token from Users List', 'dologin' ); ?></a>
	</div>
</div>

<table class="wp-list-table widefat striped">
	<thead>
	<tr>
		<th>#</th>
		<th><?php esc_html_e( 'Action', 'dologin' ); ?></th>
		<th><?php esc_html_e( 'Site Title', 'dologin' ); ?></th>
		<th><?php esc_html_e( 'Site URL', 'dologin' ); ?></th>
		<th><?php esc_html_e( 'Site Public Key', 'dologin' ); ?></th>
		<th><?php esc_html_e( 'Created At', 'dologin' ); ?></th>
		<th><?php esc_html_e( 'Login As', 'dologin' ); ?></th>
		<th><?php esc_html_e( 'Last Used', 'dologin' ); ?></th>
		<th><?php esc_html_e( 'Status', 'dologin' ); ?></th>
	</tr>
	</thead>
	<tbody>
	<?php $dologin_site_list = (array) $this->sites(); ?>
	<?php if ( ! $dologin_site_list ) : ?>
		<tr class="no-items">
			<td colspan="9"><?php esc_html_e( 'No list yet.', 'dologin' ); ?></td>
		</tr>
	<?php endif; ?>
	<?php foreach ( $dologin_site_list as $dologin_v ) : ?>
		<tr>
			<td><?php echo (int) $dologin_v->id; ?></td>
			<?php if ( $dologin_v->url && $dologin_v->pk ) : ?>
				<td>
					<?php if ( $dologin_v->easy_login ) : ?>
					<a href="<?php echo esc_url( $dologin_v->easy_login ); ?>" target="_blank" class="button dologin-btn-tiny dologin-btn-success" rel="noopener"><?php esc_html_e( 'Easy Login', 'dologin' ); ?></a>
					<?php else : ?>
						<?php esc_html_e( 'Root Site', 'dologin' ); ?>
					<?php endif; ?>
				</td>
				<td><?php echo esc_html( $dologin_v->title ); ?></td>
				<td><?php echo esc_url( $dologin_v->url ); ?></td>
				<td><code><?php echo esc_html( $dologin_v->pk ); ?></code></td>
			<?php elseif ( $dologin_v->_valid ) : ?>
				<td colspan="4">
					<div class="dologin-warn"><?php esc_html_e( 'The secret token was shown only when created and is not stored. Generate a new token if it was not copied.', 'dologin' ); ?></div>
				</td>
			<?php else : ?>
				<td colspan="4" class="dologin-danger">
					<?php esc_html_e( 'Token expired', 'dologin' ); ?>
				</td>
			<?php endif; ?>
			<td><?php echo esc_html( Util::readable_time( $dologin_v->dateline ) ); ?></td>
			<td>
				<div class="dologin-warn"><?php echo esc_html( strtoupper( implode( ', ', $dologin_v->roles ) ) ); ?></div>
				<div><?php echo esc_html( $dologin_v->username ); ?></div>
			</td>
			<td><?php echo $dologin_v->last_used_at ? esc_html( Util::readable_time( $dologin_v->last_used_at ) ) : '-'; ?></td>
			<td>
				<a href="<?php echo esc_url( $dologin_v->_lock_link ); ?>"><?php echo $dologin_v->active ? '<span class="dashicons dashicons-unlock"></span>' : '<span class="dashicons dashicons-lock"></span>'; ?></a>
				<?php
				if ( 1 === (int) $dologin_v->active ) :
					echo '<span style="color:green;">' . esc_html__( 'Active', 'dologin' ) . '</span>';
				else :
					echo '<span style="color:red;">' . esc_html__( 'Disabled', 'dologin' ) . '</span>';
				endif;
				?>
				<a href="<?php echo esc_url( $dologin_v->_del_link ); ?>" class="dologin-right"><span class="dashicons dashicons-dismiss"></span></a>
			</td>
		</tr>
	<?php endforeach; ?>
	</tbody>
</table>


<p class="description">
	<?php esc_html_e( 'Here you can connect child sites to allow login from a root site.', 'dologin' ); ?><br>
	<?php esc_html_e( 'This is used to easy login if you have multiple WordPress sites to manage.', 'dologin' ); ?>
</p>

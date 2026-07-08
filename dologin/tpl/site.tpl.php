<?php
/**
 * Site connections template.
 *
 * @package dologin
 */

namespace dologin;

defined( 'WPINC' ) || exit;

?>
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
	<?php foreach ( $this->sites() as $dologin_v ) : ?>
		<tr>
			<td><?php echo (int) $dologin_v->id; ?></td>
			<?php if ( $dologin_v->url && $dologin_v->pk ) : ?>
				<td>
					<?php if ( $dologin_v->easy_login ) : ?>
					<a href="<?php echo esc_url( $dologin_v->easy_login ); ?>" target="_blank" class="button dologin-btn-tiny dologin-btn-success" rel="noopener"><?php esc_html_e( 'Easy Login', 'dologin' ); ?></a></td>
					<?php else : ?>
						<?php esc_html_e( 'Root Site', 'dologin' ); ?>
					<?php endif; ?>
				<td><?php echo esc_html( $dologin_v->title ); ?></td>
				<td><?php echo esc_url( $dologin_v->url ); ?></td>
				<td><code><?php echo esc_html( $dologin_v->pk ); ?></code></td>
			<?php elseif ( $dologin_v->_valid ) : ?>
				<td colspan="4">
					<div class="dologin-row-flex">
						<?php esc_html_e( 'Token:', 'dologin' ); ?>
						<code class="dologin-p10 dologin-code-break dologin_pswd_link dologin_tt dologin_tt--success" data-title="<?php esc_attr_e( 'Click to copy', 'dologin' ); ?>"><?php echo esc_html( $dologin_v->token ); ?></code>
					</div>
					<div class="dologin-success dologin-mt5">
						<?php
						echo wp_kses_post(
							sprintf(
								/* translators: %s: the "Site Connections" tab name. */
								__( 'Copy to your root WordPress site "DoLogin -> %s" tab to enable easy login to this site.', 'dologin' ),
								'<strong>' . esc_html__( 'Site Connections', 'dologin' ) . '</strong>'
							)
						);
						?>
					</div>
					<p class="dologin-success">
						<?php esc_html_e( 'Token valid for 1 hour.', 'dologin' ); ?>
					</p>
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

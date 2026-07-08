<?php
/**
 * Passwordless login management template.
 *
 * @package dologin
 */

namespace dologin;

defined( 'WPINC' ) || exit;

?>
<div class="dologin-relative">
	<h3 class="dologin-title-short">
		<?php esc_html_e( 'Passwordless Login', 'dologin' ); ?>
	</h3>

	<div class="dologin-float-submit">
		<a href="users.php" class="button button-primary "><?php esc_html_e( 'Generate Links in Users List', 'dologin' ); ?></a>
	</div>
</div>

<table class="wp-list-table widefat striped">
	<thead>
	<tr>
		<th>#</th>
		<th><?php esc_html_e( 'Date', 'dologin' ); ?></th>
		<th><?php esc_html_e( 'User', 'dologin' ); ?></th>
		<th><?php esc_html_e( 'Link', 'dologin' ); ?></th>
		<th><?php esc_html_e( 'Created By', 'dologin' ); ?></th>
		<th><?php esc_html_e( 'Count', 'dologin' ); ?></th>
		<th><?php esc_html_e( 'Last Used At', 'dologin' ); ?></th>
		<th><?php esc_html_e( 'Expired At', 'dologin' ); ?></th>
		<th><?php esc_html_e( 'One Time Usage', 'dologin' ); ?></th>
		<th><?php esc_html_e( 'Status', 'dologin' ); ?></th>
	</tr>
	</thead>
	<tbody>
	<?php foreach ( $this->pswdless_log() as $dologin_v ) : ?>
		<tr>
			<td><?php echo (int) $dologin_v->id; ?></td>
			<td><?php echo esc_html( Util::readable_time( $dologin_v->dateline ) ); ?></td>
			<td><?php echo esc_html( $dologin_v->username ); ?></td>
			<td><span class="dologin_pswd_link dologin_tt dologin_tt--success" data-title="<?php esc_attr_e( 'Click to copy', 'dologin' ); ?>"><?php echo esc_url( $dologin_v->link ); ?></span></td>
			<td><?php echo esc_html( $dologin_v->src ); ?></td>
			<td><?php echo (int) $dologin_v->count; ?></td>
			<td><?php echo $dologin_v->last_used_at ? esc_html( Util::readable_time( $dologin_v->last_used_at ) ) : '-'; ?></td>
			<td>
				<?php echo $dologin_v->expired_at > time() ? esc_html( Util::readable_time( $dologin_v->expired_at - time(), 3600, false ) ) : '<span style="color:red;">' . esc_html__( 'Expired', 'dologin' ) . '</span>'; ?>

				<a href="<?php echo esc_url( Util::build_url( Router::ACTION_PSWD, Pswdless::TYPE_EXPIRE_7, false, null, array( 'dologin_id' => $dologin_v->id ) ) ); ?>" class="button button-primary"><?php esc_html_e( '+7 Days', 'dologin' ); ?></a>
			</td>
			<td>
				<?php echo $dologin_v->onetime ? '<span style="color:green;">' . esc_html__( 'Yes', 'dologin' ) . '</span>' : '<span style="color:red;">' . esc_html__( 'No', 'dologin' ) . '</span>'; ?>
				<a href="<?php echo esc_url( Util::build_url( Router::ACTION_PSWD, Pswdless::TYPE_TOGGLE_ONETIME, false, null, array( 'dologin_id' => $dologin_v->id ) ) ); ?>"><span class="dashicons dashicons-controls-repeat"></span></a>
			</td>
			<td>
				<a href="<?php echo esc_url( Util::build_url( Router::ACTION_PSWD, Pswdless::TYPE_LOCK, false, null, array( 'dologin_id' => $dologin_v->id ) ) ); ?>"><?php echo $dologin_v->active ? '<span class="dashicons dashicons-unlock"></span>' : '<span class="dashicons dashicons-lock"></span>'; ?></a>
				<?php
				if ( 1 === (int) $dologin_v->active ) :
					echo '<span style="color:green;">' . esc_html__( 'Active', 'dologin' ) . '</span>';
				else :
					echo '<span style="color:red;">' . esc_html__( 'Disabled', 'dologin' ) . '</span>';
				endif;
				?>
				<a href="<?php echo esc_url( Util::build_url( Router::ACTION_PSWD, Pswdless::TYPE_DEL, false, null, array( 'dologin_id' => $dologin_v->id ) ) ); ?>" class="dologin-right"><span class="dashicons dashicons-dismiss"></span></a>
			</td>
		</tr>
	<?php endforeach; ?>
	</tbody>
</table>


<p class="description"><?php esc_html_e( 'Here you can generate login links and manage them.', 'dologin' ); ?></p>
<div class="dologin-success">
	<strong>= API =</strong>
	<p>*
	<?php
	echo wp_kses_post(
		sprintf(
			/* translators: %s: dologin_gen_link() PHP call example. */
			__( 'Call the function %s to generate one passwordless login link for the current user.', 'dologin' ),
			'<code>$link = function_exists( \'dologin_gen_link\' ) ? dologin_gen_link( \'your plugin name or tag\' ) : \'\';</code>'
		)
	);
	?>
	</p>

	<p>*
	<?php
	echo wp_kses_post(
		sprintf(
			/* translators: 1: dologin_gen_link() PHP call example, 2: the $user_id variable. */
			__( 'Call the function %1$s to generate a passwordless login link for the user which ID is %2$s.', 'dologin' ),
			'<code>$link = function_exists( \'dologin_gen_link\' ) ? dologin_gen_link( \'note/tip for this generation\', $user_id ) : \'\';</code>',
			'<code>$user_id</code>'
		)
	);
	?>
	</p>

	<p><?php esc_html_e( 'The generated one-time used link will be expired after 7 days.', 'dologin' ); ?></p>

	<p>*
	<?php
	echo wp_kses_post(
		sprintf(
			/* translators: %s: the SILENCE_INSTALL PHP constant. */
			__( 'Define const %s to avoid redirecting to setting page after installtion.', 'dologin' ),
			'<code>SILENCE_INSTALL</code>'
		)
	);
	?>
	</p>
</div>

<div class="dologin-success">
	<strong>= CLI =</strong>

	<p>* <?php esc_html_e( 'List all passwordless links', 'dologin' ); ?>: <code>wp dologin list</code></p>

	<p>*
	<?php
	echo wp_kses_post(
		sprintf(
			/* translators: %s: an example login name. */
			__( 'Generate a passwordless link for one username (for the login name %s)', 'dologin' ),
			'<code>root</code>'
		)
	);
	?>
	: <code>wp dologin gen root</code></p>

	<p>*
	<?php
	echo wp_kses_post(
		sprintf(
			/* translators: %s: an example record ID. */
			__( 'Delete a passwordless link w/ the ID in list (for the record w/ ID %s)', 'dologin' ),
			'<code>5</code>'
		)
	);
	?>
	: <code>wp dologin del 5</code></p>
</div>

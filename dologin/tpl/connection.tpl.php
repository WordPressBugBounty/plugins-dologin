<?php
namespace dologin;
defined( 'WPINC' ) || exit;

?>
<div class="dologin-relative">
	<h3 class="dologin-title-short">
		<?php echo __( 'Connections', 'dologin' ); ?>
	</h3>

	<div class="dologin-float-submit">
		<a href="users.php" class="button button-primary "><?php echo __( 'Generate Child Site Connections from Users List', 'dologin' ); ?></a>
	</div>
</div>

<table class="wp-list-table widefat striped">
	<thead>
	<tr>
		<th>#</th>
		<th><?php echo __( 'Action', 'dologin' ); ?></th>
		<th><?php echo __( 'Site Title', 'dologin' ); ?></th>
		<th><?php echo __( 'Site URL', 'dologin' ); ?></th>
		<th><?php echo __( 'Site Public Key', 'dologin' ); ?></th>
		<th><?php echo __( 'Created At', 'dologin' ); ?></th>
		<th><?php echo __( 'Login As User', 'dologin' ); ?></th>
		<th><?php echo __( 'Last Used At', 'dologin' ); ?></th>
		<th><?php echo __( 'Status', 'dologin' ); ?></th>
	</tr>
	</thead>
	<tbody>
	<?php foreach ( $this->connections() as $v ) : ?>
		<tr>
			<td><?php echo $v->id; ?></td>
			<td><a href="<?php echo Util::build_url( Router::ACTION_SITE, Pswdless::TYPE_TOGGLE_ONETIME, false, null, array( 'dologin_id' => $v->id ) ); ?>" target="_blank"><?php echo __( 'One click to login', 'dologin' ); ?></a></td>
			<td><?php echo $v->title; ?></td>
			<td><?php echo $v->url; ?></td>
			<td><code><?php echo $v->pk; ?></code></td>
			<td><?php echo Util::readable_time( $v->dateline ); ?></td>
			<td><?php echo $v->last_used_at ? Util::readable_time( $v->last_used_at ) : '-'; ?></td>
			<td>
				<a href="<?php echo Util::build_url( Router::ACTION_SITE, Pswdless::TYPE_LOCK, false, null, array( 'dologin_id' => $v->id ) ); ?>"><?php echo $v->active ? '<span class="dashicons dashicons-unlock"></span>' : '<span class="dashicons dashicons-lock"></span>'; ?></a>
				<?php
				if ( $v->active == 1 ) :
					echo '<font color="green">' . __( 'Active', 'dologin') . '</font>';
				else :
					echo '<font color="red">' . __( 'Disabled', 'dologin') . '</font>';
				endif;
				?>
				<a href="<?php echo Util::build_url( Router::ACTION_SITE, Pswdless::TYPE_DEL, false, null, array( 'dologin_id' => $v->id ) ); ?>" class="dologin-right"><span class="dashicons dashicons-dismiss"></span></a>
			</td>
		</tr>
	<?php endforeach; ?>
	</tbody>
</table>


<p class="description"><?php echo __( 'Here you can connect child sites to allow login from a root site.', 'dologin' ); ?></p>

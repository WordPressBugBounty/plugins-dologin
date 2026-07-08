<?php
/**
 * Login attempts log template.
 *
 * @package dologin
 */

namespace dologin;

defined( 'WPINC' ) || exit;

$dologin_list       = $this->cls( 'Auth' )->history_list( 20 );
$dologin_count      = $this->cls( 'Auth' )->count_list();
$dologin_pagination = Util::pagination( $dologin_count, 20 );
?>
<div class="dologin-relative">
	<h3 class="dologin-title-short">
		<?php esc_html_e( 'Login Attempts Log', 'dologin' ); ?>
	</h3>

	<div class="dologin-float-submit">
		<a href="<?php echo esc_url( Util::build_url( Router::ACTION_AUTH, Auth::TYPE_CLEAR_LOG ) ); ?>" class="button dologin-btn-warning"><?php esc_html_e( 'Clear records older than one month', 'dologin' ); ?></a>
	</div>
</div>

<?php echo esc_html__( 'Total', 'dologin' ) . ': ' . (int) $dologin_count; ?>

<?php echo wp_kses_post( $dologin_pagination ); ?>

<table class="wp-list-table widefat striped">
	<thead>
	<tr>
		<th>#</th>
		<th><?php esc_html_e( 'Date', 'dologin' ); ?></th>
		<th><?php esc_html_e( 'IP', 'dologin' ); ?></th>
		<th><?php esc_html_e( 'GeoLocation', 'dologin' ); ?></th>
		<th><?php esc_html_e( 'Login As', 'dologin' ); ?></th>
		<th><?php esc_html_e( 'Gateway', 'dologin' ); ?></th>
	</tr>
	</thead>
	<tbody>
	<?php foreach ( $dologin_list as $dologin_v ) : ?>
		<tr>
			<td><?php echo (int) $dologin_v->id; ?></td>
			<td><?php echo esc_html( Util::readable_time( $dologin_v->dateline ) ); ?></td>
			<td><?php echo esc_html( $dologin_v->ip ); ?></td>
			<td><?php echo esc_html( $dologin_v->ip_geo ); ?></td>
			<td><?php echo esc_html( $dologin_v->username ); ?></td>
			<td><?php echo esc_html( $dologin_v->gateway ); ?></td>
		</tr>
	<?php endforeach; ?>
	</tbody>
</table>

<?php echo wp_kses_post( $dologin_pagination ); ?>

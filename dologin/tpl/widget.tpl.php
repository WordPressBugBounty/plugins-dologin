<?php
/**
 * Dashboard overview widget template.
 *
 * @package dologin
 */

namespace dologin;

defined( 'WPINC' ) || exit;

$dologin_list     = $this->cls( 'Auth' )->history_list( 20 );
$dologin_count    = $this->cls( 'Auth' )->count_list();
$dologin_is_admin = current_user_can( 'manage_options' );

echo '<h2>' . esc_html__( 'Blocked login attempts total', 'dologin' ) . ': ' . (int) $dologin_count . '</h2>';
echo '<h2>' . esc_html__( 'Login Attempts Log', 'dologin' ) . '</h2>';
?>
<style type="text/css">
	.dologin-widget-table {
		width: 100%;
		max-width: 100%;
		border-collapse: collapse;
	}

	.dologin-widget-table thead th {
		background-color: #222;
		color: #FFFFFF;
		font-weight: bold;
		border-color: #474747;
		text-align: left;
		padding: 6px 4px;
		border: 1px solid #cccccc;
	}

	.dologin-widget-table tbody td {
		text-align: left;
		padding: 6px 4px;
		border: 1px solid #cccccc;
	}
</style>
<table class="wp-list-table striped dologin-widget-table">
	<thead>
		<tr>
			<th>IP</th>
			<th>Location</th>
			<th>Date</th>
		</tr>
	</thead>
	<tbody>
		<?php if ( ! $dologin_list ) : ?>
			<tr>
				<td><?php esc_html_e( 'No list yet.', 'dologin' ); ?></td>
			</tr>
		<?php else : ?>
			<?php
			foreach ( $dologin_list as $dologin_v ) {
				$dologin_ip_geo      = explode( ', ', $dologin_v->ip_geo );
				$dologin_ip_geo_desc = array();
				foreach ( $dologin_ip_geo as $dologin_v2 ) {
					$dologin_v2 = explode( ':', $dologin_v2 );
					if ( in_array( $dologin_v2[0], array( 'country', 'city' ), true ) ) {
						$dologin_ip_geo_desc[] = $dologin_v2[1];
					}
				}
				$dologin_ip_geo_desc = implode( '-', $dologin_ip_geo_desc );
				echo '<tr><td>' . ( ! $dologin_is_admin ? '**' : esc_html( $dologin_v->ip ) ) . '</td><td>' . esc_html( $dologin_ip_geo_desc ) . '</td><td>' . esc_html( date_i18n( 'm/d H:i', $dologin_v->dateline ) ) . '</td></tr>';
			}
			?>
		<?php endif; ?>
	</tbody>
</table>

<div>
	<a href="<?php echo esc_url( menu_page_url( 'dologin', 0 ) ); ?>#log" style="text-align: right; display: block;"><?php esc_html_e( 'Check more', 'dologin' ); ?></a>
</div>

<?php
/**
 * Plugin Name: Search Antispam
 * Plugin URI: http://danielhuesken.de/portfolio/search-antispam
 * Description: Antispam for the WordPress frontend search
 * Author: Daniel Hüsken
 * Version: 1.0
 * Author URI: http://danielhuesken.de
 * Text Domain: search-antispam
 * Domain Path: /lang/
 * License: GPLv3
 */

/**
 *	Copyright 2011-2012  Daniel Hüsken  (email: mail@danielhuesken.de)
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

if ( ! class_exists( 'Search_Antispam' ) ) {

	//Start Plugin
	if ( function_exists( 'add_filter' ) ) {
			add_action( 'plugins_loaded', array( 'Search_Antispam', 'get_object' ), 11 );
	}


	final class Search_Antispam {

		private $key = '890abcdef123';

		private $today = '0000-00-00';

		private $plugin_base_name = 'search-antispam';

		private $spamcount = 0;

		private $spamchart = array();

		private $spamtypes = array( 'csshack', 'nonce', 'dnsbl', 'referrer' );

		public function __construct() {

			if ( ( defined( 'DOING_AJAX' ) && DOING_AJAX ) or ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE ) or ( defined( 'DOING_CRON' ) && DOING_CRON ) )
				return;

			//set vars correctly
			$this->key         		= substr( md5( md5( AUTH_KEY ) ), 7, 8 );
			$this->today            = date_i18n( 'Y-m-d' );
			$this->plugin_base_name = untrailingslashit( dirname( plugin_basename( __FILE__ ) ) );
			$this->spamcount        = get_option( 'search_antispam_spamcount', $this->spamcount );
			$this->spamchart        = get_option( 'search_antispam_spamchart', $this->spamchart );

			//call spam chart
			$this->spam_chart();
			//load text domain
			load_plugin_textdomain( 'search-antispam', FALSE, $this->plugin_base_name . '/lang' );
			//add filter and actions for scan
			add_action( 'wp_head', array( $this, 'ob_start_wp_head' ), 100);
			//add menu
			add_action('admin_menu', array( $this, 'admin_menu' ));
			//add dashborad widget
			if ( get_option( 'search_antispam_cfg_schowdashboardchart', TRUE ) )
				add_action( 'wp_dashboard_setup', array( $this, 'init_dashboard_chart' ) );
			add_filter( 'plugin_row_meta', array( $this, 'plugin_links' ), 10, 2 );
			add_action( 'admin_init',  array( $this, 'register_admin_settings' ) );
			//add_action( 'bbp_dashboard_widget_right_now_content_table_end', array( $this, 'add_blocked_on_table_end' ) );
			//check the spam must before WP_Query that is why here
			$this->spam_check();

		}

		/**
		 * @static
		 * @return \Search_Antispam
		 */
		public static function get_object() {
			return new self;
		}


		public function ob_start_wp_head() {

			if ( get_option('search_antispam_cfg_disableloggedinuser', TRUE ) && is_user_logged_in() )
				return;

			// only on frontend
			if ( is_admin() )
				return;

			ob_start( array( $this, 'ob_callback_wp_content' ) );
		}

		public function ob_callback_wp_content( $buffer ) {

			$nonce = '';
			if ( get_option( 'search_antispam_cfg_checknonce', TRUE ) )
				$nonce = wp_nonce_field( 'search-antispam-' . $this->key, '_sa_nonce', FALSE, FALSE);

			if ( get_option( 'search_antispam_cfg_checkcsshack', TRUE ) ) {
				$buffer = preg_replace("#<input(.*?)name=([\"\'])s([\"\'])(.+?)/>#i", "<input name=\"s\" value=\"\" type=\"hidden\" />" . $nonce . "<input$1name=$2s-" . $this->key . "$3$4 />", $buffer );
			} else {
				$buffer = preg_replace("#<input(.*?)name=([\"\'])s([\"\'])(.+?)/>#i", $nonce . "<input$1name=$2s$3$4 />", $buffer);
			}

			return $buffer;
		}



		private function spam_check( ) {

			if ( get_option( 'search_antispam_cfg_disableloggedinuser', TRUE ) && is_user_logged_in() )
				return;

			// only on frontend
			if ( is_admin() )
				return;

			//only if a search is done
			if ( ! isset( $_GET[ 's' ] ) )
				return;

			if ( get_option( 'search_antispam_cfg_checkcsshack', TRUE ) ) {
				if ( ! empty( $_GET[ 's' ] ) ) {
					$this->count_spam( 'csshack' );
					unset( $_GET[ 's' ] );
					wp_redirect( home_url(), 404 );
					exit();
				}
				//rewrite extra field to search
				if ( !empty( $_GET[ 's-' . $this->key ] ) ) {
					$_GET[ 's' ] = $_GET[ 's-' . $this->key ];
					unset($_GET[ 's-' . $this->key ]);
				}
			}
			//Filter spam
			if ( get_option( 'search_antispam_cfg_checknonce', TRUE ) && $this->is_nonce_spam() ) {
				$this->count_spam( 'nonce' );
				unset( $_GET[ 's' ] );
				wp_redirect( home_url(), 404 );
				exit();
			}
			if ( get_option( 'search_antispam_cfg_checkdnsbl', TRUE ) && $this->is_dnsbl_spam() ) {
				$this->count_spam( 'dnsbl' );
				unset( $_GET[ 's' ] );
				wp_redirect( home_url(), 404 );
				exit();
			}
			if ( get_option( 'search_antispam_cfg_checkreferrer', TRUE ) && $this->is_false_referrer() ) {
				$this->count_spam( 'referrer' );
				unset( $_GET[ 's' ] );
				wp_redirect( home_url(), 404 );
				exit();
			}

		}

		private function count_spam( $type ) {
			$type = strtolower( $type );
			if ( in_array( $type, $this->spamtypes ) )
				$this->spamchart[ $this->today ][ $type ] ++;
			$this->spamcount ++;
			update_option( 'search_antispam_spamchart', $this->spamchart );
			update_option( 'search_antispam_spamcount', $this->spamcount );
		}


		private function is_nonce_spam() {

			$nonce_ok = isset($_GET[ '_sa_nonce' ]) ? wp_verify_nonce( $_GET[ '_sa_nonce' ], 'search-antispam-' . $this->key ) : FALSE;
			if ( !$nonce_ok )
				return TRUE;

			return FALSE;
		}

		private function is_dnsbl_spam() {

			if ( ! function_exists( 'dns_get_record' ) )
				return FALSE;

			$ip = $_SERVER['REMOTE_ADDR'];

			if ( strstr( $ip, ':') ) {
				//ipv6 (DNSxLs rfc5782)
				$hex = unpack( "H*hex" , inet_pton( $ip ) );
				$ip = substr( preg_replace( "/([A-f0-9]{4})/", "$1:", $hex[ 'hex' ] ), 0, -1);
				$oktets = array_reverse( explode( ':', $ip ) );
				foreach ($oktets as $key => $oktet) {
					$oktets[ $key ] = implode( '.', array_reverse( str_split( $oktet ) ) );
				}
				$reverse_ip = implode( '.', $oktets);
			} else {
				//ipv4
				$reverse_ip = implode( '.', array_reverse( explode( '.', $ip ) ) );
			}

			if ( $text = dns_get_record( $reverse_ip  . '.opm.tornevall.org.', DNS_TXT ) )
				return '[' . $text[0]['txt'] . ']';

			if ( $text = dns_get_record( $reverse_ip  . '.ix.dnsbl.manitu.net.', DNS_TXT ) )
				return '[' . $text[0]['txt'] . ']';

			if ( $text = dns_get_record( $reverse_ip  . '.sbl.spamhaus.org.', DNS_TXT ) )
				return '[' . $text[0]['txt'] . ']';

			if ( $text = dns_get_record( $reverse_ip  . '.xbl.spamhaus.org.', DNS_TXT ) )
				return '[' . $text[0]['txt'] . ']';

			return FALSE;

		}

		private function is_false_referrer() {

			$url 	 = strtolower( home_url() );
			$referer = strtolower( wp_get_referer() );

			if ( ! strstr($referer, $url) ) {
				return TRUE;
			}

			return FALSE;
		}

		public function admin_menu() {

			$hook = add_options_page( __( 'Search Antispam', 'search-antispam' ), __( 'Search Antispam', 'search-antispam' ), 'manage_options', 'search-antispam', array( $this, 'options_page' ) );
			add_action( 'load-' . $hook, array( $this, 'add_help_tab' ));
		}

		public function options_page() {

			?>
			<div class="wrap">
			<?php screen_icon(); ?>
        	<h2><?php _e( 'Search Antispam', 'search-antispam' ); ?></h2>
			<form method="post" action="options.php">
            <?php settings_fields( 'search-antispam' ); ?>
			<?php do_settings_sections( 'search-antispam' );?>
			<?php submit_button(); ?>
            </form>
            </div>
			<?php

		}

		public function init_dashboard_chart() {

			if ( ! current_user_can( 'administrator' ) )
				return FALSE;

			wp_add_dashboard_widget( 'search_antispam', 'Search Antispam', array( $this, 'dashboard_show_spam_chart' ) );
			add_action( 'admin_head-index.php', array( $this, 'add_dashboard_head' ) );
		}

		public function add_dashboard_head() {
			?>
        <style type="text/css" media="screen">
                /*<![CDATA[*/
            #search_antispam_chart {
                height: 175px;
            }

                /*]]>*/
        </style>
        <script type="text/javascript" src="https://www.google.com/jsapi"></script>
        <script type="text/javascript">
            google.load("visualization", "1", {packages:["corechart"]});
            google.setOnLoadCallback(drawChartSearchAntispam);
            function drawChartSearchAntispam() {
                var data = new google.visualization.DataTable();
                data.addColumn('string', '<?PHP _e( 'Date', 'search-antispam' ); ?>');
                data.addColumn('number', '<?PHP _e( 'Summary', 'search-antispam' ); ?>');
                data.addColumn('number', '<?PHP _e( 'CSS Hack', 'search-antispam' ); ?>');
                data.addColumn('number', '<?PHP _e( 'Nonce', 'search-antispam' ); ?>');
                data.addColumn('number', '<?PHP _e( 'DNSBL', 'search-antispam' ); ?>');
                data.addColumn('number', '<?PHP _e( 'Referrer', 'search-antispam' ); ?>');
                data.addRows([<?php
					$data = '';
					foreach ( $this->spamchart as $day => $dayvalue ) {
						$count = 0;
						if ( ! is_array( $dayvalue ) )
							continue;
						foreach ( $dayvalue as $key => $value )
							$count = $count + $value;
						$data .= "['" . $day . "'," . $count;
						foreach ( $this->spamtypes as $type ) {
							$data .= "," . $dayvalue[ $type ];
						}
						$data .= "],";
					}
					echo substr( $data, 0, - 1 );
					?>]);
                var chart = new google.visualization.AreaChart(document.getElementById('search_antispam_chart'));
                chart.draw(data, {width:parseInt(jQuery("#search_antispam_chart").parent().width(), 10), height:175,
                    legend:'none', pointSize:4, lineWidth:2, gridlineColor:'#ececec', focusTarget:'category', fontSize:9,
                    colors:['black', 'red', 'blue', 'green', 'yellow'], chartArea:{width:'100%', height:'100%'},
                    backgroundColor:'transparent', vAxis:{baselineColor:'transparent', textPosition:'in'}});
            }
        </script>
		<?php
		}

		public function dashboard_show_spam_chart() {

			echo '<div id="search_antispam_chart"></div>';
		}

		public function plugin_links( $links, $file ) {

			if ( ! current_user_can( 'install_plugins' ) )
				return $links;

			if ( $file == $this->plugin_base_name . '/search-antispam.php' ) {
				$links[ ] = __( '<a href="https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=CS7BVQ6TTCRYU" target="_blank">Donate</a>', 'bbpress-antispam' );
				$links[ ] = __( '<a href="https://flattr.com/donation/give/to/danielhuesken" target="_blank">Flattr</a>', 'bbpress-antispam' );
			}

			return $links;
		}

		public function add_help_tab() {

			if ( method_exists( get_current_screen(), 'add_help_tab' ) ) {
				get_current_screen()->add_help_tab( array(
														 'id'      => 'antispam',
														 'title'   => __( 'Overview', 'search-antispam' ),
														 'content' =>
														 '<p><a href="http://danielhuesken.de/portfolio/search-antispam" target="_blank">Search Antispam</a>, <a href="http://www.gnu.org/licenses/gpl-3.0" target="_blank">GPLv3</a> &copy 2012-' . date( 'Y' ) . ' <a href="http://danielhuesken.de" target="_blank">Daniel H&uuml;sken</a></p><p>' . __( 'Search Antispam comes with ABSOLUTELY NO WARRANTY. This is free software, and you are welcome to redistribute it under certain conditions.', 'search-antispam' ) . '</p>'
													) );
			}
			get_current_screen()->set_help_sidebar(
				'<p><strong>' . __( 'For more information:', 'search-antispam' ) . '</strong></p>' .
					'<p>' . __( '<a href="http://wordpress.org/extend/plugins/search-antispam/" target="_blank">Wordpress Plugin Site</a>', 'search-antispam' ) . '</p>' .
					'<p>' . __( '<a href="http://danielhuesken.de/portfolio/search-antispam/" target="_blank">Plugin Site</a>', 'search-antispam' ) . '</p>' .
					'<p>' . __( '<a href="http://wordpress.org/extend/plugins/search-antispam/faq/" target="_blank">FAQ</a>', 'search-antispam' ) . '</p>' .
					'<p>' . __( '<a href="http://wordpress.org/tags/search-antispam/" target="_blank">Support Forums</a>', 'search-antispam' ) . '</p>' .
					'<p>' . __( '<a href="https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=CS7BVQ6TTCRYU" target="_blank">Donate</a>', 'search-antispam' ) . '</p>' .
					'<p>' . __( '<a href="https://flattr.com/donation/give/to/danielhuesken" target="_blank">Flattr</a>', 'search-antispam' ) . '</p>' .
					'<p>' . __( '<a href="https://plus.google.com/109825920160870159805/" target="_blank">Google+</a>', 'search-antispam' ) . '</p>'

			);
		}

		public function register_admin_settings() {

			add_settings_section( 'search-antispam', __( 'Antispam', 'search-antispam' ), array( $this, 'callback_main_section' ), 'search-antispam' );

			add_settings_field( 'search_antispam_cfg_generl', __( 'Generel Settings', 'search-antispam' ), array( $this, 'option_callback_generel' ), 'search-antispam', 'search-antispam' );
			register_setting( 'search-antispam', 'search_antispam_cfg_schowdashboardchart', 'intval' );
			register_setting( 'search-antispam', 'search_antispam_cfg_disableloggedinuser', 'intval' );

			add_settings_field( 'search_antispam_cfg_checkcsshack', __('Use CSS Hack', 'search-antispam'), array( $this, 'option_callback_checkcsshack' ), 'search-antispam', 'search-antispam' );
			register_setting( 'search-antispam', 'search_antispam_cfg_checkcsshack', 'intval' );

			add_settings_field( 'search_antispam_cfg_checknonce', __( 'Check Nonce', 'search-antispam' ), array( $this, 'search_antispam_checknonce' ), 'search-antispam', 'search-antispam' );
			register_setting( 'search-antispam', 'search_antispam_cfg_checknonce', 'intval' );

			add_settings_field( 'search_antispam_cfg_checkdnsbl', __( 'Check DNSBL', 'search-antispam' ), array( $this, 'option_callback_checkdnsbl' ), 'search-antispam', 'search-antispam' );
			register_setting( 'search-antispam', 'search_antispam_cfg_checkdnsbl', 'intval' );

			add_settings_field( 'search_antispam_cfg_checkreferrer', __( 'Check Referrer', 'search-antispam' ), array( $this, 'option_callback_checkreferrer' ), 'search-antispam', 'search-antispam' );
			register_setting( 'search-antispam', 'search_antispam_cfg_checkreferrer', 'intval' );


		}

		public function callback_main_section() {
			?>
			<p id="search-antispam"><?php _e( 'Search Antispam Configuration', 'search-antispam' ); ?></p>
			<?php
		}

		public function option_callback_generel() {
			?>
        <input id="search_antispam_cfg_generl_schowdashboardchart" name="search_antispam_cfg_schowdashboardchart"
               type="checkbox"
               value="1" <?php checked( get_option( 'search_antispam_cfg_schowdashboardchart', TRUE ) ); ?> />
        <label
                for="search_antispam_cfg_generl_schowdashboardchart"><?php _e( 'Show chart in Dashboard', 'search-antispam' ); ?></label>
        <br/>

        <input id="search_antispam_cfg_generl_disableloggedinuser" name="search_antispam_cfg_disableloggedinuser"
               type="checkbox"
               value="1" <?php checked( get_option( 'search_antispam_cfg_disableloggedinuser', TRUE ) ); ?> />
        <label
                for="search_antispam_cfg_generl_disableloggedinuser"><?php _e( 'Do not scan logged in users', 'search-antispam' ); ?></label>
        <br/>

        <br/>
		<?php
		}

		public function option_callback_checkcsshack() {
			?>
			<input id="search_antispam_cfg_checkcsshack" name="search_antispam_cfg_checkcsshack"
				   type="checkbox"
				   value="1" <?php checked( get_option( 'search_antispam_cfg_checkcsshack', TRUE ) ); ?> />
			<label
					for="search_antispam_cfg_checkcsshack"><?php _e( 'Use a CSS hack to prevent spamming.', 'search-antispam' ); ?></label>

			<?php
		}

		public function option_callback_checkdnsbl() {
			?>
        <input id="search_antispam_cfg_checkdnsbl" name="search_antispam_cfg_checkdnsbl"
               type="checkbox"
               value="1" <?php checked( get_option( 'search_antispam_cfg_checkdnsbl', TRUE ) ); ?> />
        <label
                for="search_antispam_cfg_checkdnsbl"><?php _e( 'Use DNS Blacklists to prevent spamming.', 'search-antispam' ); ?></label>
		<?php
		}

		public function search_antispam_checknonce() {
			?>
        <input id="search_antispam_cfg_checknonce" name="search_antispam_cfg_checknonce"
               type="checkbox"
               value="1" <?php checked( get_option( 'search_antispam_cfg_checknonce', TRUE ) ); ?> />
        <label
                for="search_antispam_cfg_checknonce"><?php _e( 'Add a Nonce to serach and check it.', 'search-antispam' ); ?></label>
		<?php
		}

		public function option_callback_checkreferrer() {
			?>
        <input id="search_antispam_cfg_checkreferrer" name="search_antispam_cfg_checkreferrer"
               type="checkbox"
               value="1" <?php checked( get_option( 'search_antispam_cfg_checkreferrer', TRUE ) ); ?> />
        <label
                for="search_antispam_cfg_checkreferrer"><?php _e( 'Check Referrer to prevent spamming.', 'search-antispam' ); ?></label>
		<?php
		}

		private function spam_chart() {

			// add var to spam count
			foreach ( $this->spamtypes as $type ) {
				if ( !isset($this->spamchart[$this->today][$type]) )
					$this->spamchart[$this->today][$type] = 0;
			}
			//remove old days from chart
			if ( count($this->spamchart) > 30 ) {
				$mustremoved = count($this->spamchart) - 30;
				foreach ( $this->spamchart as $date => $values ) {
					if ( $mustremoved <= 0 )
						break;
					unset($this->spamchart[$date]);
					$mustremoved--;
				}
			}
		}
	}
}

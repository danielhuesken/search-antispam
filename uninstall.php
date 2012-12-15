<?PHP
if ( !defined('ABSPATH') && !defined('WP_UNINSTALL_PLUGIN') )
	die();
delete_option('search_antispam_spamcount');
delete_option('search_antispam_spamchart');
delete_option('search_antispam_cfg_schowdashboardchart');
delete_option('search_antispam_cfg_disableloggedinuser');
delete_option('search_antispam_cfg_checkcsshack');
delete_option('search_antispam_cfg_checknonce');
delete_option('search_antispam_cfg_checkdnsbl');
delete_option('search_antispam_cfg_checkreferrer');
?>

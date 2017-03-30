<?php if (!defined('BASEPATH')) exit('No direct script access allowed');


$config['website_name'] = 'Your project';
$config['webmaster_email'] = 'webmaster@your-site.com';


$config['phpass_hash_portable'] = FALSE;
$config['phpass_hash_strength'] = 8;


$config['email_activation'] = TRUE;
$config['email_activation_expire'] = 60*60*24*2;
$config['email_account_details'] = TRUE;
$config['use_username'] = TRUE;



$config['login_by_username'] = TRUE;
$config['login_by_email'] = TRUE;
$config['login_record_ip'] = TRUE;
$config['login_record_time'] = TRUE;
$config['login_count_attempts'] = TRUE;
$config['login_max_attempts'] = 5;
$config['login_attempt_expire'] = 60*60*24;


$config['autologin_cookie_name'] = 'nuanTrip_autologin';
$config['autologin_cookie_life'] = 60*60*24*31*2;


$config['forgot_password_expire'] = 60*15;
$config['db_table_prefix'] = 'nuan_';



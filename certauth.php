<?php
/*
Plugin Name: The Space: X.509 Certificate Authentication
Author: BBC Archive Development
Author URI: http://www.bbc.co.uk/archive/
Description: Permits the use of SSL client certificates for authentication
*/

/*
 * Copyright 2011-2013 BBC.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */


class CertificateAuth
{
	public $certificate = null;
	public $certificateInfo;
	public $publicKey;
	public $email;
	public $publicKeyHash;
	public $haveCredentials = false;
	
	protected $fingerprint = array();

	public function __construct($cert = null)
	{
		$this->obtainCertificate($cert);
		$this->processCertificate();
		add_action('init', array($this, 'init'), 1);
		add_filter('show_password_fields', array($this, 'show_password_fields'), 10, 2);
		add_action('user_profile_update_errors', array($this, 'user_profile_update_errors'), 255, 3);
		add_action('profile_update', array($this, 'profile_update'), 255, 2);
	}

	public /*callback*/ function init()
	{
		if($this->haveCredentials)
		{
			$this->attemptLogin($this->email, $this->publicKeyHash);
		}
	}

	public /*callback*/ function show_password_fields($show, $user = null)
	{
		$fingerprint = '';
		if(!is_object($user))
		{
			/* Don't show the fingerprint field for new users */
			return;
		}
		if(strlen(@$_POST['fingerprint']))
		{
			$fingerprint = @$_POST['fingerprint'];
		}
		if(ctype_xdigit($user->user_pass))
		{
			$show = false;
			if(!strlen($fingerprint))
			{
				$fingerprint = $user->user_pass;
			}
		}
		echo '<tr id="password">';
		echo '<th><label for="fingerprint">RSA key fingerprint:</label></th>';
		echo '<td><input type="text" name="fingerprint" id="fingerprint" size="40" value="' . htmlspecialchars($fingerprint, ENT_QUOTES, 'UTF-8') . '" /><br /><span class="description">If the user should authenticate using an SSL certificate, specify the RSA key fingerprint here (the username <strong>must</strong> match the <code>emailAddress</code> in the DN)</span></td>';
		echo '</tr>';
		return $show;
	}

	public /*callback*/ function user_profile_update_errors(&$errors, $update, &$user)
	{
		$user->fingerprint = null;
		if(strlen(@$_POST['fingerprint']))
		{
			$fingerprint = strtolower(preg_replace('![^0-9a-f]!i', '', $_POST['fingerprint']));
			if(strlen($fingerprint))
			{
				$this->fingerprint[$user->ID] = $fingerprint;
				error_log('certauth: fingerprint submitted for user ID ' . $user->ID . ' was ' . $fingerprint);
			}
			else
			{
				error_log('certauth: fingerprint was submitted but is not valid');
			}
		}
		else
		{
			error_log('certauth: no fingerprint submitted');
		}
	}
	
	public /*callback*/ function profile_update($user_id, $old_user_data)
	{
		global $wpdb;
		
		if(!current_user_can('edit_user', $user_id))
		{
			error_log('certauth: refusing to update user ID ' .  $user_id);
			return false;
		}
		if(isset($this->fingerprint[$user_id]))
		{
			error_log('certauth: updating fingerprint of user ID ' . $user_id . ' to ' . $this->fingerprint[$user_id]);
			$wpdb->update($wpdb->users, array('user_pass' => $this->fingerprint[$user_id]), array('ID' => $user_id));
		}
		else
		{
			error_log('certauth: no submitted fingerprint found for user ID ' . $user_id);
		}
	}
	
	protected function obtainCertificate($cert = null)
	{
		if($cert !== null)
		{
			$this->certificate = $cert;
		}
		else if(defined('CERTAUTH_REQUEST_HEADER'))
		{
			/* If CERTAUTH_REQUEST_HEADER, the certificate is passed in a
			 * custom header from a front-end proxy (e.g., Varnish)
			 */
			if(function_exists('apache_request_headers'))
			{
				$headers = apache_request_headers();
				if(isset($headers[CERTAUTH_REQUEST_HEADER]))
				{
					/* The header is forwarded with newlines replaced by spaces */
					$tmp = $headers[CERTAUTH_REQUEST_HEADER];
					$tmp = str_replace(' ', "\n", $tmp);
					$tmp = str_replace("BEGIN\nCERTIFICATE", 'BEGIN CERTIFICATE', $tmp);
					$tmp = str_replace("END\nCERTIFICATE",   'END CERTIFICATE',   $tmp);
					$this->certificate = $tmp;
				}
			}
		}
		else if(isset($_SERVER['SSL_CLIENT_CERT']))
		{
			/* The certificate is passed by the web server using the SSL_CLIENT_CERT
			 * CGI environment variable
			 */
			$this->certificate = $_SERVER['SSL_CLIENT_CERT'];
		}
	}

	protected function processCertificate()
	{
		if(!strlen($this->certificate))
		{
			return false;
		}
		require_once(dirname(__FILE__) . '/asn1.php');
		$cert = @openssl_x509_read($this->certificate);
		if(!is_resource($cert))
		{
			return;
		}
		$this->certificateInfo = openssl_x509_parse($cert);
		if(isset($this->certificateInfo['subject']['emailAddress']))
		{
			$this->email = $this->certificateInfo['subject']['emailAddress'];
		}
		if(!strlen($this->email))
		{
			return;
		}
		$publicKey = openssl_pkey_get_public($cert);
		$details = openssl_pkey_get_details($publicKey);
		$this->publicKey = $details['key'];
		$this->publicKeyHash = null;
		$matches = array();
		if(preg_match('!^-----BEGIN ([A-Z ]+)-----\s*?([A-Za-z0-9+=/\r\n]+)\s*?-----END \1-----\s*$!D', $this->publicKey, $matches))
		{ 
			$binary = base64_decode(str_replace(array("\r", "\n"), array('', ''), $matches[2]));
			$decoded = ASN1::decodeBER($binary);
			if(isset($decoded[0]['sequence']))
			{
				foreach($decoded[0]['sequence'] as $entry)
				{
					if($entry['type'] == 'BIT-STRING')
					{
						$this->publicKeyHash = openssl_digest(base64_decode($entry['value']), 'SHA1');
						$this->haveCredentials = true;
						break;
					}
				}
			}
		}
	}

	protected function attemptLogin($email, $hash)
	{
		global $wpdb;

		if(!strlen($email) || !strlen($hash))
		{
			return;
		}
		/* The e-mail address in the DN of the certificate must match the user's
		 * login name
		 */
		$user = $wpdb->get_row($wpdb->prepare('SELECT * FROM ' . $wpdb->users . ' WHERE `user_login` = %s', $email));
		if(!is_object($user))
		{
			return;
		}
		/* The user_pass field of the user must match the certificate's key
		 * fingerprint (hash)
		 */
		if(strcmp($user->user_pass, $hash))
		{
			return;
		}
		error_log('certauth: authenticated user ' . $email . ' with fingerprint ' . $hash);
		/* The certificate matches stored credentials, log the user in */
		$credentials = array(
			'user_login' => $email,
			'user_password' => 'x',
			'user_key_hash' => $hash,
			'remember' => false,
			);
		$secure_cookie = '';
		if('' === $secure_cookie)
		{
			$secure_cookie = is_ssl();
		}
		$secure_cookie = apply_filters('secure_signon_cookie', $secure_cookie, $credentials);

		global $auth_secure_cookie; // XXX ugly hack to pass this to wp_authenticate_cookie
		$auth_secure_cookie = $secure_cookie;
		wp_set_auth_cookie($user->ID, $credentials['remember'], $secure_cookie);
		wp_set_current_user($user->ID);
		do_action('wp_login', $credentials['user_login']);
	}
}

$certificateAuth = new CertificateAuth();

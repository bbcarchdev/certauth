Certificate Authentication
==========================

This plugin allows X.509 certificate authentication to be used in place of
usernames and passwords.

It assumes that:

* Your web server is validating certificates presented to it.

* You want everybody with a certificate issued by your permitted CAs to be able to access WordPress's front-end.
  
* Some or all of your WordPress users should be authenticated according to their certificate.

In other words, everybody that your web server's certificate validation permits
will be able to access the WordPress front-end, but only users presenting the
correct certificates (corresponding to their accounts) will be able to log in,
assuming their accounts have been configured accordingly. It's up to you whether
you enforce this for all users (and disable registration), or only for privileged
accounts (editors, administrators, etc.).

The e-mail address in the DN of the certificate must match the user name stored
in the wp_users database table, while the 'password' field contains the key
fingerprint. Note that this means that the user cannot log in any other way,
and that their username must be an e-mail address.

Because the key fingerprint is stored against the user account, that user can
only log in with a certificate signed by that key: if they have a new certificate
issued with a new key, you will need to update their stored fingerprint.

This is not two-factor authentication -- certificate-based login replaces
password login entirely, and your local certificate policies apply. For
example, you could mandate that certificates must be stored on a particular
type of hardware token and only set/update the stored fingerprint when you
know that the key was generated on that token and can't be exported.

The certificate data must be supplied by the web server in the environment via
SSLOptions ExportCertData or equivalent. The plugin checks the contents of the
SSL_CLIENT_CERT environment variable. Alternatively, you can define
CERTAUTH_REQUEST_HEADER in your wp-config.php to the name of an HTTP request
header containing the supplied client certificate. This will only work
if your web server is Apache (because the plugin uses apache_request_headers()
to obtain the contents of the header). You can use this mechanism if
the SSL session is terminated at a proxy/cache (such as Varnish) in front of
the actual WordPress instance.

Minimal validation of the certificate occurs — we don’t care about anything
that the web server isn’t configured to check beyond the combination of
e-mail address and key fingerprint, therefore care should be taken to
ensure that the SSLVerify options are set properly.

-- Mo McRoberts <mo.mcroberts@bbc.co.uk>

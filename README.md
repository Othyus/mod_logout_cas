# mod_logout_cas
An Apache mod to logout of cas when using mod_auth_cas to login

How to use ?
Add theses lines in httpd.conf :

LoadModule logout_cas_module mod_logout_cas.so
<IfModule mod_logout_cas.c>
	LogoutCASCookiePath /path_where_cas_cookies_are_stored/
	LogoutCASLogoutURL https://my_cas_server/logout?service=current_service
	LogoutCASURLHandler /logout
</IfModule>

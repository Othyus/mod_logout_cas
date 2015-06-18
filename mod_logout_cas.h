#include "ap_config.h"

#define LOGOUT_CAS_MAX_LENGTH 1000
#define LOGOUT_CAS_DEFAULT_COOKIE_PATH "/var/cache/cas/"
#define LOGOUT_CAS_DEFAULT_LOGOUT_URL "https://www.cas.com/logout?service=https://www.myservice.com"
#define LOGOUT_CAS_DEFAULT_URL_HANDLER "/logout"

typedef struct logout_cas_cfg {
	unsigned int merged;
	char *LogoutCASCookiePath;
	char *LogoutCASLogoutURL;
	char *LogoutCASURLHandler;
} logout_cas_cfg;

typedef enum {
	logout_cas_cmd_cookie_path, logout_cas_cmd_logout_url, logout_cas_cmd_url_handler
} logout_cas_valid_cmds;

module AP_MODULE_DECLARE_DATA logout_cas_module;
AP_DECLARE_HOOK(int,logout_cas_handler,(request_rec *r));
static int logout_cas_handler(request_rec *r);
void *logout_cas_create_server_config(apr_pool_t *pool, server_rec *svr);
void *logout_cas_merge_server_config(apr_pool_t *pool, void *BASE, void *ADD);
void *logout_cas_create_dir_config(apr_pool_t *pool, char *path);
void *logout_cas_merge_dir_config(apr_pool_t *pool, void *BASE, void *ADD);
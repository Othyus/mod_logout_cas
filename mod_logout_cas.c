#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "httpd.h"
#include "http_config.h"
#include "mod_logout_cas.h"
#include "http_protocol.h"
#include "http_log.h"
#include "ap_config.h"

static int logout_cas_handler(request_rec *r){
    r->content_type = "text/html";
	logout_cas_cfg *c = ap_get_module_config(r->server->module_config, &logout_cas_module);
	if(strcmp(r->uri, c->LogoutCASURLHandler)==0){
		if(r->user != NULL){
			struct dirent *directoryCursor;
			DIR *directory;
			directory = opendir(c->LogoutCASCookiePath);
			while ((directoryCursor = readdir(directory))) {
				FILE* file = NULL;
				char line[LOGOUT_CAS_MAX_LENGTH] = "";
				char fullName[LOGOUT_CAS_MAX_LENGTH] = "";
				sprintf(fullName,"%s", c->LogoutCASCookiePath);
				strcat(fullName, directoryCursor->d_name);
				int correctFile = 0;
				if(directoryCursor->d_name[0] != '.'){
					file = fopen(fullName, "r");
					if (file != NULL) {
						while(fgets(line, LOGOUT_CAS_MAX_LENGTH, file) != NULL){
							ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "line <%s>", line);
							if(strstr(line, "user") != NULL && strstr(line, r->user) != NULL){
								ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "user found");
								correctFile = 1;
							}
						}
						if(correctFile == 1){
							if(remove(fullName) != 0){
								ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "Unable to delete the file <%s>", fullName);
							}
						}
						fclose(file);
					}else{
						ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "File <%s> does not exist", fullName);
					}
				}else{
					if((strcmp(directoryCursor->d_name, ".")!=0) && (strcmp(directoryCursor->d_name, "..")!=0)){
						if(remove(fullName) != 0){
							ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "Unable to delete the file <%s>", fullName);
						}
					}
				}
			}
			closedir(directory);
			apr_table_add(r->headers_out, "Location", c->LogoutCASLogoutURL);
			return HTTP_MOVED_TEMPORARILY;
		}else{
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "User is null");
		}
	}
    return DECLINED;
}

static void logout_cas_register_hooks(apr_pool_t *p){
    ap_hook_handler(logout_cas_handler,NULL, NULL, APR_HOOK_MIDDLE);
}

void *logout_cas_create_server_config(apr_pool_t *pool, server_rec *svr){
	logout_cas_cfg *c = apr_pcalloc(pool, sizeof(logout_cas_cfg));
	c->merged = FALSE;
	c->LogoutCASCookiePath = LOGOUT_CAS_DEFAULT_COOKIE_PATH;
	c->LogoutCASLogoutURL = LOGOUT_CAS_DEFAULT_LOGOUT_URL;
	c->LogoutCASURLHandler = LOGOUT_CAS_DEFAULT_URL_HANDLER;
	return c;
}

void *cas_logout_create_dir_config(apr_pool_t *pool, char *path){
	logout_cas_cfg *c = apr_pcalloc(pool, sizeof(logout_cas_cfg));
	c->LogoutCASCookiePath = LOGOUT_CAS_DEFAULT_COOKIE_PATH;
	c->LogoutCASLogoutURL = LOGOUT_CAS_DEFAULT_LOGOUT_URL;
	c->LogoutCASURLHandler = LOGOUT_CAS_DEFAULT_URL_HANDLER;
	return(c);
}

const char *cfg_readLogoutCASParameter(cmd_parms *cmd, void *cfg, const char *value){
	logout_cas_cfg *c = (logout_cas_cfg *) ap_get_module_config(cmd->server->module_config, &logout_cas_module);
	apr_finfo_t f;
	char d;
	switch((size_t) cmd->info) {
		case logout_cas_cmd_cookie_path:
			if(apr_stat(&f, value, APR_FINFO_TYPE, cmd->temp_pool) == APR_INCOMPLETE){
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "Could not find LogoutCASCookiePath <%s>", value);
				return NULL;
			}
			if(f.filetype != APR_DIR || value[strlen(value)-1] != '/'){
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "LogoutCASCookiePath <%s> is not a directory or does not end in a trailing '/'", value);
				return NULL;
			}
			c->LogoutCASCookiePath = (char *)value;
		break;
		case logout_cas_cmd_logout_url:
			c->LogoutCASLogoutURL = (char *)value;
		break;
		case logout_cas_cmd_url_handler:
			c->LogoutCASURLHandler = (char *)value;
		break;
		default:
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "invalid command <%s>", cmd->directive->directive);
			return NULL;
		break;
	}
	return NULL;
}

const command_rec logout_cas_cmds [] = {
	AP_INIT_TAKE1("LogoutCASCookiePath", cfg_readLogoutCASParameter, (void *) logout_cas_cmd_cookie_path, RSRC_CONF, "Define the CAS cookie path (ex: /var/cache/cas)"),
	AP_INIT_TAKE1("LogoutCASLogoutURL", cfg_readLogoutCASParameter, (void *) logout_cas_cmd_logout_url, RSRC_CONF, "Define the CAS logout URL (ex: https://www.cas_example.com/logout)"),
	AP_INIT_TAKE1("LogoutCASURLHandler", cfg_readLogoutCASParameter, (void *) logout_cas_cmd_url_handler, RSRC_CONF, "Define URL which handle by mod"),
	AP_INIT_TAKE1(0, 0, 0, 0, 0)
};

module logout_cas_module={
    STANDARD20_MODULE_STUFF,
    cas_logout_create_dir_config,
    NULL,
    logout_cas_create_server_config,
    NULL,
    logout_cas_cmds,
    logout_cas_register_hooks
};
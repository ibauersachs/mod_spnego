/* -----------------------------------------------------------------------------
 * mod_spnego is an Apache module that supports authentication via the RFC
 * 2478 SPNEGO GSS-API mechanism.
 *
 * mod_spnego supports Apache >= 2.0.
 *
 * Author: Frank Balluffi and Markus Moeller
 * Cleanup: Ingo Bauersachs
 *
 * Copyright (C) 2002-2007 Frank Balluffi and Markus Moeller. All rights
 * reserved.
 * Copyright (C) 2012 Ingo Bauersachs
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * -----------------------------------------------------------------------------
 */


// Include necessary Windows headers
#define WIN32_LEAN_AND_MEAN
#define SECURITY_WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <security.h>
#include <schannel.h>
#include <errno.h>

#include <iostream>
#include <string>
#include <sstream>

// Apache headers
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

// Apache portable headers
#include "apr_base64.h"
#include "apr_env.h"
#include "apr_strings.h"

/*
 * PORTABLE_APLOG_DEBUG and PORTABLE_APLOG_INFO are hacks.
 */
#define PORTABLE_APLOG_ERR  APLOG_ERR, 0
#define PORTABLE_APLOG_INFO APLOG_INFO, 0


/**
 * Defines a structure representing the directory configuration set.
 */
typedef struct DIRECTORY_CONFIG_st {
    const char *krb5KeyTabFile;
    const char *krb5ServiceName;
    int krb5AuthorizeFlag;
    int krb5RemoveDomain;
} DIRECTORY_CONFIG, *PDIRECTORY_CONFIG;

/**
 * Defines a structure representing the server configuration set.
 */
typedef struct SERVER_CONFIG_st {
    int krb5AuthEachReq;
} SERVER_CONFIG, *PSERVER_CONFIG;

/**
 * Defines a structure representing the connection configuration set.
 */
typedef struct CONNECTION_CONFIG_st {
    LPSTR user;
    LPSTR service_name;
    LPSTR last_service_name;
    PCtxtHandle security_context;
} CONNECTION_CONFIG, *PCONNECTION_CONFIG;

// forward declarations
extern "C" module AP_MODULE_DECLARE_DATA spnego_module;
static PCONNECTION_CONFIG get_connection_config(request_rec* request);

/**
 * Writes GSS-API messages to Apache's error log.
 *
 * @param   file        The file.
 * @param   line        The line.
 * @param   level       The level.
 * @param   request     The request that is being processed for authentication.
 * @param   message     The message to log.
 * @param   messageId   A Windows system message identifier to append to the custom message.
 */
static void logSSPIError(
    LPCSTR file,
    int line,
    int level,
    const request_rec* request,
    LPTSTR message,
    DWORD messageId)
{
    LPSTR pBuffer = NULL;
    FormatMessage(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        messageId,
        0,
        (LPSTR)&pBuffer,
        0,
        NULL
    );

    OutputDebugString(message);
    ap_log_rerror(file, line, level, 0, request, "%s; SSPI: %s (%d)", message, (LPSTR) pBuffer ? pBuffer : "", messageId);

    if(pBuffer)
    {
        OutputDebugString(pBuffer);
        LocalFree(pBuffer);
    }
    OutputDebugString("\n");
}

/**
 * Handles the SPNEGO token.
 *
 * @param [in,out]  request             to process.
 * @param   client_token                The input token.
 * @param   client_token_length         Length of the input token.
 * @param [in,out]  server_token        If non-null, the output token.
 * @param [in,out]  server_token_length If non-null, length of the output token.
 *
 * @return A HTTP_Status code.
 */
static int handleSpnegoToken(
    request_rec* request,
    const LPBYTE client_token,
    size_t client_token_length,
    LPBYTE* server_token,
    size_t* server_token_length)
{
    ap_log_rerror(APLOG_MARK, PORTABLE_APLOG_INFO, request, "mod_spnego: entering handleSpnegoToken");

    // obtain and validate configurations
    PDIRECTORY_CONFIG directoryConfig = (PDIRECTORY_CONFIG)ap_get_module_config(request->per_dir_config, &spnego_module);
    if(!directoryConfig)
    {
        ap_log_rerror(APLOG_MARK, PORTABLE_APLOG_INFO, request, "mod_spnego: handleSpnegoToken: could not obtain directory config");
        return HTTP_UNAUTHORIZED;
    }

    if(!directoryConfig->krb5ServiceName)
    {
        ap_log_rerror(APLOG_MARK, PORTABLE_APLOG_INFO, request, "mod_spnego: handleSpnegoToken: no KRB5 service name set");
        return HTTP_UNAUTHORIZED;
    }

    PCONNECTION_CONFIG conn_config = get_connection_config(request);
    if(!conn_config)
    {
        ap_log_rerror(APLOG_MARK, PORTABLE_APLOG_INFO, request, "mod_spnego: handleSpnegoToken: connection config unavailable");
        return HTTP_UNAUTHORIZED;
    }

    // prepare the security data from the CLIENT's token
    SecBufferDesc client_sec_buffer_desc;
    SecBuffer client_sec_buffer;
    client_sec_buffer_desc.cBuffers = 1;
    client_sec_buffer_desc.ulVersion = SECBUFFER_VERSION;
    client_sec_buffer_desc.pBuffers = &client_sec_buffer;

    client_sec_buffer.cbBuffer = (unsigned long) client_token_length;
    client_sec_buffer.BufferType = SECBUFFER_TOKEN;
    client_sec_buffer.pvBuffer = client_token;

    // prepare the security data for the SERVER's token
    SecBufferDesc server_sec_buffer_desc;
    SecBuffer server_sec_buffer;
    server_sec_buffer_desc.cBuffers = 1;
    server_sec_buffer_desc.ulVersion = SECBUFFER_VERSION;
    server_sec_buffer_desc.pBuffers = &server_sec_buffer;

    server_sec_buffer.cbBuffer = 0;
    server_sec_buffer.pvBuffer = NULL;
    server_sec_buffer.BufferType = SECBUFFER_TOKEN;
	CredHandle server_creds;

    // try to authenticate with all configured Kerberos service names
    LPSTR krb5_service_name = apr_pstrdup(request->connection->pool, directoryConfig->krb5ServiceName);
    SECURITY_STATUS result;
	SECURITY_STATUS credhandleResult;
    if(!conn_config->service_name)
    {
        conn_config->service_name = apr_strtok(krb5_service_name, " ", &conn_config->last_service_name);
    }

    while(conn_config->service_name != NULL)
    {
        ap_log_rerror(APLOG_MARK, PORTABLE_APLOG_INFO, request, "mod_spnego: Try service name %s", conn_config->service_name);
		// hypothesis, declaration should be elsewhere       
		// CredHandle server_creds;
        TimeStamp expiry;
        result = AcquireCredentialsHandle(
            conn_config->service_name,
            "Negotiate",
            SECPKG_CRED_INBOUND,
            NULL,		// no logon id
            NULL,		// no auth data
            NULL,		// no get key fn
            NULL,		// no get key arg
            &server_creds,
            &expiry
        );
        if(result != SEC_E_OK)
        {
            logSSPIError(APLOG_MARK, APLOG_ERR, request, "mod_spnego: AcquireCredentialsHandle failed", result);
            conn_config->service_name = apr_strtok(NULL, " ", &conn_config->last_service_name);
            continue; // try next service name
        }

        ULONG ret_flags = 0;
        CtxtHandle new_context;
        result = AcceptSecurityContext(
            &server_creds,
            conn_config->security_context, // NULL on new connections, existing context on continuations
            &client_sec_buffer_desc,
            ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_MUTUAL_AUTH,
            SECURITY_NATIVE_DREP,
            &new_context, // NULL on new connections, existing context on continuations
            &server_sec_buffer_desc, // needs release with FreeContextBuffer after being sent to client
            &ret_flags,
            &expiry
        );

        conn_config->security_context = (PCtxtHandle)apr_palloc(request->connection->pool, sizeof(CtxtHandle));
        memcpy(conn_config->security_context, &new_context, sizeof(CtxtHandle));

        //FreeContextBuffer(client_sec_buffer.pvBuffer);
        //client_sec_buffer.pvBuffer = NULL;

        if(result != SEC_E_OK && result != SEC_I_CONTINUE_NEEDED)
        {
            logSSPIError(APLOG_MARK, APLOG_ERR, request, "mod_spnego: AcceptSecurityContext failed", result);
            conn_config->service_name = apr_strtok(NULL, " ", &conn_config->last_service_name);
			// oprava JB 6.9.2017 uvolneni credential handle
			credhandleResult = FreeCredentialsHandle(&server_creds);
            continue; // try next service name
        }
        else
        {
            // Any data in the buffer must be sent to the client, even in the OK case
            if(server_sec_buffer.cbBuffer != 0)
            {
                *server_token_length = server_sec_buffer.cbBuffer;
                *server_token = (LPBYTE)apr_pcalloc(request->pool, *server_token_length);
                if(!*server_token)
                {
                    ap_log_rerror(APLOG_MARK, PORTABLE_APLOG_ERR, request, "mod_spnego: apr_pcalloc failed for *server_token");
                    DeleteSecurityContext(conn_config->security_context);
                    conn_config->security_context = NULL;
					// oprava JB 6.9.2017
					credhandleResult = FreeCredentialsHandle(&server_creds);
                    return HTTP_INTERNAL_SERVER_ERROR;
                }
                memcpy(*server_token, server_sec_buffer.pvBuffer, server_sec_buffer.cbBuffer);
            }
            FreeContextBuffer(server_sec_buffer.pvBuffer);
            server_sec_buffer.pvBuffer = NULL;
            break;
        }
    }

	if (!conn_config->service_name)
	{
		logSSPIError(APLOG_MARK, APLOG_ERR, request, "mod_spnego: handleSpnegoToken failed, none of the service names accepted the client token", result);
		DeleteSecurityContext(conn_config->security_context);
		conn_config->security_context = NULL;
		// oprava JB 6.9.2017 uvolneni credential handle
		credhandleResult = FreeCredentialsHandle(&server_creds);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    // okay, authentication succeeded
    if(result == SEC_E_OK)
    {
        SecPkgContext_Names names;
        result = QueryContextAttributes(conn_config->security_context, SECPKG_ATTR_NAMES, &names);
        if (result != SEC_E_OK)
        {
            logSSPIError(APLOG_MARK, APLOG_ERR, request, "mod_spnego: QueryContextAttributes failed", result);
			// oprava JB 6.9.2017 uvolneni security contextu
			DeleteSecurityContext(conn_config->security_context);
			conn_config->security_context = NULL;
			// oprava JB 6.9.2017 uvolneni credential handle
			credhandleResult = FreeCredentialsHandle(&server_creds);
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        if(directoryConfig->krb5RemoveDomain)
        {
            request->user = apr_pstrdup(request->pool, strchr(names.sUserName, '\\')+1);
        }
        else
        {
            request->user = apr_pstrdup(request->pool, names.sUserName);
        }
		
        ap_log_rerror(APLOG_MARK, PORTABLE_APLOG_INFO, request, "mod_spnego: setting connection user to %s", request->user);
        conn_config->user = apr_pstrdup(request->connection->pool, request->user);

        // MSDN says we are responsible to clean variable sized arguments from the output of QueryContextAttributes
        FreeContextBuffer(names.sUserName);
        names.sUserName = NULL;

        DeleteSecurityContext(conn_config->security_context);
        conn_config->security_context = NULL;
		// oprava JB 6.9.2017 uvolneni credential handle
		credhandleResult = FreeCredentialsHandle(&server_creds);

        return OK;
    }
    else if(result == SEC_I_CONTINUE_NEEDED)
    {
        // nothing more to do, just send the server's token to the client
		// oprava JB 6.9.2017 uvolneni credential handle
		credhandleResult = FreeCredentialsHandle(&server_creds);

    }
    else
    {
        // some other failure occurred, clean up
        DeleteSecurityContext(conn_config->security_context);
        conn_config->security_context = NULL;
		// oprava JB 6.9.2017 uvolneni credential handle
		credhandleResult = FreeCredentialsHandle(&server_creds);

    }
    return HTTP_UNAUTHORIZED;
}

/**
 * Authenticates a user (or an Apache client).
 *
 * @param [in,out]  request   If non-null, the request_rec * to process.
 *
 * @return A HTTP_Status code.
 */
static int authenticate_user(
    request_rec * request)
{
    ap_log_rerror(APLOG_MARK, PORTABLE_APLOG_INFO, request, "mod_spnego: entering authenticate_user");

    // Check 'AuthType' config for 'SPNEGO', decline access for everything else
    LPCSTR auth_type = ap_auth_type(request);
    if(!auth_type || strcasecmp(auth_type, "SPNEGO"))
    {
        ap_log_rerror(APLOG_MARK, PORTABLE_APLOG_INFO, request, "mod_spnego: unrecognized AuthType \'%s\'", auth_type ? auth_type : "NULL");

        return DECLINED;
    }

    PSERVER_CONFIG serverConfig = (PSERVER_CONFIG)ap_get_module_config(request->server->module_config, &spnego_module);
    if(!serverConfig)
    {
        ap_log_rerror(APLOG_MARK, PORTABLE_APLOG_INFO, request, "mod_spnego: could not obtain server config, declining access");
        return DECLINED;
    }

    PCONNECTION_CONFIG conn_config = get_connection_config(request);
    if(!conn_config)
    {
        ap_log_rerror(APLOG_MARK, PORTABLE_APLOG_INFO, request, "mod_spnego: could not obtain connection config, declining access");
        return DECLINED;
    }

    /*
     * mod_auth_digest calls ap_is_initial_req for ap_hook_post_read_request hook
     * function and returns DECLINED if ap_is_initial_req returns 0.
     * 
     * Returning DECLINED if ap_is_initial_req returns 0 caused the following error:
     * 
     * [Mon Aug 04 20:54:29 2003] [crit] [client 10.155.131.145] configuration error:couldn't check user.  No user file?: /index.html
     */

    int rc;
    //FIXME: this stuff is bogus. Always return DECLINED for subrequests?
    if(!ap_is_initial_req(request) && !conn_config->user)
    {
        ap_log_rerror(APLOG_MARK, PORTABLE_APLOG_INFO, request, "mod_spnego: ap_is_initial_req returned 0");

        rc = HTTP_UNAUTHORIZED;

        ap_log_rerror(APLOG_MARK, PORTABLE_APLOG_INFO, request, "mod_spnego: authenticate_user returning %d", rc);
        return rc;
    }
    else if(!ap_is_initial_req(request) && conn_config->user)
    {
        if(!request->user)
        {
            request->user = apr_pstrdup(request->pool, conn_config->user);
        }
        return OK;
    }

    //FIXME: what is the point of this condition
    if(!serverConfig->krb5AuthEachReq && conn_config->user)
    {
        ap_log_rerror(APLOG_MARK, PORTABLE_APLOG_INFO, request, "mod_spnego: setting request user to %s", conn_config->user);
        request->user = apr_pstrdup(request->pool, conn_config->user);
        return OK;
    }

    LPCSTR authorization_header = apr_table_get(request->headers_in, "Authorization");
    if(!authorization_header)
    {
        // if the Authorization header is missing, send a WWW-Authenticate header back to the client
        ap_log_rerror(APLOG_MARK, PORTABLE_APLOG_INFO, request, "mod_spnego: sending 401 and \"WWW-Authenticate: Negotiate\"");
        apr_table_add(request->err_headers_out, "WWW-Authenticate", "Negotiate");
        return HTTP_UNAUTHORIZED;
    }

    LPCSTR auth_protocol = ap_getword_white(request->pool, &authorization_header);
    ap_log_rerror(APLOG_MARK, PORTABLE_APLOG_INFO, request, "mod_spnego: Authorization header is \"%s\"", auth_protocol);
    if(!strncasecmp(auth_protocol, "Negotiate", 9))
    {
        LPCSTR auth_value = ap_getword_white(request->pool, &authorization_header);
        if(!auth_value)
            return HTTP_UNAUTHORIZED;

        // decode the supplied token
        size_t inputTokenLength = apr_base64_decode_len(auth_value);
        LPBYTE inputToken = (LPBYTE)apr_pcalloc(request->pool, inputTokenLength);
        if(!inputToken)
        {
            ap_log_rerror(APLOG_MARK, PORTABLE_APLOG_ERR, request, "mod_spnego: apr_pcalloc failed");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        inputTokenLength = apr_base64_decode_binary(inputToken, auth_value);

        // validate the token
        LPBYTE outputToken = NULL;
        size_t outputTokenLength = 0;
        int rc = handleSpnegoToken(request,
            inputToken,
            inputTokenLength,
            &outputToken, // allocated from the request's pool, no need to free
            &outputTokenLength
        );
        ap_log_rerror(APLOG_MARK, PORTABLE_APLOG_INFO, request, "mod_spnego: handleSpnegoToken returned %d", rc);

        // encode Windows' reply
        LPSTR auth_return = (LPSTR)apr_pcalloc(request->pool, apr_base64_encode_len((int) outputTokenLength));
        if(!auth_return)
        {
            ap_log_rerror(APLOG_MARK, PORTABLE_APLOG_ERR, request, "mod_spnego: apr_pcalloc failed");
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        apr_base64_encode_binary(auth_return, outputToken, (int)outputTokenLength);
        ap_log_rerror(APLOG_MARK, PORTABLE_APLOG_INFO, request, "mod_spnego: WWW-Authenticate value is \"Negotiate %s\"", auth_return);

        // and now reply the encoded value
        apr_table_set(
            request->err_headers_out,
            "WWW-Authenticate",
            apr_pstrcat(request->pool, "Negotiate ", auth_return, NULL)
        );

        ap_log_rerror(APLOG_MARK, PORTABLE_APLOG_INFO, request, "mod_spnego: authenticate_user returning %d", rc);
        return rc;
    }

    // the client did not authenticate with 'Negotiate', so deny access
    return HTTP_UNAUTHORIZED;
}

/**
 * Authorizes a user (or an Apache client).
 *
 * @param [in,out]  request   If non-null, the request_rec * to process.
 *
 * @return A HTTP_Status code.
 */
static int authorize_user(
    request_rec * request)
{
    const char *authType = NULL;
    int methodRestricted = 0;
    require_line *reqs;
    PDIRECTORY_CONFIG directoryConfig = (PDIRECTORY_CONFIG)ap_get_module_config(request->per_dir_config, &spnego_module);
    const apr_array_header_t *reqs_arr = ap_requires(request);
    int rc = OK;
    const char *require;
    const char *word;
    register int i;

    errno = 0;
    ap_log_rerror(APLOG_MARK, PORTABLE_APLOG_INFO, request, "mod_spnego: entering authorize_user");
    ap_log_rerror(APLOG_MARK, PORTABLE_APLOG_INFO, request, "mod_spnego: user is %s", request->user);

    /* Check AuthType. */
    authType = ap_auth_type(request);

	if (!authType || strcasecmp(authType, "SPNEGO"))
	{
		ap_log_rerror(APLOG_MARK, PORTABLE_APLOG_INFO, request, "mod_spnego: unrecognized AuthType \'%s\'", authType ? authType : "NULL");

        return DECLINED;
    }

    if(!directoryConfig->krb5AuthorizeFlag)
    {
        ap_log_rerror(APLOG_MARK, PORTABLE_APLOG_INFO, request, "mod_spnego: Authorize Flag = 0");
        return DECLINED;
    }
    if(!ap_is_initial_req(request) && !request->user)
    {
        ap_log_rerror(APLOG_MARK, PORTABLE_APLOG_INFO, request, "mod_spnego: ap_is_initial_req returned 0");

        rc = HTTP_UNAUTHORIZED;

        ap_log_rerror(APLOG_MARK, PORTABLE_APLOG_INFO, request, "mod_spnego: authorize_user returning %d", rc);
        return rc;
    }

    /*
     * What does the following check do? The author's testing shows that if Require
     * is not defined, authenticate_user and authorize_user are not called.
     */
    if(!reqs_arr)
    {
        ap_log_rerror(APLOG_MARK, PORTABLE_APLOG_INFO, request, "mod_spnego: Require directive not present");
        ap_log_rerror(APLOG_MARK, PORTABLE_APLOG_INFO, request, "mod_spnego: authorize_user returning OK");
        return OK;
    }

    reqs = (require_line*)reqs_arr->elts;
    for (i = 0; i < reqs_arr->nelts; i++)
    {
        require = reqs[i].requirement;
        ap_log_rerror(APLOG_MARK, PORTABLE_APLOG_INFO, request, "mod_spnego: Require[%d] %s", i, require);

        if(!(reqs[i].method_mask & (AP_METHOD_BIT << request->method_number)))
        {
            ap_log_rerror(APLOG_MARK, PORTABLE_APLOG_INFO, request, "continue");
            continue;
        }
        methodRestricted = 1;
        word = ap_getword_white(request->pool, (const char **) &require);

        if(!strcmp(word, "valid-user"))
        {
            ap_log_rerror(APLOG_MARK, PORTABLE_APLOG_INFO, request, "mod_spnego: authorize_user returning OK");
            return OK;
        }
        else if (!strcmp(word, "user"))
        {
            while (require[0])
            {
                word = ap_getword_conf(request->pool, (const char **) &require);

                if (!strcmp(request->user, word))
                {
                    ap_log_rerror(APLOG_MARK, PORTABLE_APLOG_INFO, request, "mod_spnego: authorize_user returning OK");
                    return OK;
                }
            }
        }
    }

    if (!methodRestricted)
    {
        ap_log_rerror(APLOG_MARK, PORTABLE_APLOG_INFO, request, "mod_spnego: authorize_user returning OK");
		
        return OK;
    }
	
    ap_log_rerror(APLOG_MARK, PORTABLE_APLOG_INFO, request, "access to %s failed, reason: user %s not allowed access", request->uri, request->user);
    ap_log_rerror(APLOG_MARK, PORTABLE_APLOG_INFO, request, "mod_spnego: authorize_user returning HTTP_UNAUTHORIZED");
    return HTTP_UNAUTHORIZED;
}

/**
 * Sets the krb5AuthEachReq element in a SERVER_CONFIG structure.
 *
 * @param [in,out]  cmd     If non-null, the command.
 * @param [in,out]  config  Unused
 * @param   krb5AuthEachReq 0 for shared authentication, any other value to authenticate each request.
 *
 * @return Always NULL.
 */
static LPCSTR setKrb5AuthEachReq(
    cmd_parms * cmd,
    void *config,
    int krb5AuthEachReq)
{
    PSERVER_CONFIG serverConfig = (PSERVER_CONFIG)ap_get_module_config(cmd->server->module_config, &spnego_module);
    OutputDebugString("mod_spnego: setKrb5AuthEachReq krb5AuthEachReq=");
    OutputDebugString(krb5AuthEachReq == 0 ? "no\n" : "yes\n");
    serverConfig->krb5AuthEachReq = krb5AuthEachReq;
    return NULL;
}

/**
 * Sets the krb5ServiceName element in a DIRECTORY_CONFIG structure.
 *
 * @param [in,out]  cmd     If non-null, the command.
 * @param [in,out]  config  If non-null, the configuration.
 * @param   krb5ServiceName Name of the kerberos service.
 *
 * @return Always NULL.
 */
static LPCSTR setKrb5ServiceName(
    cmd_parms * cmd,
    void *config,
    const LPSTR krb5ServiceName)
{
    OutputDebugString("mod_spnego: setKrb5ServiceName to ");
    OutputDebugString(krb5ServiceName);
    OutputDebugString("\n");
    ((PDIRECTORY_CONFIG)config)->krb5ServiceName = apr_pstrdup(cmd->pool, krb5ServiceName);
    return NULL;
}

/**
 * Sets the krb5RemoveDomain flag in a DIRECTORY_CONFIG structure.
 *
 * @param [in,out]  cmd         If non-null, the command.
 * @param [in,out]  config      If non-null, the configuration.
 * @param   krb5RemoveDomain    "0" to NOT strip the domain name from the user's login, any other number to strip it.
 *
 * @return Always NULL.
 */
static LPCSTR setKrb5RemoveDomain(
    cmd_parms * cmd,
    void *config,
    const char *krb5RemoveDomain)
{
    OutputDebugString("mod_spnego: setKrb5RemoveDomain krb5RemoveDomain=");
    OutputDebugString(krb5RemoveDomain);
    OutputDebugString("\n");
    ((PDIRECTORY_CONFIG)config)->krb5RemoveDomain = atoi(krb5RemoveDomain);
    return NULL;
}

/**
 * Sets the krb5AuthorizeFlag flag in a DIRECTORY_CONFIG structure.
 *
 * @param [in,out]  cmd         If non-null, the command.
 * @param [in,out]  config      If non-null, the configuration.
 * @param   krb5AuthorizeFlag   The krb 5 authorize flag.
 *
 * @return Always NULL.
 */
static LPCSTR setKrb5AuthorizeFlag(
    cmd_parms * cmd,
    void *config,
    const char *krb5AuthorizeFlag)
{
    OutputDebugString("mod_spnego: setKrb5AuthorizeFlag krb5AuthorizeFlag=%d\n");
    OutputDebugString(krb5AuthorizeFlag);
    OutputDebugString("\n");
    ((PDIRECTORY_CONFIG)config)->krb5AuthorizeFlag = atoi(krb5AuthorizeFlag);
    return NULL;
}

static PCONNECTION_CONFIG get_connection_config(
    request_rec* request)
{
    if(!request)
    {
        ap_log_rerror(APLOG_MARK, PORTABLE_APLOG_ERR, request, "mod_spnego: get_connection_config request is null");
        return NULL;
    }

    PCONNECTION_CONFIG conn_config = (PCONNECTION_CONFIG)ap_get_module_config(request->connection->conn_config, &spnego_module);
    if(!conn_config)
    {
        conn_config = (PCONNECTION_CONFIG)apr_pcalloc(request->connection->pool, sizeof(CONNECTION_CONFIG));
        if(!conn_config)
        {
            ap_log_rerror(APLOG_MARK, PORTABLE_APLOG_ERR, request, "mod_spnego: get_connection_config could not allocate connection config");
            return NULL;
        }
        ap_set_module_config(request->connection->conn_config, &spnego_module, conn_config);
    }

    return conn_config;
}

/**
 * Creates a per directory configuration structure (DIRECTORY_CONFIG).
 *
 * @param [in,out]  pool   to process.
 * @param   dir         If non-null, the dir.
 *
 * @return  A pointer to a directory configuration structure initialized with,
 *   default values.
 */
static LPVOID create_directory_config(
    apr_pool_t* pool,
    LPSTR dir)
{
    if(!dir)
    {
        OutputDebugString("mod_spnego: returning NULL from create_directory_config because dir is NULL\n");
        return NULL;
    }

    OutputDebugString("mod_spnego: entering create_directory_config, directory: ");
    OutputDebugString(dir);
    OutputDebugString("\n");

    PDIRECTORY_CONFIG directory_config = (DIRECTORY_CONFIG*)apr_pcalloc(pool, sizeof(DIRECTORY_CONFIG));
    if(!directory_config)
    {
        OutputDebugString("mod_spnego: returning NULL from create_directory_config, could not allocate DIRECTORY_CONFIG structure\n");
        return NULL;
    }

    directory_config->krb5KeyTabFile = NULL;
    directory_config->krb5ServiceName = NULL;
    directory_config->krb5AuthorizeFlag = 0;
    directory_config->krb5RemoveDomain = 0;
    OutputDebugString("mod_spnego: leaving create_directory_config\n");
    return directory_config;
}

/**
 * Creates a per server configuration structure.
 *
 * @param [in,out]  p   If non-null, the apr_pool_t * to process.
 * @param [in,out]  s   If non-null, the server_rec * to process.
 *
 * @return A pointer to the configuration structure, initialized with default values.
 */
static LPVOID create_server_config(
    apr_pool_t * p,
    server_rec * s)
{
    OutputDebugString("mod_spnego: entering create_server_config\n");
    PSERVER_CONFIG server_config = (PSERVER_CONFIG)apr_pcalloc(p, sizeof(SERVER_CONFIG));

    if(!server_config)
    {
        OutputDebugString("mod_spnego: could not create SERVER_CONFIG structure, returning null\n");
        return NULL;
    }

    server_config->krb5AuthEachReq = 1;

    OutputDebugString("mod_spnego: leaving create_server_config\n");
    return server_config;
}

/**
 * Registers the module's hook functions.
 *
 * @param [in,out]  pool   If non-null, the apr_pool_t * to process.
 */
static void register_hooks(
    apr_pool_t * pool)
{
    OutputDebugString("mod_spnego: entering register_hooks\n");
    ap_hook_check_user_id(authenticate_user, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_auth_checker(authorize_user, NULL, NULL, APR_HOOK_MIDDLE);
    OutputDebugString("mod_spnego: leaving register_hooks\n");
}

///< Array of the directory directives for this module.
static const command_rec SPNEGO_DIRECTIVES[] =
{
    {
        "Krb5AuthEachReq",
        (cmd_func) setKrb5AuthEachReq,
        NULL,
        RSRC_CONF,
        FLAG,
        "Require Kerberos V5 authentication for each request."
    },

    {
        "Krb5ServiceName",
        (cmd_func) setKrb5ServiceName,
        NULL,
        OR_AUTHCFG,
        RAW_ARGS,
        "Kerberos V5 service name."
    },

    {
        "Krb5AuthorizeFlag",
        (cmd_func) setKrb5AuthorizeFlag,
        NULL,
        OR_AUTHCFG,
        RAW_ARGS,
        "Kerberos V5 Authorize Flag."
    },

    {
        "Krb5RemoveDomain",
        (cmd_func) setKrb5RemoveDomain,
        NULL,
        OR_AUTHCFG,
        RAW_ARGS,
        "Kerberos V5 remove domain from username."
    },

    {NULL}
};

///< Apache module definition.
extern "C" module AP_MODULE_DECLARE_DATA spnego_module =
{
    STANDARD20_MODULE_STUFF,
    create_directory_config,    // create_dir_config
    NULL,                       // merge_dir_config
    create_server_config,       // create_server_config
    NULL,                       // merge_server_config
    SPNEGO_DIRECTIVES,          // cmds
    register_hooks              // register_hooks
};

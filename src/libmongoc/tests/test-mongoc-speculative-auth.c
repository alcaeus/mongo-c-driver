/*
 * Copyright 2016 MongoDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <mongoc/mongoc.h>
#ifdef _POSIX_VERSION
#include <sys/utsname.h>
#endif

#include "mongoc/mongoc-client-private.h"
#include "mongoc/mongoc-handshake.h"
#include "mongoc/mongoc-handshake-private.h"

#include "TestSuite.h"
#include "test-libmongoc.h"
#include "test-conveniences.h"
#include "mock_server/future.h"
#include "mock_server/future-functions.h"
#include "mock_server/mock-server.h"

typedef void (*setup_uri_options_t) (mongoc_uri_t *uri);

/* For single threaded clients, to cause an isMaster to be sent, we must wait
 * until we're overdue for a heartbeat, and then execute some command */
static future_t *
_force_ismaster_with_ping (mongoc_client_t *client, int heartbeat_ms)
{
   future_t *future;

   /* Wait until we're overdue to send an isMaster */
   _mongoc_usleep (heartbeat_ms * 2 * 1000);

   /* Send a ping */
   future = future_client_command_simple (
         client, "admin", tmp_bson ("{'ping': 1}"), NULL, NULL, NULL);
         ASSERT (future);
   return future;
}

/* Call after we've dealt with the isMaster sent by
 * _force_ismaster_with_ping */
static void
_respond_to_ping (future_t *future, mock_server_t *server)
{
   request_t *request;

   ASSERT (future);

   request = mock_server_receives_command (
         server, "admin", MONGOC_QUERY_SLAVE_OK, "{'ping': 1}");

   ASSERT (request);

   mock_server_replies_simple (request, "{'ok': 1}");

   ASSERT (future_get_bool (future));
   future_destroy (future);
   request_destroy (request);
}

static bool
_auto_ismaster_without_speculative_auth (request_t *request, void *data)
{
   const char *response_json = (const char *) data;
   char *quotes_replaced;

   if (!request->is_command || strcasecmp (request->command_name, "ismaster")) {
      return false;
   }

   if (bson_has_field (request_get_doc(request, 0), "speculativeAuthenticate")) {
      return false;
   }

   quotes_replaced = single_quotes_to_double (response_json);

   if (mock_server_get_rand_delay (request->server)) {
      _mongoc_usleep ((int64_t) (rand () % 10) * 1000);
   }

   mock_server_replies (request, MONGOC_REPLY_NONE, 0, 0, 1, response_json);

   bson_free (quotes_replaced);
   request_destroy (request);
   return true;
}

static void
_test_mongoc_speculative_auth_pool (setup_uri_options_t setup_uri_options, bool includes_speculative_auth, bson_t *expected_auth_cmd, bson_t *speculative_auth_response)
{
   mock_server_t *server;
   mongoc_uri_t *uri;
   mongoc_client_t *client;
   mongoc_client_pool_t *pool;
   request_t *request;
   const bson_t *request_doc;
   bson_iter_t iter;
   future_t *future;
   const int heartbeat_ms = 500;

   mongoc_ssl_opt_t client_ssl_opts = {0};
   mongoc_ssl_opt_t server_ssl_opts = {0};
   client_ssl_opts.ca_file = CERT_CA;
   client_ssl_opts.pem_file = CERT_CLIENT;
   server_ssl_opts.ca_file = CERT_CA;
   server_ssl_opts.pem_file = CERT_SERVER;

   server = mock_server_new ();
   mock_server_set_ssl_opts (server, &server_ssl_opts);
   mock_server_autoresponds (server, _auto_ismaster_without_speculative_auth, "{'ok': 1, 'ismaster': true, 'minWireVersion': 2, 'maxWireVersion': 5}", NULL);

   mock_server_run (server);
   uri = mongoc_uri_copy (mock_server_get_uri (server));
   mongoc_uri_set_option_as_int32 (uri, MONGOC_URI_HEARTBEATFREQUENCYMS, heartbeat_ms);

   if (setup_uri_options) {
      setup_uri_options (uri);
   }

   pool = mongoc_client_pool_new (uri);
   mongoc_client_pool_set_ssl_opts (pool, &client_ssl_opts);

   /* Force topology scanner to start */
   client = mongoc_client_pool_pop (pool);

   future = _force_ismaster_with_ping (client, heartbeat_ms);

   // isMaster should use speculative authentication
   if (includes_speculative_auth) {
      request = mock_server_receives_ismaster(server);
      ASSERT (request);
      request_doc = request_get_doc(request, 0);
      ASSERT (request_doc);
      ASSERT (bson_has_field(request_doc, "isMaster"));
      ASSERT (bson_has_field(request_doc, "speculativeAuthenticate") == includes_speculative_auth);

      if (expected_auth_cmd) {
         ASSERT (bson_iter_init_find(&iter, request_doc, "speculativeAuthenticate"));
         bson_t auth_cmd;
         uint32_t len;
         const uint8_t *data;

         bson_iter_document(&iter, &len, &data);

         ASSERT (bson_init_static(&auth_cmd, data, len));
         ASSERT_CMPJSON (bson_as_canonical_extended_json(&auth_cmd, NULL),
                         bson_as_canonical_extended_json(expected_auth_cmd, NULL));
      }

      // Include authentication information in response
      bson_t *response = BCON_NEW (
            "ok", BCON_INT32(1),
            "ismaster", BCON_BOOL(true),
            "minWireVersion", BCON_INT32(2),
            "maxWireVersion", BCON_INT32(5)
      );

      if (speculative_auth_response) {
         BSON_APPEND_DOCUMENT (response, "speculativeAuthenticate", speculative_auth_response);
      }

      mock_server_replies_simple(request, bson_as_canonical_extended_json(response, NULL));
      bson_destroy(response);
      request_destroy(request);
   }

   if (includes_speculative_auth && ! speculative_auth_response) {
      // Todo: handle authentication request
   }

   _respond_to_ping (future, server);

   /* Cleanup */
   mongoc_client_pool_push (pool, client);
   mongoc_client_pool_destroy (pool);
   mongoc_uri_destroy (uri);
   mock_server_destroy (server);
}

static void
_test_mongoc_speculative_auth (setup_uri_options_t setup_uri_options, bool includes_speculative_auth, bson_t *expected_auth_cmd, bson_t *speculative_auth_response)
{
   mock_server_t *server;
   mongoc_uri_t *uri;
   mongoc_client_t *client;
   request_t *request;
   const bson_t *request_doc;
   bson_iter_t iter;
   future_t *future;
   const int heartbeat_ms = 500;

   server = mock_server_new ();
   mock_server_run (server);
   uri = mongoc_uri_copy (mock_server_get_uri (server));
   mongoc_uri_set_option_as_int32 (uri, MONGOC_URI_HEARTBEATFREQUENCYMS, heartbeat_ms);

   if (setup_uri_options) {
      setup_uri_options (uri);
   }

   client = mongoc_client_new_from_uri (uri);
   future = _force_ismaster_with_ping (client, heartbeat_ms);

   request = mock_server_receives_ismaster (server);
   ASSERT (request);
   request_doc = request_get_doc (request, 0);
   ASSERT (request_doc);
   ASSERT (bson_has_field (request_doc, "isMaster"));
   ASSERT (bson_has_field (request_doc, "speculativeAuthenticate") == includes_speculative_auth);

   if (includes_speculative_auth && expected_auth_cmd) {
      ASSERT (bson_iter_init_find (&iter, request_doc, "speculativeAuthenticate"));
      bson_t auth_cmd;
      uint32_t len;
      const uint8_t *data;

      bson_iter_document(&iter, &len, &data);

      ASSERT (bson_init_static (&auth_cmd, data, len));
      ASSERT_CMPJSON (bson_as_canonical_extended_json (&auth_cmd, NULL), bson_as_canonical_extended_json (expected_auth_cmd, NULL));
   }

   // Include authentication information in response
   bson_t *response = BCON_NEW (
      "ok", BCON_INT32 (1),
      "ismaster", BCON_BOOL (true),
      "minWireVersion", BCON_INT32 (2),
      "maxWireVersion", BCON_INT32 (5)
   );

   if (speculative_auth_response) {
      BSON_APPEND_DOCUMENT (response, "speculativeAuthenticate", speculative_auth_response);
   }

   mock_server_replies_simple (request, bson_as_canonical_extended_json (response, NULL));
   bson_destroy (response);
   request_destroy (request);

   if (includes_speculative_auth && ! speculative_auth_response) {
      // Todo: handle authentication request
   }

   _respond_to_ping (future, server);

   /* Cleanup */
   mongoc_client_destroy (client);
   mongoc_uri_destroy (uri);
   mock_server_destroy (server);
}

static void
_setup_speculative_auth_x_509 (mongoc_uri_t *uri)
{
   mongoc_uri_set_auth_mechanism (uri, "MONGODB-X509");
   mongoc_uri_set_username (uri, "CN=myName,OU=myOrgUnit,O=myOrg,L=myLocality,ST=myState,C=myCountry");
}

static void
test_mongoc_speculative_auth_request_none (void)
{
   _test_mongoc_speculative_auth (NULL, false, NULL, NULL);
}

static void
test_mongoc_speculative_auth_request_none_pool (void)
{
   _test_mongoc_speculative_auth_pool (NULL, false, NULL, NULL);
}

static void
test_mongoc_speculative_auth_request_x509 (void)
{
   _test_mongoc_speculative_auth (
      _setup_speculative_auth_x_509,
      true,
      BCON_NEW (
         "authenticate", BCON_INT32 (1),
         "mechanism", BCON_UTF8 ("MONGODB-X509"),
         "user", BCON_UTF8 ("CN=myName,OU=myOrgUnit,O=myOrg,L=myLocality,ST=myState,C=myCountry"),
         "db", BCON_UTF8 ("$external")
      ),
      BCON_NEW (
         "dbname", BCON_UTF8 ("$external"),
         "user", BCON_UTF8 ("CN=myName,OU=myOrgUnit,O=myOrg,L=myLocality,ST=myState,C=myCountry")
      )
   );
}

static void
test_mongoc_speculative_auth_request_x509_pool (void)
{
   _test_mongoc_speculative_auth_pool (
      _setup_speculative_auth_x_509,
      true,
      BCON_NEW (
         "authenticate", BCON_INT32 (1),
         "mechanism", BCON_UTF8 ("MONGODB-X509"),
         "user", BCON_UTF8 ("CN=myName,OU=myOrgUnit,O=myOrg,L=myLocality,ST=myState,C=myCountry"),
         "db", BCON_UTF8 ("$external")
      ),
      BCON_NEW (
         "dbname", BCON_UTF8 ("$external"),
         "user", BCON_UTF8 ("CN=myName,OU=myOrgUnit,O=myOrg,L=myLocality,ST=myState,C=myCountry")
      )
   );
}

void
test_speculative_auth_install (TestSuite *suite)
{
   TestSuite_AddMockServerTest (suite,
                  "/MongoDB/speculative_auth/request_none",
                  test_mongoc_speculative_auth_request_none);
   TestSuite_AddMockServerTest (suite,
                  "/MongoDB/speculative_auth/request_x509",
                  test_mongoc_speculative_auth_request_x509);
   TestSuite_AddMockServerTest (suite,
                  "/MongoDB/speculative_auth_pool/request_none",
                  test_mongoc_speculative_auth_request_none_pool);
   TestSuite_AddMockServerTest (suite,
                  "/MongoDB/speculative_auth_pool/request_x509",
                  test_mongoc_speculative_auth_request_x509_pool);
}

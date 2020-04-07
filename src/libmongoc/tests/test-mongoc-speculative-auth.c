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

static void
_test_mongoc_speculative_auth (setup_uri_options_t setup_uri_options, bool includes_speculative_auth, bson_t *expected_auth_cmd)
{
   mock_server_t *server;
   mongoc_uri_t *uri;
   mongoc_client_t *client;
   mongoc_client_pool_t *pool;
   request_t *request;
   const bson_t *request_doc;
   bson_iter_t iter;

   server = mock_server_new ();
   mock_server_run (server);
   uri = mongoc_uri_copy (mock_server_get_uri (server));
   mongoc_uri_set_option_as_int32 (uri, MONGOC_URI_HEARTBEATFREQUENCYMS, 500);

   if (setup_uri_options) {
      setup_uri_options (uri);
   }

   pool = mongoc_client_pool_new (uri);

   /* Force topology scanner to start */
   client = mongoc_client_pool_pop (pool);

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

   // Todo: Include authentication information in response
   mock_server_replies_simple (request, "{'ok': 1, 'ismaster': true}");
   request_destroy (request);

   // Todo: Perform authentication cycle

   /* Cleanup */
   mongoc_client_pool_push (pool, client);
   mongoc_client_pool_destroy (pool);
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
   _test_mongoc_speculative_auth (NULL, false, NULL);
}

static void
test_mongoc_speculative_auth_request_x509 (void)
{
   _test_mongoc_speculative_auth (_setup_speculative_auth_x_509, true, BCON_NEW (
         "authenticate", BCON_INT32 (1),
         "mechanism", BCON_UTF8 ("MONGODB-X509"),
         "user", BCON_UTF8 ("CN=myName,OU=myOrgUnit,O=myOrg,L=myLocality,ST=myState,C=myCountry"),
         "db", BCON_UTF8 ("$external")
   ));
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
}

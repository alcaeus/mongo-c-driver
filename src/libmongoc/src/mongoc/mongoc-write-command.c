/*
 * Copyright 2014 MongoDB, Inc.
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

#include <bson/bson.h>

#include "mongoc-client-private.h"
#include "mongoc-client-session-private.h"
#include "mongoc-client-side-encryption-private.h"
#include "mongoc-error.h"
#include "mongoc-error-private.h"
#include "mongoc-trace-private.h"
#include "mongoc-write-command-private.h"
#include "mongoc-write-command-legacy-private.h"
#include "mongoc-write-concern-private.h"
#include "mongoc-util-private.h"
#include "mongoc-opts-private.h"


/*
 * TODO:
 *
 *    - Remove error parameter to ops, favor result->error.
 */

typedef void (*mongoc_write_op_t) (mongoc_write_command_t *command,
                                   mongoc_client_t *client,
                                   mongoc_server_stream_t *server_stream,
                                   const char *database,
                                   const char *collection,
                                   uint32_t offset,
                                   mongoc_write_result_t *result,
                                   bson_error_t *error);


/* indexed by MONGOC_WRITE_COMMAND_DELETE, INSERT, UPDATE */
static const char *gCommandNames[] = {"delete", "insert", "update"};
static const char *gCommandFields[] = {"deletes", "documents", "updates"};
static const uint32_t gCommandFieldLens[] = {7, 9, 7};

static mongoc_write_op_t gLegacyWriteOps[3] = {
   _mongoc_write_command_delete_legacy,
   _mongoc_write_command_insert_legacy,
   _mongoc_write_command_update_legacy};


const char *
_mongoc_command_type_to_name (int command_type)
{
   return gCommandNames[command_type];
}

const char *
_mongoc_command_type_to_field_name (int command_type)
{
   return gCommandFields[command_type];
}

void
_mongoc_write_command_insert_append (mongoc_write_command_t *command,
                                     const bson_t *document)
{
   bson_iter_t iter;
   bson_oid_t oid;
   bson_t tmp;

   ENTRY;

   BSON_ASSERT (command);
   BSON_ASSERT (command->type == MONGOC_WRITE_COMMAND_INSERT);
   BSON_ASSERT (document);
   BSON_ASSERT (document->len >= 5);

   /*
    * If the document does not contain an "_id" field, we need to generate
    * a new oid for "_id".
    */
   if (!bson_iter_init_find (&iter, document, "_id")) {
      bson_init (&tmp);
      bson_oid_init (&oid, NULL);
      BSON_APPEND_OID (&tmp, "_id", &oid);
      bson_concat (&tmp, document);
      _mongoc_buffer_append (&command->payload, bson_get_data (&tmp), tmp.len);
      bson_destroy (&tmp);
   } else {
      _mongoc_buffer_append (
         &command->payload, bson_get_data (document), document->len);
   }

   command->n_documents++;

   EXIT;
}

void
_mongoc_write_command_update_append (mongoc_write_command_t *command,
                                     const bson_t *selector,
                                     const bson_t *update,
                                     const bson_t *opts)
{
   bson_t document;

   ENTRY;

   BSON_ASSERT (command);
   BSON_ASSERT (command->type == MONGOC_WRITE_COMMAND_UPDATE);
   BSON_ASSERT (selector && update);

   bson_init (&document);
   BSON_APPEND_DOCUMENT (&document, "q", selector);
   if (_mongoc_document_is_pipeline (update)) {
      BSON_APPEND_ARRAY (&document, "u", update);
   } else {
      BSON_APPEND_DOCUMENT (&document, "u", update);
   }
   if (opts) {
      bson_concat (&document, opts);
   }

   _mongoc_buffer_append (
      &command->payload, bson_get_data (&document), document.len);
   command->n_documents++;

   bson_destroy (&document);

   EXIT;
}

void
_mongoc_write_command_delete_append (mongoc_write_command_t *command,
                                     const bson_t *selector,
                                     const bson_t *opts)
{
   bson_t document;

   ENTRY;

   BSON_ASSERT (command);
   BSON_ASSERT (command->type == MONGOC_WRITE_COMMAND_DELETE);
   BSON_ASSERT (selector);

   BSON_ASSERT (selector->len >= 5);

   bson_init (&document);
   BSON_APPEND_DOCUMENT (&document, "q", selector);
   if (opts) {
      bson_concat (&document, opts);
   }

   _mongoc_buffer_append (
      &command->payload, bson_get_data (&document), document.len);
   command->n_documents++;

   bson_destroy (&document);

   EXIT;
}

void
_mongoc_write_command_init_bulk (mongoc_write_command_t *command,
                                 int type,
                                 mongoc_bulk_write_flags_t flags,
                                 int64_t operation_id,
                                 const bson_t *opts)
{
   ENTRY;

   BSON_ASSERT (command);

   command->type = type;
   command->flags = flags;
   command->operation_id = operation_id;
   if (!bson_empty0 (opts)) {
      bson_copy_to (opts, &command->cmd_opts);
   } else {
      bson_init (&command->cmd_opts);
   }

   _mongoc_buffer_init (&command->payload, NULL, 0, NULL, NULL);
   command->n_documents = 0;

   EXIT;
}


void
_mongoc_write_command_init_insert (mongoc_write_command_t *command, /* IN */
                                   const bson_t *document,          /* IN */
                                   const bson_t *cmd_opts,          /* IN */
                                   mongoc_bulk_write_flags_t flags, /* IN */
                                   int64_t operation_id)            /* IN */
{
   ENTRY;

   BSON_ASSERT (command);

   _mongoc_write_command_init_bulk (
      command, MONGOC_WRITE_COMMAND_INSERT, flags, operation_id, cmd_opts);

   /* must handle NULL document from mongoc_collection_insert_bulk */
   if (document) {
      _mongoc_write_command_insert_append (command, document);
   }

   EXIT;
}


void
_mongoc_write_command_init_insert_idl (mongoc_write_command_t *command,
                                       const bson_t *document,
                                       const bson_t *cmd_opts,
                                       int64_t operation_id)
{
   mongoc_bulk_write_flags_t flags = MONGOC_BULK_WRITE_FLAGS_INIT;

   ENTRY;

   BSON_ASSERT (command);

   _mongoc_write_command_init_bulk (
      command, MONGOC_WRITE_COMMAND_INSERT, flags, operation_id, cmd_opts);

   /* must handle NULL document from mongoc_collection_insert_bulk */
   if (document) {
      _mongoc_write_command_insert_append (command, document);
   }

   EXIT;
}


void
_mongoc_write_command_init_delete (mongoc_write_command_t *command, /* IN */
                                   const bson_t *selector,          /* IN */
                                   const bson_t *cmd_opts,          /* IN */
                                   const bson_t *opts,              /* IN */
                                   mongoc_bulk_write_flags_t flags, /* IN */
                                   int64_t operation_id)            /* IN */
{
   ENTRY;

   BSON_ASSERT (command);
   BSON_ASSERT (selector);

   _mongoc_write_command_init_bulk (
      command, MONGOC_WRITE_COMMAND_DELETE, flags, operation_id, cmd_opts);
   _mongoc_write_command_delete_append (command, selector, opts);

   EXIT;
}


void
_mongoc_write_command_init_delete_idl (mongoc_write_command_t *command,
                                       const bson_t *selector,
                                       const bson_t *cmd_opts,
                                       const bson_t *opts,
                                       int64_t operation_id)
{
   mongoc_bulk_write_flags_t flags = MONGOC_BULK_WRITE_FLAGS_INIT;

   ENTRY;

   BSON_ASSERT (command);
   BSON_ASSERT (selector);

   _mongoc_write_command_init_bulk (
      command, MONGOC_WRITE_COMMAND_DELETE, flags, operation_id, cmd_opts);

   _mongoc_write_command_delete_append (command, selector, opts);

   EXIT;
}


void
_mongoc_write_command_init_update (mongoc_write_command_t *command, /* IN */
                                   const bson_t *selector,          /* IN */
                                   const bson_t *update,            /* IN */
                                   const bson_t *opts,              /* IN */
                                   mongoc_bulk_write_flags_t flags, /* IN */
                                   int64_t operation_id)            /* IN */
{
   ENTRY;

   BSON_ASSERT (command);
   BSON_ASSERT (selector);
   BSON_ASSERT (update);

   _mongoc_write_command_init_bulk (
      command, MONGOC_WRITE_COMMAND_UPDATE, flags, operation_id, NULL);
   _mongoc_write_command_update_append (command, selector, update, opts);

   EXIT;
}


void
_mongoc_write_command_init_update_idl (mongoc_write_command_t *command,
                                       const bson_t *selector,
                                       const bson_t *update,
                                       const bson_t *opts,
                                       int64_t operation_id)
{
   mongoc_bulk_write_flags_t flags = MONGOC_BULK_WRITE_FLAGS_INIT;

   ENTRY;

   BSON_ASSERT (command);

   _mongoc_write_command_init_bulk (
      command, MONGOC_WRITE_COMMAND_UPDATE, flags, operation_id, NULL);
   _mongoc_write_command_update_append (command, selector, update, opts);

   EXIT;
}


/* takes initialized bson_t *doc and begins formatting a write command */
void
_mongoc_write_command_init (bson_t *doc,
                            mongoc_write_command_t *command,
                            const char *collection)
{
   ENTRY;

   if (!command->n_documents) {
      EXIT;
   }

   BSON_APPEND_UTF8 (doc, gCommandNames[command->type], collection);
   BSON_APPEND_BOOL (doc, "ordered", command->flags.ordered);

   if (command->flags.bypass_document_validation) {
      BSON_APPEND_BOOL (doc,
                        "bypassDocumentValidation",
                        command->flags.bypass_document_validation);
   }

   EXIT;
}


/*
 *-------------------------------------------------------------------------
 *
 * _mongoc_write_command_too_large_error --
 *
 *       Fill a bson_error_t and optional bson_t with error info after
 *       receiving a document for bulk insert, update, or remove that is
 *       larger than max_bson_size.
 *
 *       "err_doc" should be NULL or an empty initialized bson_t.
 *
 * Returns:
 *       None.
 *
 * Side effects:
 *       "error" and optionally "err_doc" are filled out.
 *
 *-------------------------------------------------------------------------
 */

void
_mongoc_write_command_too_large_error (bson_error_t *error,
                                       int32_t idx,
                                       int32_t len,
                                       int32_t max_bson_size)
{
   bson_set_error (error,
                   MONGOC_ERROR_BSON,
                   MONGOC_ERROR_BSON_INVALID,
                   "Document %u is too large for the cluster. "
                   "Document is %u bytes, max is %d.",
                   idx,
                   len,
                   max_bson_size);
}


void
_empty_error (mongoc_write_command_t *command, bson_error_t *error)
{
   static const uint32_t codes[] = {MONGOC_ERROR_COLLECTION_DELETE_FAILED,
                                    MONGOC_ERROR_COLLECTION_INSERT_FAILED,
                                    MONGOC_ERROR_COLLECTION_UPDATE_FAILED};

   bson_set_error (error,
                   MONGOC_ERROR_COLLECTION,
                   codes[command->type],
                   "Cannot do an empty %s",
                   gCommandNames[command->type]);
}


bool
_mongoc_write_command_will_overflow (uint32_t len_so_far,
                                     uint32_t document_len,
                                     uint32_t n_documents_written,
                                     int32_t max_bson_size,
                                     int32_t max_write_batch_size)
{
   /* max BSON object size + 16k bytes.
    * server guarantees there is enough room: SERVER-10643
    */
   int32_t max_cmd_size = max_bson_size + BSON_OBJECT_ALLOWANCE;

   BSON_ASSERT (max_bson_size);

   if (len_so_far + document_len > max_cmd_size) {
      return true;
   } else if (max_write_batch_size > 0 &&
              n_documents_written >= max_write_batch_size) {
      return true;
   }

   return false;
}


static void
_mongoc_write_opmsg (mongoc_write_command_t *command,
                     mongoc_client_t *client,
                     mongoc_server_stream_t *server_stream,
                     const char *database,
                     const char *collection,
                     const mongoc_write_concern_t *write_concern,
                     uint32_t index_offset,
                     mongoc_client_session_t *cs,
                     mongoc_write_result_t *result,
                     bson_error_t *error)
{
   mongoc_cmd_parts_t parts;
   bson_iter_t iter;
   bson_t cmd;
   bson_t reply;
   bool ret = false;
   int32_t max_msg_size;
   int32_t max_bson_obj_size;
   int32_t max_document_count;
   uint32_t header;
   uint32_t payload_batch_size = 0;
   uint32_t payload_total_offset = 0;
   bool ship_it = false;
   int document_count = 0;
   int32_t len;
   mongoc_server_stream_t *retry_server_stream = NULL;

   ENTRY;

   BSON_ASSERT (command);
   BSON_ASSERT (client);
   BSON_ASSERT (database);
   BSON_ASSERT (server_stream);
   BSON_ASSERT (collection);

   max_bson_obj_size = mongoc_server_stream_max_bson_obj_size (server_stream);
   max_msg_size = mongoc_server_stream_max_msg_size (server_stream);
   if (_mongoc_cse_is_enabled (client)) {
      max_msg_size = MONGOC_REDUCED_MAX_MSG_SIZE_FOR_FLE;
   }
   max_document_count =
      mongoc_server_stream_max_write_batch_size (server_stream);

   bson_init (&cmd);
   _mongoc_write_command_init (&cmd, command, collection);
   mongoc_cmd_parts_init (&parts, client, database, MONGOC_QUERY_NONE, &cmd);
   parts.assembled.operation_id = command->operation_id;
   parts.is_write_command = true;
   if (!mongoc_cmd_parts_set_write_concern (
          &parts, write_concern, server_stream->sd->max_wire_version, error)) {
      bson_destroy (&cmd);
      mongoc_cmd_parts_cleanup (&parts);
      EXIT;
   }

   if (parts.assembled.is_acknowledged) {
      mongoc_cmd_parts_set_session (&parts, cs);
   }

   /* Write commands that include multi-document operations are not retryable.
    * Set this explicitly so that mongoc_cmd_parts_assemble does not need to
    * inspect the command body later. */
   parts.allow_txn_number =
      (command->flags.has_multi_write || !parts.assembled.is_acknowledged)
         ? MONGOC_CMD_PARTS_ALLOW_TXN_NUMBER_NO
         : MONGOC_CMD_PARTS_ALLOW_TXN_NUMBER_YES;

   BSON_ASSERT (bson_iter_init (&iter, &command->cmd_opts));
   if (!mongoc_cmd_parts_append_opts (
          &parts, &iter, server_stream->sd->max_wire_version, error)) {
      bson_destroy (&cmd);
      mongoc_cmd_parts_cleanup (&parts);
      EXIT;
   }

   if (!mongoc_cmd_parts_assemble (&parts, server_stream, error)) {
      bson_destroy (&cmd);
      mongoc_cmd_parts_cleanup (&parts);
      EXIT;
   }

   /*
    * OP_MSG header == 16 byte
    * + 4 bytes flagBits
    * + 1 byte payload type = 1
    * + 1 byte payload type = 2
    * + 4 byte size of payload
    * == 26 bytes opcode overhead
    * + X Full command document {insert: "test", writeConcern: {...}}
    * + Y command identifier ("documents", "deletes", "updates") ( + \0)
    */

   header =
      26 + parts.assembled.command->len + gCommandFieldLens[command->type] + 1;

   do {
      memcpy (&len,
              command->payload.data + payload_batch_size + payload_total_offset,
              4);
      len = BSON_UINT32_FROM_LE (len);

      if (len > max_bson_obj_size + BSON_OBJECT_ALLOWANCE) {
         /* Quit if the document is too large */
         _mongoc_write_command_too_large_error (
            error, index_offset, len, max_bson_obj_size);
         result->failed = true;
         break;

      } else if ((payload_batch_size + header) + len <= max_msg_size ||
                 document_count == 0) {
         /* The current batch is still under max batch size in bytes */
         payload_batch_size += len;

         /* If this document filled the maximum document count */
         if (++document_count == max_document_count) {
            ship_it = true;
            /* If this document is the last document we have */
         } else if (payload_batch_size + payload_total_offset ==
                    command->payload.len) {
            ship_it = true;
         } else {
            ship_it = false;
         }
      } else {
         ship_it = true;
      }

      if (ship_it) {
         bool is_retryable = parts.is_retryable_write;
         mongoc_write_err_type_t error_type;

         /* Seek past the document offset we have already sent */
         parts.assembled.payload = command->payload.data + payload_total_offset;
         /* Only send the documents up to this size */
         parts.assembled.payload_size = payload_batch_size;
         parts.assembled.payload_identifier = gCommandFields[command->type];

         /* increment the transaction number for the first attempt of each
          * retryable write command */
         if (is_retryable) {
            bson_iter_t txn_number_iter;
            BSON_ASSERT (bson_iter_init_find (
               &txn_number_iter, parts.assembled.command, "txnNumber"));
            bson_iter_overwrite_int64 (
               &txn_number_iter,
               ++parts.assembled.session->server_session->txn_number);
         }
      retry:
         ret = mongoc_cluster_run_command_monitored (
            &client->cluster, &parts.assembled, &reply, error);

         /* Add this batch size so we skip these documents next time */
         payload_total_offset += payload_batch_size;
         payload_batch_size = 0;

         /* If a retryable error is encountered and the write is retryable,
          * select a new writable stream and retry. If server selection fails or
          * the selected server does not support retryable writes, fall through
          * and allow the original error to be reported. */
         error_type = _mongoc_write_error_get_type (
            ret,
            error,
            &reply,
            server_stream->sd->max_wire_version >=
               WIRE_VERSION_RETRYABLE_WRITE_ERROR_LABEL);
         if (is_retryable) {
            _mongoc_write_error_update_if_unsupported_storage_engine (
               ret, error, &reply);
         }
         if (is_retryable && error_type == MONGOC_WRITE_ERR_RETRY) {
            bson_error_t ignored_error;

            /* each write command may be retried at most once */
            is_retryable = false;

            if (retry_server_stream) {
               mongoc_server_stream_cleanup (retry_server_stream);
            }

            retry_server_stream = mongoc_cluster_stream_for_writes (
               &client->cluster, cs, NULL, &ignored_error);

            if (retry_server_stream &&
                retry_server_stream->sd->max_wire_version >=
                   WIRE_VERSION_RETRY_WRITES) {
               parts.assembled.server_stream = retry_server_stream;
               bson_destroy (&reply);
               GOTO (retry);
            }
         }

         if (!ret) {
            result->failed = true;
            /* Conservatively set must_stop to true. Per CDRIVER-3305 we
             * shouldn't stop for unordered bulk writes, but also need to check
             * if the server stream was invalidated per CDRIVER-3306. */
            result->must_stop = true;
         }

         /* Result merge needs to know the absolute index for a document
          * so it can rewrite the error message which contains the relative
          * document index per batch
          */
         _mongoc_write_result_merge (result, command, &reply, index_offset);
         index_offset += document_count;
         document_count = 0;
         bson_destroy (&reply);
      }
      /* While we have more documents to write */
   } while (payload_total_offset < command->payload.len && !result->must_stop);

   bson_destroy (&cmd);
   mongoc_cmd_parts_cleanup (&parts);

   if (retry_server_stream) {
      if (ret) {
         /* if a retry succeeded, report that in the result so bulk write can
          * use the newly selected server. */
         result->retry_server_id =
            mongoc_server_description_id (retry_server_stream->sd);
      }
      mongoc_server_stream_cleanup (retry_server_stream);
   }

   if (ret) {
      /* if a retry succeeded, clear the initial error */
      memset (&result->error, 0, sizeof (bson_error_t));
   }

   EXIT;
}


void
_append_array_from_command (mongoc_write_command_t *command, bson_t *bson)
{
   bson_t ar;
   bson_reader_t *reader;
   char str[16];
   uint32_t i = 0;
   const char *key;
   bool eof;
   const bson_t *current;


   reader =
      bson_reader_new_from_data (command->payload.data, command->payload.len);

   bson_append_array_begin (bson,
                            gCommandFields[command->type],
                            gCommandFieldLens[command->type],
                            &ar);

   while ((current = bson_reader_read (reader, &eof))) {
      bson_uint32_to_string (i, &key, str, sizeof str);
      BSON_APPEND_DOCUMENT (&ar, key, current);
      i++;
   }

   bson_append_array_end (bson, &ar);
   bson_reader_destroy (reader);
}

/* Assemble the base @cmd with all of the command options.
 * @parts is always initialized, even on error.
 * This is called twice in _mongoc_write_opquery.
 * Once with no payload documents, to determine the total size. And once with
 * payload documents, to send the final command. */
static bool
_assemble_cmd (bson_t *cmd,
               mongoc_write_command_t *command,
               mongoc_client_t *client,
               mongoc_server_stream_t *server_stream,
               const char *database,
               const mongoc_write_concern_t *write_concern,
               mongoc_cmd_parts_t *parts,
               bson_error_t *error)
{
   bool ret;
   bson_iter_t iter;

   mongoc_cmd_parts_init (parts, client, database, MONGOC_QUERY_NONE, cmd);
   parts->is_write_command = true;
   parts->assembled.operation_id = command->operation_id;

   ret = mongoc_cmd_parts_set_write_concern (
      parts, write_concern, server_stream->sd->max_wire_version, error);
   if (ret) {
      BSON_ASSERT (bson_iter_init (&iter, &command->cmd_opts));
      ret = mongoc_cmd_parts_append_opts (
         parts, &iter, server_stream->sd->max_wire_version, error);
   }
   if (ret) {
      ret = mongoc_cmd_parts_assemble (parts, server_stream, error);
   }
   return ret;
}

static void
_mongoc_write_opquery (mongoc_write_command_t *command,
                       mongoc_client_t *client,
                       mongoc_server_stream_t *server_stream,
                       const char *database,
                       const char *collection,
                       const mongoc_write_concern_t *write_concern,
                       uint32_t offset,
                       mongoc_write_result_t *result,
                       bson_error_t *error)
{
   mongoc_cmd_parts_t parts;
   const char *key;
   uint32_t len = 0;
   bson_t ar;
   bson_t cmd;
   char str[16];
   bool has_more;
   bool ret = false;
   uint32_t i;
   int32_t max_bson_obj_size;
   int32_t max_write_batch_size;
   uint32_t overhead;
   uint32_t key_len;
   int data_offset = 0;
   bson_reader_t *reader;
   const bson_t *bson;
   bool eof;

   ENTRY;

   BSON_ASSERT (command);
   BSON_ASSERT (client);
   BSON_ASSERT (database);
   BSON_ASSERT (server_stream);
   BSON_ASSERT (collection);

   bson_init (&cmd);
   max_bson_obj_size = mongoc_server_stream_max_bson_obj_size (server_stream);
   max_write_batch_size =
      mongoc_server_stream_max_write_batch_size (server_stream);

again:
   has_more = false;
   i = 0;

   _mongoc_write_command_init (&cmd, command, collection);
   /* If any part of assembling failed, return with failure. */
   if (!_assemble_cmd (&cmd,
                       command,
                       client,
                       server_stream,
                       database,
                       write_concern,
                       &parts,
                       error)) {
      result->failed = true;
      bson_destroy (&cmd);
      mongoc_cmd_parts_cleanup (&parts);
      EXIT;
   }

   /* Use the assembled command to compute the overhead, since it may be a new
    * BSON document with options applied. If no options were applied, then
    * parts.assembled.command points to cmd. The constant 2 is due to 1 byte to
    * specify array type and 1 byte for field name's null terminator. */
   overhead =
      parts.assembled.command->len + 2 + gCommandFieldLens[command->type];
   /* Toss out the assembled command, we'll assemble again after adding all of
    * the payload documents. */
   mongoc_cmd_parts_cleanup (&parts);

   reader = bson_reader_new_from_data (command->payload.data + data_offset,
                                       command->payload.len - data_offset);

   bson_append_array_begin (&cmd,
                            gCommandFields[command->type],
                            gCommandFieldLens[command->type],
                            &ar);

   while ((bson = bson_reader_read (reader, &eof))) {
      key_len = (uint32_t) bson_uint32_to_string (i, &key, str, sizeof str);
      len = bson->len;
      /* 1 byte to specify document type, 1 byte for key's null terminator */
      if (_mongoc_write_command_will_overflow (overhead,
                                               key_len + len + 2 + ar.len,
                                               i,
                                               max_bson_obj_size,
                                               max_write_batch_size)) {
         has_more = true;
         break;
      }
      BSON_APPEND_DOCUMENT (&ar, key, bson);
      data_offset += len;
      i++;
   }

   bson_append_array_end (&cmd, &ar);

   if (!i) {
      _mongoc_write_command_too_large_error (error, i, len, max_bson_obj_size);
      result->failed = true;
      result->must_stop = true;
      ret = false;
      if (bson) {
         data_offset += len;
      }
   } else {
      bson_t reply;

      ret = _assemble_cmd (&cmd,
                           command,
                           client,
                           server_stream,
                           database,
                           write_concern,
                           &parts,
                           error);
      if (ret) {
         ret = mongoc_cluster_run_command_monitored (
            &client->cluster, &parts.assembled, &reply, error);
      } else {
         bson_init (&reply);
      }

      if (!ret) {
         result->failed = true;
         if (bson_empty (&reply)) {
            /* assembling failed, or a network error running the command */
            result->must_stop = true;
         }
      }

      _mongoc_write_result_merge (result, command, &reply, offset);
      offset += i;
      bson_destroy (&reply);
      mongoc_cmd_parts_cleanup (&parts);
   }
   bson_reader_destroy (reader);

   if (has_more && (ret || !command->flags.ordered) && !result->must_stop) {
      bson_reinit (&cmd);
      GOTO (again);
   }

   bson_destroy (&cmd);
   EXIT;
}


void
_mongoc_write_command_execute (
   mongoc_write_command_t *command,             /* IN */
   mongoc_client_t *client,                     /* IN */
   mongoc_server_stream_t *server_stream,       /* IN */
   const char *database,                        /* IN */
   const char *collection,                      /* IN */
   const mongoc_write_concern_t *write_concern, /* IN */
   uint32_t offset,                             /* IN */
   mongoc_client_session_t *cs,                 /* IN */
   mongoc_write_result_t *result)               /* OUT */
{
   mongoc_crud_opts_t crud = {0};

   ENTRY;

   BSON_ASSERT (command);
   BSON_ASSERT (client);
   BSON_ASSERT (server_stream);
   BSON_ASSERT (database);
   BSON_ASSERT (collection);
   BSON_ASSERT (result);

   if (!write_concern) {
      write_concern = client->write_concern;
   }

   if (!mongoc_write_concern_is_valid (write_concern)) {
      bson_set_error (&result->error,
                      MONGOC_ERROR_COMMAND,
                      MONGOC_ERROR_COMMAND_INVALID_ARG,
                      "The write concern is invalid.");
      result->failed = true;
      EXIT;
   }

   crud.client_session = cs;
   crud.writeConcern = (mongoc_write_concern_t *) write_concern;

   _mongoc_write_command_execute_idl (command,
                                      client,
                                      server_stream,
                                      database,
                                      collection,
                                      offset,
                                      &crud,
                                      result);
   EXIT;
}

void
_mongoc_write_command_execute_idl (mongoc_write_command_t *command,
                                   mongoc_client_t *client,
                                   mongoc_server_stream_t *server_stream,
                                   const char *database,
                                   const char *collection,
                                   uint32_t offset,
                                   const mongoc_crud_opts_t *crud,
                                   mongoc_write_result_t *result)
{
   ENTRY;

   BSON_ASSERT (command);
   BSON_ASSERT (client);
   BSON_ASSERT (server_stream);
   BSON_ASSERT (database);
   BSON_ASSERT (collection);
   BSON_ASSERT (result);

   if (command->flags.has_collation) {
      if (!mongoc_write_concern_is_acknowledged (crud->writeConcern)) {
         result->failed = true;
         bson_set_error (&result->error,
                         MONGOC_ERROR_COMMAND,
                         MONGOC_ERROR_COMMAND_INVALID_ARG,
                         "Cannot set collation for unacknowledged writes");
         EXIT;
      }

      if (server_stream->sd->max_wire_version < WIRE_VERSION_COLLATION) {
         bson_set_error (&result->error,
                         MONGOC_ERROR_COMMAND,
                         MONGOC_ERROR_PROTOCOL_BAD_WIRE_VERSION,
                         "The selected server does not support collation");
         result->failed = true;
         EXIT;
      }
   }

   if (command->flags.has_array_filters) {
      if (!mongoc_write_concern_is_acknowledged (crud->writeConcern)) {
         result->failed = true;
         bson_set_error (&result->error,
                         MONGOC_ERROR_COMMAND,
                         MONGOC_ERROR_COMMAND_INVALID_ARG,
                         "Cannot use array filters with unacknowledged writes");
         EXIT;
      }

      if (server_stream->sd->max_wire_version < WIRE_VERSION_ARRAY_FILTERS) {
         bson_set_error (&result->error,
                         MONGOC_ERROR_COMMAND,
                         MONGOC_ERROR_PROTOCOL_BAD_WIRE_VERSION,
                         "The selected server does not support array filters");
         result->failed = true;
         EXIT;
      }
   }

   if (command->flags.has_update_hint) {
      if (server_stream->sd->max_wire_version < WIRE_VERSION_UPDATE_HINT) {
         bson_set_error (
            &result->error,
            MONGOC_ERROR_COMMAND,
            MONGOC_ERROR_PROTOCOL_BAD_WIRE_VERSION,
            "The selected server does not support hint for update");
         result->failed = true;
         EXIT;
      }
   }

   if (command->flags.bypass_document_validation) {
      if (!mongoc_write_concern_is_acknowledged (crud->writeConcern)) {
         result->failed = true;
         bson_set_error (
            &result->error,
            MONGOC_ERROR_COMMAND,
            MONGOC_ERROR_COMMAND_INVALID_ARG,
            "Cannot set bypassDocumentValidation for unacknowledged writes");
         EXIT;
      }
   }

   if (crud->client_session &&
       !mongoc_write_concern_is_acknowledged (crud->writeConcern)) {
      result->failed = true;
      bson_set_error (&result->error,
                      MONGOC_ERROR_COMMAND,
                      MONGOC_ERROR_COMMAND_INVALID_ARG,
                      "Cannot use client session with unacknowledged writes");
      EXIT;
   }

   if (command->payload.len == 0) {
      _empty_error (command, &result->error);
      EXIT;
   }

   if (server_stream->sd->max_wire_version >= WIRE_VERSION_OP_MSG) {
      _mongoc_write_opmsg (command,
                           client,
                           server_stream,
                           database,
                           collection,
                           crud->writeConcern,
                           offset,
                           crud->client_session,
                           result,
                           &result->error);
   } else {
      if (mongoc_write_concern_is_acknowledged (crud->writeConcern)) {
         _mongoc_write_opquery (command,
                                client,
                                server_stream,
                                database,
                                collection,
                                crud->writeConcern,
                                offset,
                                result,
                                &result->error);
      } else {
         gLegacyWriteOps[command->type](command,
                                        client,
                                        server_stream,
                                        database,
                                        collection,
                                        offset,
                                        result,
                                        &result->error);
      }
   }

   EXIT;
}


void
_mongoc_write_command_destroy (mongoc_write_command_t *command)
{
   ENTRY;

   if (command) {
      bson_destroy (&command->cmd_opts);
      _mongoc_buffer_destroy (&command->payload);
   }

   EXIT;
}


void
_mongoc_write_result_init (mongoc_write_result_t *result) /* IN */
{
   ENTRY;

   BSON_ASSERT (result);

   memset (result, 0, sizeof *result);

   bson_init (&result->upserted);
   bson_init (&result->writeConcernErrors);
   bson_init (&result->writeErrors);
   bson_init (&result->errorLabels);

   EXIT;
}


void
_mongoc_write_result_destroy (mongoc_write_result_t *result)
{
   ENTRY;

   BSON_ASSERT (result);

   bson_destroy (&result->upserted);
   bson_destroy (&result->writeConcernErrors);
   bson_destroy (&result->writeErrors);
   bson_destroy (&result->errorLabels);

   EXIT;
}


void
_mongoc_write_result_append_upsert (mongoc_write_result_t *result,
                                    int32_t idx,
                                    const bson_value_t *value)
{
   bson_t child;
   const char *keyptr = NULL;
   char key[12];
   int len;

   BSON_ASSERT (result);
   BSON_ASSERT (value);

   len = (int) bson_uint32_to_string (
      result->upsert_append_count, &keyptr, key, sizeof key);

   bson_append_document_begin (&result->upserted, keyptr, len, &child);
   BSON_APPEND_INT32 (&child, "index", idx);
   BSON_APPEND_VALUE (&child, "_id", value);
   bson_append_document_end (&result->upserted, &child);

   result->upsert_append_count++;
}


int32_t
_mongoc_write_result_merge_arrays (uint32_t offset,
                                   mongoc_write_result_t *result, /* IN */
                                   bson_t *dest,                  /* IN */
                                   bson_iter_t *iter)             /* IN */
{
   const bson_value_t *value;
   bson_iter_t ar;
   bson_iter_t citer;
   int32_t idx;
   int32_t count = 0;
   int32_t aridx;
   bson_t child;
   const char *keyptr = NULL;
   char key[12];
   int len;

   ENTRY;

   BSON_ASSERT (result);
   BSON_ASSERT (dest);
   BSON_ASSERT (iter);
   BSON_ASSERT (BSON_ITER_HOLDS_ARRAY (iter));

   aridx = bson_count_keys (dest);

   if (bson_iter_recurse (iter, &ar)) {
      while (bson_iter_next (&ar)) {
         if (BSON_ITER_HOLDS_DOCUMENT (&ar) &&
             bson_iter_recurse (&ar, &citer)) {
            len =
               (int) bson_uint32_to_string (aridx++, &keyptr, key, sizeof key);
            bson_append_document_begin (dest, keyptr, len, &child);
            while (bson_iter_next (&citer)) {
               if (BSON_ITER_IS_KEY (&citer, "index")) {
                  idx = bson_iter_int32 (&citer) + offset;
                  BSON_APPEND_INT32 (&child, "index", idx);
               } else {
                  value = bson_iter_value (&citer);
                  BSON_APPEND_VALUE (&child, bson_iter_key (&citer), value);
               }
            }
            bson_append_document_end (dest, &child);
            count++;
         }
      }
   }

   RETURN (count);
}


void
_mongoc_write_result_merge (mongoc_write_result_t *result,   /* IN */
                            mongoc_write_command_t *command, /* IN */
                            const bson_t *reply,             /* IN */
                            uint32_t offset)
{
   int32_t server_index = 0;
   const bson_value_t *value;
   bson_iter_t iter;
   bson_iter_t citer;
   bson_iter_t ar;
   int32_t n_upserted = 0;
   int32_t affected = 0;

   ENTRY;

   BSON_ASSERT (result);
   BSON_ASSERT (reply);

   if (bson_iter_init_find (&iter, reply, "n") &&
       BSON_ITER_HOLDS_INT32 (&iter)) {
      affected = bson_iter_int32 (&iter);
   }

   if (bson_iter_init_find (&iter, reply, "writeErrors") &&
       BSON_ITER_HOLDS_ARRAY (&iter) && bson_iter_recurse (&iter, &citer) &&
       bson_iter_next (&citer)) {
      result->failed = true;
   }

   switch (command->type) {
   case MONGOC_WRITE_COMMAND_INSERT:
      result->nInserted += affected;
      break;
   case MONGOC_WRITE_COMMAND_DELETE:
      result->nRemoved += affected;
      break;
   case MONGOC_WRITE_COMMAND_UPDATE:

      /* server returns each upserted _id with its index into this batch
       * look for "upserted": [{"index": 4, "_id": ObjectId()}, ...] */
      if (bson_iter_init_find (&iter, reply, "upserted")) {
         if (BSON_ITER_HOLDS_ARRAY (&iter) &&
             (bson_iter_recurse (&iter, &ar))) {
            while (bson_iter_next (&ar)) {
               if (BSON_ITER_HOLDS_DOCUMENT (&ar) &&
                   bson_iter_recurse (&ar, &citer) &&
                   bson_iter_find (&citer, "index") &&
                   BSON_ITER_HOLDS_INT32 (&citer)) {
                  server_index = bson_iter_int32 (&citer);

                  if (bson_iter_recurse (&ar, &citer) &&
                      bson_iter_find (&citer, "_id")) {
                     value = bson_iter_value (&citer);
                     _mongoc_write_result_append_upsert (
                        result, offset + server_index, value);
                     n_upserted++;
                  }
               }
            }
         }
         result->nUpserted += n_upserted;
         /*
          * XXX: The following addition to nMatched needs some checking.
          *      I'm highly skeptical of it.
          */
         result->nMatched += BSON_MAX (0, (affected - n_upserted));
      } else {
         result->nMatched += affected;
      }
      if (bson_iter_init_find (&iter, reply, "nModified") &&
          BSON_ITER_HOLDS_INT32 (&iter)) {
         result->nModified += bson_iter_int32 (&iter);
      }
      break;
   default:
      BSON_ASSERT (false);
      break;
   }

   if (bson_iter_init_find (&iter, reply, "writeErrors") &&
       BSON_ITER_HOLDS_ARRAY (&iter)) {
      _mongoc_write_result_merge_arrays (
         offset, result, &result->writeErrors, &iter);
   }

   if (bson_iter_init_find (&iter, reply, "writeConcernError") &&
       BSON_ITER_HOLDS_DOCUMENT (&iter)) {
      uint32_t len;
      const uint8_t *data;
      bson_t write_concern_error;
      char str[16];
      const char *key;

      /* writeConcernError is a subdocument in the server response
       * append it to the result->writeConcernErrors array */
      bson_iter_document (&iter, &len, &data);
      BSON_ASSERT (bson_init_static (&write_concern_error, data, len));

      bson_uint32_to_string (
         result->n_writeConcernErrors, &key, str, sizeof str);

      if (!bson_append_document (
             &result->writeConcernErrors, key, -1, &write_concern_error)) {
         MONGOC_ERROR ("Error adding \"%s\" to writeConcernErrors.\n", key);
      }

      result->n_writeConcernErrors++;
   }

   /* inefficient if there are ever large numbers: for each label in each err,
    * we linear-search result->errorLabels to see if it's included yet */
   _mongoc_bson_array_copy_labels_to (reply, &result->errorLabels);

   EXIT;
}


/*
 * If error is not set, set code from first document in array like
 * [{"code": 64, "errmsg": "duplicate"}, ...]. Format the error message
 * from all errors in array.
 */
static void
_set_error_from_response (bson_t *bson_array,
                          mongoc_error_domain_t domain,
                          const char *error_type,
                          bson_error_t *error /* OUT */)
{
   bson_iter_t array_iter;
   bson_iter_t doc_iter;
   bson_string_t *compound_err;
   const char *errmsg = NULL;
   int32_t code = 0;
   uint32_t n_keys, i;

   compound_err = bson_string_new (NULL);
   n_keys = bson_count_keys (bson_array);
   if (n_keys > 1) {
      bson_string_append_printf (
         compound_err, "Multiple %s errors: ", error_type);
   }

   if (!bson_empty0 (bson_array) && bson_iter_init (&array_iter, bson_array)) {
      /* get first code and all error messages */
      i = 0;

      while (bson_iter_next (&array_iter)) {
         if (BSON_ITER_HOLDS_DOCUMENT (&array_iter) &&
             bson_iter_recurse (&array_iter, &doc_iter)) {
            /* parse doc, which is like {"code": 64, "errmsg": "duplicate"} */
            while (bson_iter_next (&doc_iter)) {
               /* use the first error code we find */
               if (BSON_ITER_IS_KEY (&doc_iter, "code") && code == 0) {
                  code = bson_iter_int32 (&doc_iter);
               } else if (BSON_ITER_IS_KEY (&doc_iter, "errmsg")) {
                  errmsg = bson_iter_utf8 (&doc_iter, NULL);

                  /* build message like 'Multiple write errors: "foo", "bar"' */
                  if (n_keys > 1) {
                     bson_string_append_printf (compound_err, "\"%s\"", errmsg);
                     if (i < n_keys - 1) {
                        bson_string_append (compound_err, ", ");
                     }
                  } else {
                     /* single error message */
                     bson_string_append (compound_err, errmsg);
                  }
               }
            }

            i++;
         }
      }

      if (code && compound_err->len) {
         bson_set_error (
            error, domain, (uint32_t) code, "%s", compound_err->str);
      }
   }

   bson_string_free (compound_err, true);
}


/* complete a write result, including only certain fields */
bool
_mongoc_write_result_complete (
   mongoc_write_result_t *result,             /* IN */
   int32_t error_api_version,                 /* IN */
   const mongoc_write_concern_t *wc,          /* IN */
   mongoc_error_domain_t err_domain_override, /* IN */
   bson_t *bson,                              /* OUT */
   bson_error_t *error,                       /* OUT */
   ...)
{
   mongoc_error_domain_t domain;
   va_list args;
   const char *field;
   int n_args;
   bson_iter_t iter;
   bson_iter_t child;

   ENTRY;

   BSON_ASSERT (result);

   if (error_api_version >= MONGOC_ERROR_API_VERSION_2) {
      domain = MONGOC_ERROR_SERVER;
   } else if (err_domain_override) {
      domain = err_domain_override;
   } else if (result->error.domain) {
      domain = (mongoc_error_domain_t) result->error.domain;
   } else {
      domain = MONGOC_ERROR_COLLECTION;
   }

   /* produce either old fields like nModified from the deprecated Bulk API Spec
    * or new fields like modifiedCount from the CRUD Spec, which we partly obey
    */
   if (bson && mongoc_write_concern_is_acknowledged (wc)) {
      n_args = 0;
      va_start (args, error);
      while ((field = va_arg (args, const char *))) {
         n_args++;

         if (!strcmp (field, "nInserted")) {
            BSON_APPEND_INT32 (bson, field, result->nInserted);
         } else if (!strcmp (field, "insertedCount")) {
            BSON_APPEND_INT32 (bson, field, result->nInserted);
         } else if (!strcmp (field, "nMatched")) {
            BSON_APPEND_INT32 (bson, field, result->nMatched);
         } else if (!strcmp (field, "matchedCount")) {
            BSON_APPEND_INT32 (bson, field, result->nMatched);
         } else if (!strcmp (field, "nModified")) {
            BSON_APPEND_INT32 (bson, field, result->nModified);
         } else if (!strcmp (field, "modifiedCount")) {
            BSON_APPEND_INT32 (bson, field, result->nModified);
         } else if (!strcmp (field, "nRemoved")) {
            BSON_APPEND_INT32 (bson, field, result->nRemoved);
         } else if (!strcmp (field, "deletedCount")) {
            BSON_APPEND_INT32 (bson, field, result->nRemoved);
         } else if (!strcmp (field, "nUpserted")) {
            BSON_APPEND_INT32 (bson, field, result->nUpserted);
         } else if (!strcmp (field, "upsertedCount")) {
            BSON_APPEND_INT32 (bson, field, result->nUpserted);
         } else if (!strcmp (field, "upserted") &&
                    !bson_empty0 (&result->upserted)) {
            BSON_APPEND_ARRAY (bson, field, &result->upserted);
         } else if (!strcmp (field, "upsertedId") &&
                    !bson_empty0 (&result->upserted) &&
                    bson_iter_init_find (&iter, &result->upserted, "0") &&
                    bson_iter_recurse (&iter, &child) &&
                    bson_iter_find (&child, "_id")) {
            /* "upsertedId", singular, for update_one() */
            BSON_APPEND_VALUE (bson, "upsertedId", bson_iter_value (&child));
         }
      }

      va_end (args);

      /* default: a standard result includes all Bulk API fields */
      if (!n_args) {
         BSON_APPEND_INT32 (bson, "nInserted", result->nInserted);
         BSON_APPEND_INT32 (bson, "nMatched", result->nMatched);
         BSON_APPEND_INT32 (bson, "nModified", result->nModified);
         BSON_APPEND_INT32 (bson, "nRemoved", result->nRemoved);
         BSON_APPEND_INT32 (bson, "nUpserted", result->nUpserted);
         if (!bson_empty0 (&result->upserted)) {
            BSON_APPEND_ARRAY (bson, "upserted", &result->upserted);
         }
      }

      /* always append errors if there are any */
      if (!n_args || !bson_empty (&result->writeErrors)) {
         BSON_APPEND_ARRAY (bson, "writeErrors", &result->writeErrors);
      }

      if (result->n_writeConcernErrors) {
         BSON_APPEND_ARRAY (
            bson, "writeConcernErrors", &result->writeConcernErrors);
      }
   }

   /* set bson_error_t from first write error or write concern error */
   _set_error_from_response (
      &result->writeErrors, domain, "write", &result->error);

   if (!result->error.code) {
      _set_error_from_response (&result->writeConcernErrors,
                                MONGOC_ERROR_WRITE_CONCERN,
                                "write concern",
                                &result->error);
   }

   if (bson && !bson_empty (&result->errorLabels)) {
      BSON_APPEND_ARRAY (bson, "errorLabels", &result->errorLabels);
   }

   if (error) {
      memcpy (error, &result->error, sizeof *error);
   }

   RETURN (!result->failed && result->error.code == 0);
}


/*--------------------------------------------------------------------------
 *
 * _mongoc_write_error_is_retryable --
 *
 *       Checks if the error from a write command is considered retryable
 *       when checking code and message.
 *
 *
 * Return:
 *       True if the error is retryable, false otherwise.
 *
 *--------------------------------------------------------------------------
 */
static bool
_mongoc_write_error_is_retryable (bson_error_t *error)
{
   switch (error->code) {
   case 6:     /* HostUnreachable */
   case 7:     /* HostNotFound */
   case 89:    /* NetworkTimeout */
   case 91:    /* ShutdownInProgress */
   case 189:   /* PrimarySteppedDown */
   case 262:   /* ExceededTimeLimit */
   case 9001:  /* SocketException */
   case 10107: /* NotMaster */
   case 11600: /* InterruptedAtShutdown */
   case 11602: /* InterruptedDueToReplStateChange */
   case 13435: /* NotMasterNoSlaveOk */
   case 13436: /* NotMasterOrSecondary */
      return true;
   default:
      if (strstr (error->message, "not master") ||
          strstr (error->message, "node is recovering")) {
         return true;
      }
      return false;
   }
}

static bool
_mongoc_write_error_labels_contains (bson_iter_t *iter, const char *label)
{
   while (bson_iter_next (iter)) {
      if (!BSON_ITER_HOLDS_UTF8 (iter)) {
         continue;
      }

      if (!strcmp (bson_iter_utf8 (iter, NULL), label)) {
         return true;
      }
   }

   return false;
}

/*--------------------------------------------------------------------------
 *
 * _mongoc_write_error_has_retryable_label --
 *
 *       Checks if the error from a write command has a "RetryableWriteError"
 *       error label or contains a writeConcernError with a retryable label.
 *
 *
 * Return:
 *       True if the label is found, false otherwise.
 *
 *--------------------------------------------------------------------------
 */
static bool
_mongoc_write_error_has_retryable_label (const bson_t *reply)
{
   bson_iter_t iter;
   bson_iter_t label;

   if (bson_iter_init_find (&iter, reply, "errorLabels")) {
      BSON_ASSERT (bson_iter_recurse (&iter, &label));
      if (_mongoc_write_error_labels_contains (&label, RETRYABLE_WRITE_ERROR)) {
         return true;
      }
   }

   if (!bson_iter_init_find (&iter, reply, "writeConcernError")) {
      return false;
   }

   BSON_ASSERT (bson_iter_recurse (&iter, &iter));

   if (!bson_iter_find (&iter, "errorLabels")) {
      return false;
   }

   BSON_ASSERT (bson_iter_recurse (&iter, &label));

   return _mongoc_write_error_labels_contains (&label, RETRYABLE_WRITE_ERROR);
}

static void
_mongoc_write_error_append_retryable_label (bson_t *reply)
{
   bson_t reply_local = BSON_INITIALIZER;

   if (reply) {
      bson_copy_to_excluding_noinit (&reply_local, reply, "errorLabels", NULL);
      _mongoc_error_copy_labels_and_upsert (
         &reply_local, reply, RETRYABLE_WRITE_ERROR);
   }

   bson_destroy (&reply_local);
}

/*--------------------------------------------------------------------------
 *
 * _mongoc_write_error_get_type --
 *
 *       Checks if the error or reply from a write command is considered
 *       retryable according to the retryable writes spec. Checks both
 *       for a client error (a network exception) and a server error in
 *       the reply. @cmd_ret and @cmd_err come from the result of a
 *       write_command function.
 *
 *
 * Return:
 *       A mongoc_write_error_type_t indicating the type of error (if any).
 *
 *--------------------------------------------------------------------------
 */
mongoc_write_err_type_t
_mongoc_write_error_get_type (bool cmd_ret,
                              const bson_error_t *cmd_err,
                              bson_t *reply,
                              bool supports_retryable_write_label)
{
   bson_error_t error;

   if (_mongoc_write_error_has_retryable_label (reply)) {
      return MONGOC_WRITE_ERR_RETRY;
   }

   /* check for a client error. */
   if (!cmd_ret && (cmd_err->domain == MONGOC_ERROR_STREAM ||
                    (cmd_err->domain == MONGOC_ERROR_PROTOCOL &&
                     cmd_err->code == MONGOC_ERROR_PROTOCOL_INVALID_REPLY))) {
      /* Retryable writes spec: When the driver encounters a network error
       * communicating with any server version that supports retryable
       * writes, it MUST add a RetryableWriteError label to that error. */
      _mongoc_write_error_append_retryable_label (reply);

      /* Retryable writes spec: "considered retryable if [...] any network
       * exception (e.g. socket timeout or error) */
      return MONGOC_WRITE_ERR_RETRY;
   }

   /* check for a server error. */
   if (_mongoc_cmd_check_ok_no_wce (
          reply, MONGOC_ERROR_API_VERSION_2, &error)) {
      return MONGOC_WRITE_ERR_NONE;
   }

   if (!supports_retryable_write_label &&
       _mongoc_write_error_is_retryable (&error)) {
      _mongoc_write_error_append_retryable_label (reply);

      return MONGOC_WRITE_ERR_RETRY;
   }

   switch (error.code) {
   case 64: /* WriteConcernFailed */
      return MONGOC_WRITE_ERR_WRITE_CONCERN;
   default:
      return MONGOC_WRITE_ERR_OTHER;
   }
}

/* Returns true and modifies reply and cmd_err. */
bool
_mongoc_write_error_update_if_unsupported_storage_engine (bool cmd_ret,
                                                          bson_error_t *cmd_err,
                                                          bson_t *reply)
{
   bson_error_t server_error;

   if (cmd_ret) {
      return false;
   }

   if (_mongoc_cmd_check_ok_no_wce (
          reply, MONGOC_ERROR_API_VERSION_2, &server_error)) {
      return false;
   }

   if (server_error.code == 20 &&
       strstr (server_error.message, "Transaction numbers") ==
          server_error.message) {
      const char *replacement = "This MongoDB deployment does not support "
                                "retryable writes. Please add "
                                "retryWrites=false to your connection string.";

      strcpy (cmd_err->message, replacement);

      if (reply) {
         bson_t *new_reply = bson_new ();
         bson_copy_to_excluding_noinit (reply, new_reply, "errmsg", NULL);
         BSON_APPEND_UTF8 (new_reply, "errmsg", replacement);
         bson_destroy (reply);
         bson_steal (reply, new_reply);
      }
      return true;
   }
   return false;
}
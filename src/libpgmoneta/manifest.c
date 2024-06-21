/*
 * Copyright (C) 2024 The pgmoneta community
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list
 * of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may
 * be used to endorse or promote products derived from this software without specific
 * prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* pgmoneta */
#include <pgmoneta.h>
#include <csv.h>
#include <deque.h>
#include <json.h>
#include <logging.h>
#include <manifest.h>
#include <security.h>
#include <utils.h>

/* system */
#include <stdio.h>
#include <string.h>

static void
build_deque(struct deque* deque, struct csv_reader* reader, char** f);

static void
build_tree(struct art* tree, struct csv_reader* reader, char** f);

int
pgmoneta_manifest_checksum_verify(char* root)
{
   char manifest_path[MAX_PATH];
   char* key_path[1] = {"Files"};
   struct json_reader* reader = NULL;
   struct json* file = NULL;

   memset(manifest_path, 0, MAX_PATH);
   if (pgmoneta_ends_with(root, "/"))
   {
      snprintf(manifest_path, MAX_PATH, "%s%s", root, "backup_manifest");
   }
   else
   {
      snprintf(manifest_path, MAX_PATH, "%s/%s", root, "backup_manifest");
   }
   if (pgmoneta_json_reader_init(manifest_path, &reader))
   {
      goto error;
   }
   if (pgmoneta_json_locate(reader, key_path, 1))
   {
      pgmoneta_log_error("cannot locate files array in manifest %s", manifest_path);
      goto error;
   }
   while (pgmoneta_json_next_array_item(reader, &file))
   {
      char file_path[MAX_PATH];
      size_t file_size = 0;
      size_t file_size_manifest = 0;
      char* hash = NULL;
      char* algorithm = NULL;
      char* checksum = NULL;

      memset(file_path, 0, MAX_PATH);
      if (pgmoneta_ends_with(root, "/"))
      {
         snprintf(file_path, MAX_PATH, "%s%s", root, pgmoneta_json_get_string_value(file, "Path"));
      }
      else
      {
         snprintf(file_path, MAX_PATH, "%s/%s", root, pgmoneta_json_get_string_value(file, "Path"));
      }

      file_size = pgmoneta_get_file_size(file_path);
      file_size_manifest = pgmoneta_json_get_int64_value(file, "Size");
      if (file_size != file_size_manifest)
      {
         pgmoneta_log_error("File size mismatch: %s, getting %lu, should be %lu", file_size, file_size_manifest);
      }

      algorithm = pgmoneta_json_get_string_value(file, "Checksum-Algorithm");
      if (pgmoneta_create_file_hash(pgmoneta_get_hash_algorithm(algorithm), file_path, &hash))
      {
         pgmoneta_log_error("Unable to generate hash for file %s with algorithm %s", file_path, algorithm);
         goto error;
      }

      checksum = pgmoneta_json_get_string_value(file, "Checksum");
      if (!pgmoneta_compare_string(hash, checksum))
      {
         pgmoneta_log_error("File checksum mismatch, path: %s. Getting %s, should be %s", file_path, hash, checksum);
      }
      free(hash);
      pgmoneta_json_free(file);
      file = NULL;
   }
   pgmoneta_json_close_reader(reader);
   pgmoneta_json_free(file);
   return 0;

error:
   pgmoneta_json_close_reader(reader);
   pgmoneta_json_free(file);
   return 1;
}

int
pgmoneta_compare_manifests(char* old_manifest, char* new_manifest, struct art** deleted_files, struct art** changed_files, struct art** added_files)
{
   struct csv_reader* r1 = NULL;
   char** f1 = NULL;
   struct csv_reader* r2 = NULL;
   char** f2 = NULL;
   struct art* deleted = NULL;
   struct art* changed = NULL;
   struct art* added = NULL;
   char* checksum = NULL;
   int cols = 0;
   bool manifest_changed = false;
   struct art* tree = NULL;
   struct deque* que = NULL;
   struct deque_node* entry = NULL;
   char* key = NULL;
   char* val = NULL;

   *deleted_files = NULL;
   *changed_files = NULL;
   *added_files = NULL;

   pgmoneta_deque_create(&que);

   pgmoneta_art_init(&deleted, NULL);
   pgmoneta_art_init(&added, NULL);
   pgmoneta_art_init(&changed, NULL);

   if (pgmoneta_csv_reader_init(old_manifest, &r1))
   {
      goto error;
   }

   if (pgmoneta_csv_reader_init(new_manifest, &r2))
   {
      goto error;
   }

   while (pgmoneta_csv_next_row(&cols, &f1, r1))
   {
      if (cols != MANIFEST_COLUMN_COUNT)
      {
         pgmoneta_log_error("Incorrect number of columns in manifest file");
         free(f1);
         continue;
      }
      // build left chunk into a deque
      build_deque(que, r1, f1);
      while (pgmoneta_csv_next_row(&cols, &f2, r2))
      {
         if (cols != MANIFEST_COLUMN_COUNT)
         {
            pgmoneta_log_error("Incorrect number of columns in manifest file");
            free(f2);
            continue;
         }
         // build every right chunk into an ART
         pgmoneta_art_init(&tree, NULL);
         build_tree(tree, r2, f2);
         entry = pgmoneta_deque_peek(que);
         while (entry != NULL && entry != que->end)
         {
            checksum = pgmoneta_art_search(tree, (unsigned char*)entry->tag, strlen(entry->tag) + 1);
            if (checksum != NULL)
            {
               if (!strcmp(entry->data, checksum))
               {
                  // not changed but not deleted, remove the entry
                  entry = pgmoneta_deque_node_remove(que, entry);
               }
               else
               {
                  // file is changed
                  manifest_changed = true;
                  val = pgmoneta_append(NULL, entry->data);
                  pgmoneta_art_insert(changed, (unsigned char*)entry->tag, strlen(entry->tag) + 1, val);
                  // changed but not deleted, remove the entry
                  entry = pgmoneta_deque_node_remove(que, entry);
               }
            }
            else
            {
               entry = entry->next;
            }
         }
         pgmoneta_art_destroy(tree);
         tree = NULL;
      }
      entry = pgmoneta_deque_peek(que);
      // traverse
      while (!pgmoneta_deque_empty(que))
      {
         manifest_changed = true;
         // make a copy since tree insert doesn't do that
         val = pgmoneta_append(NULL, entry->data);
         pgmoneta_art_insert(deleted, (unsigned char*)entry->tag, strlen(entry->tag) + 1, val);
         entry = pgmoneta_deque_node_remove(que, entry);
      }
      // reset right reader for the next left chunk
      if (pgmoneta_csv_reader_reset(r2))
      {
         goto error;
      }
   }
   if (pgmoneta_csv_reader_reset(r1))
   {
      goto error;
   }

   while (pgmoneta_csv_next_row(&cols, &f2, r2))
   {
      if (cols != MANIFEST_COLUMN_COUNT)
      {
         pgmoneta_log_error("Incorrect number of columns in manifest file");
         free(f2);
         continue;
      }
      build_deque(que, r2, f2);
      while (pgmoneta_csv_next_row(&cols, &f1, r1))
      {
         if (cols != MANIFEST_COLUMN_COUNT)
         {
            pgmoneta_log_error("Incorrect number of columns in manifest file");
            free(f1);
            continue;
         }
         pgmoneta_art_init(&tree, NULL);
         build_tree(tree, r1, f1);
         entry = pgmoneta_deque_peek(que);
         while (entry != NULL && entry != que->end)
         {
            checksum = pgmoneta_art_search(tree, (unsigned char*)entry->tag, strlen(entry->tag) + 1);
            if (checksum != NULL)
            {
               // the entry is not new, remove it
               entry = pgmoneta_deque_node_remove(que, entry);
            }
            else
            {
               entry = entry->next;
            }
         }
         pgmoneta_art_destroy(tree);
         tree = NULL;
      }
      entry = pgmoneta_deque_peek(que);
      while (!pgmoneta_deque_empty(que))
      {
         manifest_changed = true;
         val = pgmoneta_append(NULL, entry->data);
         pgmoneta_art_insert(added, (unsigned char*)entry->tag, strlen(entry->tag) + 1, val);
         entry = pgmoneta_deque_node_remove(que, entry);;
      }
      if (pgmoneta_csv_reader_reset(r1))
      {
         goto error;
      }
   }

   if (manifest_changed)
   {
      key = pgmoneta_append(NULL, "backup.manifest");
      val = pgmoneta_append(NULL, "backup manifest");
      pgmoneta_art_insert(changed, (unsigned char*)key, strlen(key) + 1, val);
      free(key);

      key = pgmoneta_append(NULL, "data/backup_manifest");
      val = pgmoneta_append(NULL, "backup manifest");
      pgmoneta_art_insert(changed, (unsigned char*)key, strlen(key) + 1, val);
      free(key);

      key = pgmoneta_append(NULL, "backup.info");
      val = pgmoneta_append(NULL, "backup info");
      pgmoneta_art_insert(changed, (unsigned char*)key, strlen(key) + 1, val);
      free(key);
   }

   *deleted_files = deleted;
   *changed_files = changed;
   *added_files = added;

   pgmoneta_csv_reader_destroy(r1);
   pgmoneta_csv_reader_destroy(r2);
   pgmoneta_art_destroy(tree);
   pgmoneta_deque_destroy(que);

   return 0;
error:
   pgmoneta_csv_reader_destroy(r1);
   pgmoneta_csv_reader_destroy(r2);
   pgmoneta_art_destroy(tree);
   pgmoneta_deque_destroy(que);
   return 1;
}

static void
build_deque(struct deque* deque, struct csv_reader* reader, char** f)
{
   char** entry = NULL;
   char* path = NULL;
   char* checksum = NULL;
   int cols = 0;
   if (deque == NULL)
   {
      return;
   }
   path = f[MANIFEST_PATH_INDEX];
   checksum = f[MANIFEST_CHECKSUM_INDEX];
   pgmoneta_deque_offer_string(deque, checksum, path);
   free(f);
   while (deque->size < MANIFEST_CHUNK_SIZE && pgmoneta_csv_next_row(&cols, &entry, reader))
   {
      if (cols != MANIFEST_COLUMN_COUNT)
      {
         pgmoneta_log_error("Incorrect number of columns in manifest file");
         free(entry);
         continue;
      }
      path = entry[MANIFEST_PATH_INDEX];
      checksum = entry[MANIFEST_CHECKSUM_INDEX];
      pgmoneta_deque_offer_string(deque, checksum, path);
      free(entry);
      entry = NULL;
   }
}

static void
build_tree(struct art* tree, struct csv_reader* reader, char** f)
{
   char** entry = NULL;
   char* path = NULL;
   char* checksum = NULL;
   int cols = 0;
   if (tree == NULL)
   {
      return;
   }
   path = f[MANIFEST_PATH_INDEX];
   // make a copy of checksum since ART doesn't do that for us
   checksum = pgmoneta_append(checksum, f[MANIFEST_CHECKSUM_INDEX]);
   pgmoneta_art_insert(tree, (unsigned char*)path, strlen(path) + 1, checksum);
   checksum = NULL;
   free(f);
   while (tree->size < MANIFEST_CHUNK_SIZE && pgmoneta_csv_next_row(&cols, &entry, reader))
   {
      if (cols != MANIFEST_COLUMN_COUNT)
      {
         pgmoneta_log_error("Incorrect number of columns in manifest file");
         free(entry);
         continue;
      }
      path = entry[MANIFEST_PATH_INDEX];
      checksum = pgmoneta_append(checksum, entry[MANIFEST_CHECKSUM_INDEX]);
      pgmoneta_art_insert(tree, (unsigned char*)path, strlen(path) + 1, checksum);
      free(entry);
      checksum = NULL;
   }
}

int
pgmoneta_verify_data(int srv, char *backup_id)
{
	char* d = NULL;
	int backup_index = -1;
	int number_of_backups = 0;
	struct backup** backups = NULL;
	struct configuration* config;

	config = (struct configuration*)shmem;

	d = pgmoneta_get_server_backup(srv);

	if (pgmoneta_get_backups(d, &number_of_backups, &backups))
	{
		goto error;
	}
	free(d);
	d = NULL;

	//select proper backup
	if (!strcmp(backup_id, "oldest"))
	{
		for (int i = 0; backup_index == -1 && i < number_of_backups; i++)
		{
			if (backups[i] != NULL)
			{
				backup_index = i;
			}
		}
	}
	else if (!strcmp(backup_id, "latest") || !strcmp(backup_id, "newest"))
	{
		for (int i = number_of_backups - 1; backup_index == -1 && i >= 0; i--)
		{
			if (backups[i] != NULL)
			{
				backup_index = i;
			}
		}
	}
	else
	{
		for (int i = 0; backup_index == -1 && i < number_of_backups; i++)
		{
			if (backups[i] != NULL && !strcmp(backups[i]->label, backup_id))
			{
				backup_index = i;
			}
		}
	}

	if (backup_index == -1)
	{
		pgmoneta_log_error("Verify: No identifier for %s/%s", config->servers[srv].name, backup_id);
		goto error;
	}

	if (backups[backup_index]->valid == VALID_FALSE)
	{
		pgmoneta_log_error("Verify: Backup is not valid");
		goto error;
	}

	char* backup_manifest = NULL;

	//get backup_manifest file. maybe turn this into a utility function?
	backup_manifest = pgmoneta_get_server_backup_identifier_data(srv, backups[backup_index]->label);
	backup_manifest = pgmoneta_append(backup_manifest, "backup_manifest");

	if (pgmoneta_exists(backup_manifest) == false)
	{
		pgmoneta_log_error("Verify: backup_manifest does not exist.");
		free(backup_manifest);
		backup_manifest = NULL;
		goto error;
	}

	if (pgmoneta_is_file(backup_manifest) == false)
	{
		pgmoneta_log_error("Verify: backup_manifest is not a file.");
		free(backup_manifest);
		backup_manifest = NULL;
		goto error;
	}

	pgmoneta_log_debug("Verify: backup_manifest file found - OK");

	struct json_reader* reader = NULL;
	struct json* output = NULL;
	struct json* output_item = NULL;

	if (pgmoneta_json_init(&output, JSONArray) == 1)
	{
		//refactor
		pgmoneta_log_error("Verify: could not initalize output JSON Object");
		exit(2);
	}

	if (!pgmoneta_json_reader_init(backup_manifest, &reader))
	{
		pgmoneta_log_debug("Verify: Json reader init OK");
		//goto first array element
		char* key_path[1] = {"Files"};

		if (!pgmoneta_json_locate(reader, key_path, 1))
		{
			struct json* f1 = NULL;
			char* path = NULL;
			char* manifest_checksum = NULL;
			char* actual_checksum = NULL;

			//iterate through Files array items
			while(pgmoneta_json_next_array_item(reader, &f1))
			{
				char* absolute_file_path = NULL;

				//create json object
				pgmoneta_json_init(&output_item, JSONItem);

				path = pgmoneta_json_get_string_value(f1, "Path");

				//put filepath to json output_item

				//construct absolute path for data files
				absolute_file_path = pgmoneta_get_server_backup_identifier_data(srv, backups[backup_index]->label);
				pgmoneta_append(absolute_file_path, path);

				//calculate checksum for data file
				manifest_checksum = pgmoneta_json_get_string_value(f1, "Checksum");
				pgmoneta_json_item_put_string(output_item, "Manifest Checksum", manifest_checksum);

				//check if file checksum equals checksum reported on manifest.
				if(!pgmoneta_create_sha256_file(absolute_file_path, &actual_checksum))
				{
					pgmoneta_json_item_put_string(output_item, "Actual Checksum", actual_checksum);
					// pgmoneta_log_debug("Path: %s | Checksum: %s | Actual Checksum: %s", path, manifest_checksum, actual_checksum); -> delete later
					if (strcmp(manifest_checksum, actual_checksum))
					{
						//different checksums
						//put KO value in Check key in output_item json
						pgmoneta_json_item_put_string(output_item, "Check", "Fail");
						pgmoneta_log_debug("Path: %s | Checksum: %s | Actual Checksum: %s", path, manifest_checksum, actual_checksum);
						//TODO: verify leaks. As of now, since this process will die, OS frees resources
					}
					else
					{
						//put OK in value in Check key in output_item json
						pgmoneta_json_item_put_string(output_item, "Check", "Success");
					}
					pgmoneta_json_item_put_string(output_item, "Path", path);

					//now we have to put output_item into output
					pgmoneta_json_array_append_object(output, output_item);
				}
			}
			pgmoneta_json_print(output, 1);
			pgmoneta_json_close_reader(reader);
			pgmoneta_json_free(f1);
			return 0;
		}
		
	}
	else
	{
		free(reader);
		free(backup_manifest);
		goto error;
	}

error:

	for (int i = 0; i < number_of_backups; i++)
	{
		free(backups[i]);
	}
	free(backups);
	
	free(d);

	return 1;
}

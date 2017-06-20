/*
  Copyright (C) 2017 Thiago Bellini <hackedbellini@gmail.com>

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 2 of the License, or
  (at your option) any later version.
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
  You should have received a copy of the GNU General Public License
  along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define DEBUG 0
#define log_debug(msg, ...) \
  do { if (DEBUG) printf("[DEBUG] " msg "\n", ##__VA_ARGS__); } while (0)
#define log_error(msg, ...) \
  fprintf(stderr, "[ERROR] " msg "\n", ##__VA_ARGS__)

/* 499 chars as a maximum for strings should be enough for this exercise */
#define MAX_STRING 500
#define ASCII_NUM 128
#define DYNAMIC_BITS_START 8


/*
 * Structures
 */

#define BYTE_SIZE CHAR_BIT
typedef char byte;

typedef struct HT_ENC_ITEM
{
  unsigned long int key;
  int value;
} HT_ENC_ITEM;

typedef struct HT_ENC_TABLE
{
  int max;
  int size;
  struct HT_ENC_ITEM *items;
} HT_ENC_TABLE;

/* Not really a hash table as we will treat the key as item's index */
typedef struct HT_DEC_TABLE
{
  int max;
  int size;
  char **items;
} HT_DEC_TABLE;

typedef struct BIT_BUFFER
{
  FILE *fp;
  int pos;
  int first_read;
  byte bits;
} BIT_BUFFER;

typedef struct FILE_ITERATOR
{
  FILE *fp;
  char word[MAX_STRING];
  char carry;
} FILE_ITERATOR;


/*
 * Utilities
 */


/*
 * Convert int to binary.
 */
int *
_int2bin (int num, int size)
{
  int i, j;
  int *bin;

  j = size - 1;
  bin = malloc (size * sizeof (int));

  for (i = 0; i < size; i++)
    {
      bin[j] = (num >> i) & 1;
      j--;
    }

  return bin;
}

/*
 * Convert binary to int.
 */
int
_bin2int (int *num, int size)
{
  int i, j, retval;

  j = size - 1;
  retval = 0;

  for (i = 0; i < size; i++)
    {
      if (num[i])
        retval += 1 << j;
      j--;
    }

  return retval;
}

/*
 * Hash the string.
 *
 */
unsigned long int
_string_hash (char *str)
{
  char *c;
  unsigned long int hash = 0;

  /* sdbm hash algorithm */
  for (c = str; *c != '\0'; c++)
    hash = *c + (hash << 6) + (hash << 16) - hash;

  return hash;
}


/*
 * File iterator.
 */


/*
 * Initialize the file iterator.
 */
void
fi_init (struct FILE_ITERATOR *iter, FILE *fp)
{
  iter->fp = fp;
  iter->word[0] = '\0';
  iter->carry = '\0';
  rewind (iter->fp);
}


/*
 * Iterate to get next string.
 */
int
fi_next (struct FILE_ITERATOR *iter)
{
  int i = 0;
  char c;

  /* If we found a non-alphanumeric character on last iteration,
     this is what we should return in this one */
  if (iter->carry != '\0')
    {
      sprintf (iter->word, "%c", iter->carry);
      iter->carry = '\0';
      return 1;
    }

  while (fread (&(c), sizeof (char), 1, iter->fp))
    {
      /* Check if character is not alphanumeric (e.g. '.', ',', '\n', etc).
         In this case, either return it if there is no word being read
         at the moment, or put it on carry for the next iteration */
      if (!isalnum (c))
        {
          if (i == 0)
            {
              iter->word[i] = c;
              i++;
            }
          else
            {
              iter->carry = c;
            }
          break;
        }

      iter->word[i] = c;
      i++;
    }

  /* No more data to read */
  if (i == 0 && iter->carry == '\0')
    return EOF;

  iter->word[i] = '\0';
  return i;
}


/*
 * Bit buffer.
 */


/*
 * Initialize the bit buffer.
 */
void
bb_init (struct BIT_BUFFER *buffer, FILE *fp)
{
  buffer->pos = 0;
  buffer->bits = 0;
  buffer->first_read = 0;
  buffer->fp = fp;
}

/*
 * Flush bit buffer to file.
 */
void
bb_flush (struct BIT_BUFFER *buffer)
{
  if (buffer->pos == 0)
    return;

  /* Fill the rest of the byte with 0s */
  while (buffer->pos < BYTE_SIZE)
    {
      buffer->bits &= ~(1 << (BYTE_SIZE - buffer->pos - 1));
      (buffer->pos)++;
    }

  fwrite (&(buffer->bits), sizeof (byte), 1, buffer->fp);
  buffer->pos = 0;
  buffer->bits = 0;
}

/*
 * Write bits to file.
 */
void
bb_write (struct BIT_BUFFER *buffer, int *bits, int size)
{
  int i, shift_pos;

  for (i = 0; i < size; i++)
    {
      if (buffer->pos == BYTE_SIZE)
        bb_flush (buffer);

      shift_pos = BYTE_SIZE - buffer->pos - 1;
      if (bits[i])
        buffer->bits |= (1 << shift_pos);
      else
        buffer->bits &= ~(1 << shift_pos);

      (buffer->pos)++;
    }
}

/*
 * Read bits from file.
 */
int *
bb_read (struct BIT_BUFFER *buffer, int size)
{
  int i, shift_pos;
  int *bin;

  bin = malloc (size * sizeof (int));

  for (i = 0; i < size; i++)
    {
      if (!buffer->first_read || buffer->pos == BYTE_SIZE)
        {
          /* When we reach EOF, that mens any read bit was just fillers from
             the bb_flush function. We actually don't have any more data */
          if (!(fread (&(buffer->bits), sizeof (byte), 1, buffer->fp)))
            return NULL;
          buffer->first_read = 1;
          buffer->pos = 0;
        }

      shift_pos = BYTE_SIZE - buffer->pos - 1;
      bin[i] = (buffer->bits >> shift_pos) & 1;

      (buffer->pos)++;
    }

  return bin;
}


/*
 * Hash table for encoding.
 */


/*
 * Initialize the encoding hash table.
 */
void
ht_enc_init (struct HT_ENC_TABLE *table, int size)
{
  log_debug ("ht_enc_init: Initializing with a size of %d", size);

  table->size = 0;
  table->max = size;
  table->items = malloc (table->max * sizeof (HT_ENC_ITEM));
  if (table->items == NULL)
    {
      log_error ("ht_enc_init: Failed to allocate memory");
      exit (EXIT_FAILURE);
    }
}

/*
 * Free the encoding hash table.
 */
void
ht_enc_free (struct HT_ENC_TABLE *table)
{
  table->size = 0;
  free (table->items);
}

/*
 * Increase the size of the encoding hash table.
 */
void
ht_enc_increase (struct HT_ENC_TABLE *table, int size)
{
  log_debug ("ht_enc_increase: Increasing size from %d to %d",
             table->max, size);

  table->max = size;
  table->items = realloc (table->items, table->max * sizeof (HT_ENC_ITEM));
  if (table->items == NULL)
    {
      log_error ("ht_enc_increase: Failed to allocate memory");
      exit (EXIT_FAILURE);
    }
}

/*
 * Get key from the encoding hash table.
 */
int
ht_enc_get (struct HT_ENC_TABLE *table, char *key)
{
  HT_ENC_ITEM *item;
  int i;
  unsigned long int hash = _string_hash (key);

  log_debug ("ht_enc_get: key='%s'", key);

  for (i = 0; i < table->size; i++)
    {
      item = &(table->items[i]);
      if (item->key == hash)
        return item->value;
    }

  log_debug ("ht_enc_get: key not found");
  /* To simplify things, since our values will be >=0,
     -1 will mean that the key was not found */
  return -1;
}

/*
 * Set (key, vale) in the encoding hash table, overriding it if already exists.
 */
void
ht_enc_set (struct HT_ENC_TABLE *table, char *key, int value)
{
  HT_ENC_ITEM *item;
  int i;
  unsigned long int hash = _string_hash (key);

  log_debug ("ht_enc_set: key='%s', value='%d'", key, value);

  for (i = 0; i < table->size; i++)
    {
      item = &(table->items[i]);
      if (item->key == hash)
        {
          /* Existing item. Replace it */
          log_debug ("ht_enc_set: replacing existing key");
          item->value = value;
          return;
        }
    }

  log_debug ("ht_enc_set: creating new key");
  /* If the code hits here, we need to insert a new item */
  if (table->size == table->max)
    {
      log_error ("ht_enc_set: no more space in the dictionary");
      exit (EXIT_FAILURE);
    }

  item = &(table->items[table->size]);
  (table->size)++;

  item->key = hash;
  item->value = value;
}


/*
 * Hash table for decoding.
 */


/*
 * Initialize the decoding hash table.
 */
void
ht_dec_init (struct HT_DEC_TABLE *table, int size)
{
  int i;

  log_debug ("ht_dec_init: Initializing with a size of %d", size);

  table->size = 0;
  table->max = size;
  table->items = malloc (table->max * sizeof (char *));
  if (table->items == NULL)
    {
      log_error ("ht_dec_init: Failed to allocate memory");
      exit (EXIT_FAILURE);
    }

  /* Make sure everything points to NULL at the beggining */
  for (i = 0; i < size; i++)
    table->items[i] = NULL;
}

/*
 * Free the decoding hash table.
 */
void
ht_dec_free (struct HT_DEC_TABLE *table)
{
  int i;

  for (i = 0; i < table->max; i++)
    {
      char *item = table->items[i];
      free (item);
    }

  free (table->items);
}

/*
 * Increase the size of the decoding hash table.
 */
void
ht_dec_increase (struct HT_DEC_TABLE *table, int size)
{
  int i, old_max;

  old_max = table->max;
  log_debug ("ht_dec_increase: Increasing size from %d to %d", old_max, size);
  table->max = size;
  table->items = realloc (table->items, table->max * sizeof (char *));
  if (table->items == NULL)
    {
      log_error ("ht_dec_increase: Failed to allocate memory");
      exit (EXIT_FAILURE);
    }

  /* Make sure new positions points to NULL at the beggining */
  for (i = old_max; i < table->max; i++)
    table->items[i] = NULL;
}

/*
 * Get key from the decoding hash table.
 */
char *
ht_dec_get (struct HT_DEC_TABLE *table, int key)
{
  char *item;
  log_debug ("ht_dec_get: key='%d'", key);

  if (key >= table->max)
    {
      log_debug ("ht_dec_get: key greater than dictonary size");
      return NULL;
    }

  item = table->items[key];
  if (item == NULL)
    log_debug ("ht_dec_get: key not found");

  return item;
}

/*
 * Set (key, vale) in the decoding hash table, overriding it if already exists.
 */
void
ht_dec_set (struct HT_DEC_TABLE *table, int key, char *value)
{
  char *item;

  log_debug ("ht_dec_set: key='%d', value='%s'", key, value);

  if (key >= table->max)
    {
      log_error ("ht_dec_set: key doesn't fit in dictionary");
      exit (EXIT_FAILURE);
    }

  item = table->items[key];
  if (item == NULL)
    {
      log_debug ("ht_dec_set: creating new key");
      (table->size)++;
    }
  else
    {
      log_debug ("ht_dec_set: replacing existing key");
    }

  item = realloc (item, (strlen (value) + 1) * sizeof (char));
  if (item == NULL)
    {
      log_error ("ht_dec_set: failed to allocate memory for item");
      exit (EXIT_FAILURE);
    }
  strcpy (item, value);

  /* realloc may have moved the memory to another address */
  table->items[key] = item;
}


/*
 * Operations
 */

void
encode (const char *in_file_name, const char *out_file_name, int dynamic)
{
  FILE *fp_in, *fp_out;
  int i, bits, size, encoded, found, increase_bits;
  unsigned long int hash;
  char key[2], *c;
  BIT_BUFFER bb;
  FILE_ITERATOR f_iter;
  HT_ENC_TABLE ht_enc;

  log_debug ("encode: Starting to encode");

  fp_in = fopen (in_file_name, "r");
  if (fp_in == NULL)
    {
      log_error ("encode: Failed to open input file");
      exit (EXIT_FAILURE);
    }

  fp_out = fopen (out_file_name, "wb");
  if (fp_out == NULL)
    {
      log_error ("encode: Failed to open output file");
      exit (EXIT_FAILURE);
    }

  if (dynamic)
    {
      bits = DYNAMIC_BITS_START;
      size = 1 << bits; /* 2 ^ bits */
    }
  else
    {
      log_debug ("encode: Counting number of different words in the file");
      unsigned long int *hashes = NULL;
      fi_init (&f_iter, fp_in);
      size = 0;

      while (fi_next (&f_iter) != EOF)
        {
          /* Any 1 length string will already be in the ascii table */
          if (strlen (f_iter.word) == 1)
            continue;

          hash = _string_hash (f_iter.word);
          found = 0;
          for (i = 0; i < size; i++)
            {
              if (hash == hashes[i])
                {
                  found = 1;
                  break;
                }
            }
          if (!found)
            {
              hashes = realloc (hashes,
                                (size + 1) * sizeof (unsigned long int));
              if (hashes == NULL)
                {
                  log_error ("encode: failed to allocate memory for hash");
                  exit (EXIT_FAILURE);
                }
              hashes[size] = hash;
              size++;
            }
        }

      log_debug ("encode: Found %d different words", size);
      free (hashes);

      /* Number of characters on the ascii table */
      size += ASCII_NUM;
      /* ansi c has no log2, but it is the same as log(x)/log(2) */
      bits = ceil (log (size) / log (2));
      /* If not dynamic, store the dict size as the first thing on the file */
      fwrite (&(size), sizeof (int), 1, fp_out);
    }

  /* Init f_iter again so the file gets rewinded */
  fi_init (&f_iter, fp_in);
  bb_init (&bb, fp_out);
  ht_enc_init (&ht_enc, size);
  increase_bits = 0;

  /* Fill the dictionary with the ascii table */
  for (i = 0; i < ASCII_NUM; i++)
    {
      sprintf (key, "%c", (char) i);
      ht_enc_set (&ht_enc, key, i);
    }

  while (fi_next (&f_iter) != EOF)
    {
      encoded = ht_enc_get (&ht_enc, f_iter.word);
      if (encoded == -1)
        {
          for (c = f_iter.word; *c != '\0'; c++)
            {
              sprintf (key, "%c", *c);
              encoded = ht_enc_get (&ht_enc, key);
              int *encoded_bin = _int2bin (encoded, bits);
              bb_write (&bb, encoded_bin, bits);
              free (encoded_bin);
            }

          ht_enc_set (&ht_enc, f_iter.word, ht_enc.size);

          /* We can't just increase the bits here because, that would make us
             write the next separator (e.g. space, new line) with the new
             number of bits, which would make the decode fail to find it
             since it will only increase its number of bits when reading
             that same separator. To work around that, we set increase_bits
             and d the increase on next iteration, after writing the separator
          */
          if (dynamic && ht_enc.size == ht_enc.max)
              increase_bits = 1;
        }
      else
        {
          int *encoded_bin = _int2bin (encoded, bits);
          bb_write (&bb, encoded_bin, bits);
          free (encoded_bin);

          /* When ht_enc reaches its max size, increment bits by one and the
             dict by the amount of space required to store that extra bit. */
          if (increase_bits)
            {
              bits += 1;
              size = 1 << bits; /* 2 ^ bits */
              ht_enc_increase (&ht_enc, size);
              increase_bits = 0;
            }
        }
    }

  /* Flush any remaining bit to the file */
  log_debug ("encode: Flushing output file");
  bb_flush (&bb);
  fflush (fp_out);

  fclose (fp_in);
  fclose (fp_out);

  log_debug ("encode: Freeing resources");
  ht_enc_free (&ht_enc);
}

void
decode (const char *in_file_name, const char *out_file_name, int dynamic)
{
  FILE *fp_in, *fp_out;
  int i, bits, size, word_pos, encoded;
  int *encoded_bin;
  char key[2], word[MAX_STRING], *decoded;
  BIT_BUFFER bb;
  HT_DEC_TABLE ht_dec;

  log_debug ("encode: Starting to decode");

  fp_in = fopen (in_file_name, "rb");
  if (fp_in == NULL)
    {
      log_error ("encode: Failed to open input file");
      exit (EXIT_FAILURE);
    }

  fp_out = fopen (out_file_name, "w");
  if (fp_out == NULL)
    {
      log_error ("encode: Failed to open output file");
      exit (EXIT_FAILURE);
    }

  if (dynamic)
    {
      bits = DYNAMIC_BITS_START;
      size = 1 << bits; /* 2 ^ bits */
    }
  else
    {
      /* Size is the first thing in the file */
      fread (&(size), sizeof (int), 1, fp_in);
      /* ansi c has no log2, but it is the same as log(x)/log(2) */
      bits = ceil (log (size) / log (2));
    }

  bb_init (&bb, fp_in);
  ht_dec_init (&ht_dec, size);
  /* Fill the dictionary with the ascii table */
  for (i = 0; i < ASCII_NUM; i++)
    {
      sprintf (key, "%c", (char) i);
      ht_dec_set (&ht_dec, i, key);
    }

  word_pos = 0;
  while ((encoded_bin = bb_read (&bb, bits)) != NULL)
    {
      encoded = _bin2int (encoded_bin, bits);
      decoded = ht_dec_get (&ht_dec, encoded);
      fprintf (fp_out, "%s", decoded);

      if (strlen (decoded) == 1 && !isalnum (decoded[0]))
        {
          /* word_pos in (0, 1) means it is something we already had on dict,
             since we fill the ascii table at the beggining */
          if (word_pos > 1)
            {
              word[word_pos] = '\0';
              ht_dec_set (&ht_dec, ht_dec.size, word);

              /* When ht_dec reaches its max size, increment bits by one
                 and the dict by the amount of space required to store
                 that extra bit. */
              if (dynamic && ht_dec.size == ht_dec.max)
                {
                  bits += 1;
                  size = 1 << bits; /* 2 ^ bits */
                  ht_dec_increase (&ht_dec, size);
                }
            }
          word_pos = 0;
        }
      else if (strlen (decoded) == 1)
        {
          word[word_pos] = decoded[0];
          word_pos++;
        }

      int *encoded_free = encoded_bin;
      free (encoded_free);
    }

  /* Flush any remaining bit to the file */
  log_debug ("decode: Flushing output file");

  fclose (fp_in);
  fclose (fp_out);

  log_debug ("decode: Freeing resources");
  ht_dec_free (&ht_dec);
}

/*
 * Main
 */


int
main (int argc, const char *argv[])
{
  int i;
  int dynamic = 0;
  const char *in_file = NULL, *out_file = NULL, *op = NULL;

  /* Skip the first as it is the name of the program */
  for (i = 1; i < argc; i++)
    {
      if (strcmp (argv[i], "-d") == 0)
        {
          dynamic = 1;
        }
      else if (strcmp (argv[i], "-i") == 0)
        {
          i++;
          in_file = argv[i];
        }
      else if (strcmp (argv[i], "-o") == 0)
        {
          i++;
          out_file = argv[i];
        }
      else
        {
          op = argv[i];
        }
    }

  log_debug ("Operation: %s", op);
  log_debug ("Input file: %s", in_file);
  log_debug ("Output file: %s", out_file);

  if (op == NULL || in_file == NULL || out_file == NULL)
    {
      printf ("Missing required arguments. Usage:\n\n");
      printf ("  %s <operation> -i <input file> -o <output file>\n\n", argv[0]);
      printf ("Operation can be either 'encode' or 'decode'.\n");
      return EXIT_FAILURE;
    }

  if (strcmp (op, "encode") == 0)
    {
      encode (in_file, out_file, dynamic);
    }
  else if (strcmp (op, "decode") == 0)
    {
      decode (in_file, out_file, dynamic);
    }
  else
    {
      log_error ("Unknown operation '%s'", op);
      return EXIT_FAILURE;
    }

  return EXIT_SUCCESS;
}

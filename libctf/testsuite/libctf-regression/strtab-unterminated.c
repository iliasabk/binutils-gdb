/* Make sure that a dict with a string table that is not NUL-terminated is
   rejected at open time, even if all in-header offsets look fine, and that
   rejecting it leaves no stale error state behind.  */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctf-api.h>
#include <ctf.h>

int main (void)
{
  ctf_dict_t *fp;
  ctf_encoding_t e = { CTF_INT_SIGNED, 0, sizeof (long) };
  int err;
  ctf_id_t type;
  char *written;
  size_t written_size;
  ctf_header_t *hp;
  char *strs;
  char *foo;
  ctf_next_t *it = NULL;

  if ((fp = ctf_create (&err)) == NULL)
    goto open_err;

  if ((type = ctf_add_integer (fp, CTF_ADD_ROOT, "long", &e)) == CTF_ERR)
    goto err;

  if ((written = (char *) ctf_write_mem (fp, &written_size, (size_t) -1)) == NULL)
    goto write_err;

  ctf_dict_close (fp);

  /* Strip the trailing NUL from the string table: dicts ending in a string
     whose terminator is outside the section used to be accepted, at which
     point any consumer of that string read off the end of the buffer.  */

  hp = (ctf_header_t *) written;
  strs = written + sizeof (ctf_header_t);
  if (written_size < sizeof (ctf_header_t)
      || hp->cth_stroff + hp->cth_strlen > written_size - sizeof (ctf_header_t)
      || hp->cth_strlen == 0)
    {
      fprintf (stderr, "self-written dict has an unexpected layout\n");
      exit (1);
    }
  strs[hp->cth_stroff + hp->cth_strlen - 1] = 'X';

  if ((fp = ctf_simple_open (written, written_size, NULL, 0, 0, NULL, 0,
			     &err)) != NULL)
    {
      fprintf (stderr, "dict with unterminated string table opened OK?!\n");
      exit (1);
    }

  /* The rejection should specifically be the corruption check.  */
  if (err != ECTF_CORRUPT)
    {
      fprintf (stderr, "dict rejected, but with wrong error: %s\n",
	       ctf_errmsg (err));
      exit (1);
    }

  free (written);

  /* Consume the accumulated error strings.  */
  while ((foo = ctf_errwarning_next (NULL, &it, NULL, NULL)) != NULL)
    free (foo);

  printf ("All OK.\n");
  exit (0);

 open_err:
  fprintf (stderr, "Cannot create: %s\n", ctf_errmsg (err));
  exit (1);

 err:
  fprintf (stderr, "Cannot add: %s\n", ctf_errmsg (ctf_errno (fp)));
  exit (1);

 write_err:
  fprintf (stderr, "Cannot write: %s\n", ctf_errmsg (ctf_errno (fp)));
  exit (1);
}

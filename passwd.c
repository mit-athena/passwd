/* Copyright 1998 by the Massachusetts Institute of Technology.
 *
 * Permission to use, copy, modify, and distribute this
 * software and its documentation for any purpose and without
 * fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting
 * documentation, and that the name of M.I.T. not be used in
 * advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 */

/* This program implements a passwd glue program which selects between
 * the Kerberos and local password-changing programs, and updates the
 * local passwd file if the local password-changing program is selected.
 */

static const char rcsid[] = "$Id: passwd.c,v 1.13 2000-04-11 21:18:37 rbasch Exp $";

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pwd.h>
#include <signal.h>
#include <al.h>

#define PATH_KPASSWD_PROG	"/usr/athena/bin/kpasswd"
#define PATH_PASSWD_PROG	"/usr/bin/passwd"

/* This is a little non-intuitive.  PATH_PASSWD gives the pathname of
 * the file which contains the encrypted password string.
 * PATH_PASSWD_LOCAL gives the local (authoritative) copy of
 * PATH_PASSWD.  PATH_PASSWD_LOCAL_TMP gives a temporary filename for
 * updating PATH_PASSWD_LOCAL.
 */
#if defined(HAVE_MASTER_PASSWD)
#define PATH_PASSWD		"/etc/master.passwd"
#elif defined(HAVE_SHADOW)
#define PATH_PASSWD		"/etc/shadow"
#else
#define PATH_PASSWD		"/etc/passwd"
#endif
#define PATH_PASSWD_LOCAL	PATH_PASSWD ".local"
#define PATH_PASSWD_LOCAL_TMP	PATH_PASSWD_LOCAL ".tmp"

/* Temp file should be mode 600 on a master.passwd or shadow system,
 * 644 otherwise.
 */
#if defined(HAVE_MASTER_PASSWD) || defined(HAVE_SHADOW)
#define PLTMP_MODE (S_IWUSR|S_IRUSR)
#else
#define PLTMP_MODE (S_IWUSR|S_IRUSR|S_IRGRP|S_IROTH)
#endif

static void update_passwd_local(const char *username);
static int read_line(FILE *fp, char **buf, int *bufsize);
static void usage(void);
static void cleanup(int sig);

int main(int argc, char **argv)
{
  extern int optind;
  int c, local = 0, krb = 0, rval, status;
  char *args[4], *runner, *username;
  pid_t pid;
  uid_t ruid = getuid();
  struct passwd *pwd;

  while ((c = getopt(argc, argv, "lk")) != -1)
    {
      switch (c)
	{
	case 'l':
	  local = 1;
	  break;
	case 'k':
	  krb = 1;
	  break;
	default:
	  usage();
	}
    }
  argc -= optind;
  argv += optind;
  if ((local && krb) || argc > 1)
    usage();

  /* Figure out the username who is allegedly running this program.
   * Unfortunately, getenv("USER") yields the wrong answer if the user
   * has done an "su", so fall back to that only if ruid isn't in the
   * passwd file.
   */
  pwd = getpwuid(ruid);
  if (pwd)
    runner = pwd->pw_name;
  else
    {
      runner = getenv("USER");
      if (!runner)
	{
	  fprintf(stderr, "passwd: can't determine running user.\n");
	  return 1;
	}
    }

  /* runner currently points to static or environment storage; make a
   * copy of it in allocated memory.
   */
  runner = strdup(runner);
  if (!runner)
    {
      fprintf(stderr, "passwd: out of memory.\n");
      return 1;
    }

  if (!local && !krb)
    {
      /* Decide via a heuristic test whether to run local or Kerberos
       * password-changing program.  If the user running the program
       * is root or is a local account according to /etc/athena/access,
       * then we use the local passwd program; otherwise we use
       * kpasswd.
       */
      if (ruid == 0 || al_is_local_acct(runner) == 1)
	local = 1;
    }

  if (local)
    {
      /* Figure out which user's password is being changed. */
      username = (argc == 1) ? argv[0] : runner;

      /* If we're not run by root, make sure username matches our ruid
       * in the passwd file.  This is perhaps overly paranoid, since
       * /usr/bin/passwd should error out if the user is unauthorized,
       * but we don't want to let users update other users' local passwd
       * entries if /usr/bin/passwd doesn't properly flag the error.
       */
      if (ruid != 0)
	{
	  pwd = getpwnam(username);
	  if (!pwd)
	    {
	      fprintf(stderr, "passwd: Can't find uid for username %s.\n",
		      username);
	      return 1;
	    }
	  if (!pwd || pwd->pw_uid != ruid)
	    {
	      fprintf(stderr, "passwd: username/ruid mismatch: %s has uid %lu,"
		      " but ruid is %lu.\n", username,
		      (unsigned long) pwd->pw_uid, (unsigned long) ruid);
	      return 1;
	    }
	}

      printf("Running local password-changing program for %s.\n", username);
      pid = fork();
      if (pid == -1)
	{
	  perror("passwd: fork");
	  return 1;
	}
      else if (pid == 0)
	{
	  setuid(ruid);
	  args[0] = "passwd";
#ifdef PASSWD_NEEDS_LFLAG
	  /* Some passwd programs need a -l flag to specify the local
	   * password.
	   */
	  args[1] = "-l";
	  args[2] = username;
	  args[3] = NULL;
#else
	  args[1] = username;
	  args[2] = NULL;
#endif
	  execv(PATH_PASSWD_PROG, args);
	  perror("passwd: execv");
	  _exit(1);
	  /* gcc (2.95 at least) doesn't realize that _exit() exits. */
	  return 1;
	}
      else
	{
	  /* Wait for the child to complete. */
	  while ((rval = waitpid(pid, &status, 0)) == -1 && errno == EINTR)
	    ;
	  if (rval == -1)
	    {
	      perror("passwd: wait");
	      return 1;
	    }
	  /* If the child exited abnormally, assume that it printed an
	   * error message.
	   */
	  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
	    return 1;

	  update_passwd_local(username);
	  return 0;
	}
    }
  else
    {
      printf("Running Kerberos password-changing program.\n");
      setuid(ruid);
      args[0] = "kpasswd";
      if (*argv)
	{
	  args[1] = "-n";
	  args[2] = *argv;
	  args[3] = NULL;
	}
      else
	args[1] = NULL;
      execv(PATH_KPASSWD_PROG, args);
      perror("passwd: execv");
      return 1;
    }
}

static void update_passwd_local(const char *username)
{
  FILE *fp, *fp_out;
  char *line = NULL, *userline;
  int linesize, len, found, fd, i, status;
  struct sigaction action;
  sigset_t mask, omask;
  mode_t oldumask;

  len = strlen(username);

  /* Find the line for username in the passwd file. */
  fp = fopen(PATH_PASSWD, "r");
  if (fp == NULL)
    {
      fprintf(stderr, "Can't open %s so not updating local passwd file.\n",
	      PATH_PASSWD);
      exit(1);
    }
  found = 0;
  while (read_line(fp, &line, &linesize) == 0)
    {
      if (strncmp(line, username, len) == 0 && line[len] == ':')
	{
	  found = 1;
	  break;
	}
    }
  if (!found)
    {
      fprintf(stderr,
	      "Can't find %s in %s so not updating local passwd file.\n",
	      username, PATH_PASSWD);
      exit(1);
    }
  fclose(fp);
  userline = line;
  line = NULL;

  /* Open the local passwd file for reading. */
  fp = fopen(PATH_PASSWD_LOCAL, "r");
  if (fp == NULL)
    {
      if (errno != ENOENT)
	fprintf(stderr, "Can't read %s so not updating local passwd file.\n",
		PATH_PASSWD_LOCAL);
      exit(1);
    }

  sigemptyset(&mask);
  sigaddset(&mask, SIGHUP);
  sigaddset(&mask, SIGINT);
  sigaddset(&mask, SIGQUIT);
  sigaddset(&mask, SIGTERM);

  /* Open the temporary local passwd file for writing.  We have to do some
   * clever signal-handling tricks to make sure that tty signals don't
   * leave the lock file hanging around.
   */
  for (i = 0; i < 10; i++)
    {
      sigprocmask(SIG_BLOCK, &mask, &omask);
      oldumask = umask(0);
      fd = open(PATH_PASSWD_LOCAL_TMP, O_RDWR|O_CREAT|O_EXCL, PLTMP_MODE);
      umask(oldumask);
      if (fd != -1)
	{
	  sigemptyset(&action.sa_mask);
	  action.sa_handler = cleanup;
	  action.sa_flags = 0;
	  sigaction(SIGHUP, &action, NULL);
	  sigaction(SIGINT, &action, NULL);
	  sigaction(SIGQUIT, &action, NULL);
	  sigaction(SIGTERM, &action, NULL);
	}
      sigprocmask(SIG_SETMASK, &omask, NULL);
      if (fd != -1 || errno != EEXIST)
	break;
      sleep(1);
    }
  if (fd == -1 || (fp_out = fdopen(fd, "w")) == NULL)
    {
      fprintf(stderr,
	      "Can't open %s for writing so not updating local passwd file.\n",
	      PATH_PASSWD_LOCAL_TMP);
      if (fd != -1)
	{
	  sigprocmask(SIG_BLOCK, &mask, NULL);
	  unlink(PATH_PASSWD_LOCAL_TMP);
	}
      exit(1);
    }

  /* Copy the local passwd file to the temporary file.  Replace the first
   * line beginning with username with the line we found in the passwd
   * file.
   */
  found = 0;
  while ((status = read_line(fp, &line, &linesize)) == 0)
    {
      if (!found && strncmp(line, username, len) == 0 && line[len] == ':')
	{
	  fputs(userline, fp_out);
	  found = 1;
	}
      else
	fputs(line, fp_out);
      putc('\n', fp_out);
    }
  free(line);
  free(userline);
  fclose(fp);

  /* Block tty signals for the short duration of our lifetime so we don't
   * erroneously delete the temporary file after giving it up.
   */
  sigprocmask(SIG_BLOCK, &mask, NULL);

  if (!found)
    {
      /* We didn't actually change the file; don't do an update. */
      fclose(fp_out);
      unlink(PATH_PASSWD_LOCAL_TMP);
      return;
    }

  if (status < 0 || ferror(fp_out) || fclose(fp_out) == EOF)
    {
      fprintf(stderr,
	      "Error copying %s to %s so not updating local passwd file.\n",
	      PATH_PASSWD_LOCAL, PATH_PASSWD_LOCAL_TMP);
      unlink(PATH_PASSWD_LOCAL_TMP); 
      exit(1);
    }

  /* Replace the local passwd file with the temporary file. */
  printf("Updating %s with new passwd entry.\n", PATH_PASSWD_LOCAL);
  if (rename(PATH_PASSWD_LOCAL_TMP, PATH_PASSWD_LOCAL) == -1)
    {
      fprintf(stderr,
	      "Error renaming %s to %s so not updating local passwd file.\n",
	      PATH_PASSWD_LOCAL, PATH_PASSWD_LOCAL_TMP);
      unlink(PATH_PASSWD_LOCAL_TMP);
      exit(1);
    }
}

/* Read a line from a file into a dynamically allocated buffer,
 * zeroing the trailing newline if there is one.  The calling routine
 * may call read_line multiple times with the same buf and bufsize
 * pointers; *buf will be reallocated and *bufsize adjusted as
 * appropriate.  The initial value of *buf should be NULL.  After the
 * calling routine is done reading lines, it should free *buf.  This
 * function returns 0 if a line was successfully read, 1 if the file
 * ended, and -1 if there was an I/O error or if it ran out of memory.
 */

static int read_line(FILE *fp, char **buf, int *bufsize)
{
  char *newbuf;
  int offset = 0, len;

  if (*buf == NULL)
    {
      *buf = malloc(128);
      if (!*buf)
	return -1;
      *bufsize = 128;
    }

  while (1)
    {
      if (!fgets(*buf + offset, *bufsize - offset, fp))
	return (offset != 0) ? 0 : (ferror(fp)) ? -1 : 1;
      len = offset + strlen(*buf + offset);
      if ((*buf)[len - 1] == '\n')
	{
	  (*buf)[len - 1] = 0;
	  return 0;
	}
      offset = len;

      /* Allocate more space. */
      newbuf = realloc(*buf, *bufsize * 2);
      if (!newbuf)
	return -1;
      *buf = newbuf;
      *bufsize *= 2;
    }
}

static void usage(void)
{
  fprintf(stderr, "Usage: passwd [-k|-l] [username]\n");
  exit(1);
}

static void cleanup(int sig)
{
  unlink(PATH_PASSWD_LOCAL_TMP);
  exit(1);
}

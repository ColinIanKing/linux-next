// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2002 Roman Zippel <zippel@linux-m68k.org>
 */

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <xalloc.h>
#include "internal.h"
#include "lkc.h"

struct gstr autoconf_cmd;

/* return true if 'path' exists, false otherwise */
static bool is_present(const char *path)
{
	struct stat st;

	return !stat(path, &st);
}

/* return true if 'path' exists and it is a directory, false otherwise */
static bool is_dir(const char *path)
{
	struct stat st;

	if (stat(path, &st))
		return false;

	return S_ISDIR(st.st_mode);
}

/* return true if the given two files are the same, false otherwise */
static bool is_same(const char *file1, const char *file2)
{
	int fd1, fd2;
	struct stat st1, st2;
	void *map1, *map2;
	bool ret = false;

	fd1 = open(file1, O_RDONLY);
	if (fd1 < 0)
		return ret;

	fd2 = open(file2, O_RDONLY);
	if (fd2 < 0)
		goto close1;

	ret = fstat(fd1, &st1);
	if (ret)
		goto close2;
	ret = fstat(fd2, &st2);
	if (ret)
		goto close2;

	if (st1.st_size != st2.st_size)
		goto close2;

	map1 = mmap(NULL, st1.st_size, PROT_READ, MAP_PRIVATE, fd1, 0);
	if (map1 == MAP_FAILED)
		goto close2;

	map2 = mmap(NULL, st2.st_size, PROT_READ, MAP_PRIVATE, fd2, 0);
	if (map2 == MAP_FAILED)
		goto close2;

	if (memcmp(map1, map2, st1.st_size))
		goto close2;

	ret = true;
close2:
	close(fd2);
close1:
	close(fd1);

	return ret;
}

/*
 * Create the parent directory of the given path.
 *
 * For example, if 'include/config/auto.conf' is given, create 'include/config'.
 */
static int make_parent_dir(const char *path)
{
	char tmp[PATH_MAX + 1];
	char *p;

	strncpy(tmp, path, sizeof(tmp));
	tmp[sizeof(tmp) - 1] = 0;

	/* Remove the base name. Just return if nothing is left */
	p = strrchr(tmp, '/');
	if (!p)
		return 0;
	*(p + 1) = 0;

	/* Just in case it is an absolute path */
	p = tmp;
	while (*p == '/')
		p++;

	while ((p = strchr(p, '/'))) {
		*p = 0;

		/* skip if the directory exists */
		if (!is_dir(tmp) && mkdir(tmp, 0755))
			return -1;

		*p = '/';
		while (*p == '/')
			p++;
	}

	return 0;
}

static char depfile_path[PATH_MAX];
static size_t depfile_prefix_len;

/* touch depfile for symbol 'name' */
static int conf_touch_dep(const char *name)
{
	int fd;

	/* check overflow: prefix + name + '\0' must fit in buffer. */
	if (depfile_prefix_len + strlen(name) + 1 > sizeof(depfile_path))
		return -1;

	strcpy(depfile_path + depfile_prefix_len, name);

	fd = open(depfile_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd == -1)
		return -1;
	close(fd);

	return 0;
}

static void conf_warning(const char *fmt, ...)
	__attribute__ ((format (printf, 1, 2)));

static void conf_message(const char *fmt, ...)
	__attribute__ ((format (printf, 1, 2)));

static const char *conf_filename;
static int conf_lineno, conf_warnings;

bool conf_errors(void)
{
	if (conf_warnings)
		return getenv("KCONFIG_WERROR");
	return false;
}

static void conf_warning(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fprintf(stderr, "%s:%d:warning: ", conf_filename, conf_lineno);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
	conf_warnings++;
}

static void conf_default_message_callback(const char *s)
{
	printf("#\n# ");
	printf("%s", s);
	printf("\n#\n");
}

static void (*conf_message_callback)(const char *s) =
	conf_default_message_callback;
void conf_set_message_callback(void (*fn)(const char *s))
{
	conf_message_callback = fn;
}

static void conf_message(const char *fmt, ...)
{
	va_list ap;
	char buf[4096];

	if (!conf_message_callback)
		return;

	va_start(ap, fmt);

	vsnprintf(buf, sizeof(buf), fmt, ap);
	conf_message_callback(buf);
	va_end(ap);
}

const char *conf_get_configname(void)
{
	char *name = getenv("KCONFIG_CONFIG");

	return name ? name : ".config";
}

static const char *conf_get_autoconfig_name(void)
{
	char *name = getenv("KCONFIG_AUTOCONFIG");

	return name ? name : "include/config/auto.conf";
}

static const char *conf_get_autoheader_name(void)
{
	char *name = getenv("KCONFIG_AUTOHEADER");

	return name ? name : "include/generated/autoconf.h";
}

static const char *conf_get_rustccfg_name(void)
{
	char *name = getenv("KCONFIG_RUSTCCFG");

	return name ? name : "include/generated/rustc_cfg";
}

static int conf_set_sym_val(struct symbol *sym, int def, int def_flags, char *p)
{
	char *p2;

	switch (sym->type) {
	case S_TRISTATE:
		if (p[0] == 'm') {
			sym->def[def].tri = mod;
			sym->flags |= def_flags;
			break;
		}
		/* fall through */
	case S_BOOLEAN:
		if (p[0] == 'y') {
			sym->def[def].tri = yes;
			sym->flags |= def_flags;
			break;
		}
		if (p[0] == 'n') {
			sym->def[def].tri = no;
			sym->flags |= def_flags;
			break;
		}
		if (def != S_DEF_AUTO)
			conf_warning("symbol value '%s' invalid for %s",
				     p, sym->name);
		return 1;
	case S_STRING:
		/* No escaping for S_DEF_AUTO (include/config/auto.conf) */
		if (def != S_DEF_AUTO) {
			if (*p++ != '"')
				break;
			for (p2 = p; (p2 = strpbrk(p2, "\"\\")); p2++) {
				if (*p2 == '"') {
					*p2 = 0;
					break;
				}
				memmove(p2, p2 + 1, strlen(p2));
			}
			if (!p2) {
				conf_warning("invalid string found");
				return 1;
			}
		}
		/* fall through */
	case S_INT:
	case S_HEX:
		if (sym_string_valid(sym, p)) {
			sym->def[def].val = xstrdup(p);
			sym->flags |= def_flags;
		} else {
			if (def != S_DEF_AUTO)
				conf_warning("symbol value '%s' invalid for %s",
					     p, sym->name);
			return 1;
		}
		break;
	default:
		;
	}
	return 0;
}

/* like getline(), but the newline character is stripped away */
static ssize_t getline_stripped(char **lineptr, size_t *n, FILE *stream)
{
	ssize_t len;

	len = getline(lineptr, n, stream);

	if (len > 0 && (*lineptr)[len - 1] == '\n') {
		len--;
		(*lineptr)[len] = '\0';

		if (len > 0 && (*lineptr)[len - 1] == '\r') {
			len--;
			(*lineptr)[len] = '\0';
		}
	}

	return len;
}

int conf_read_simple(const char *name, int def)
{
	FILE *in = NULL;
	char   *line = NULL;
	size_t  line_asize = 0;
	char *p, *val;
	struct symbol *sym;
	int def_flags;
	const char *warn_unknown, *sym_name;

	warn_unknown = getenv("KCONFIG_WARN_UNKNOWN_SYMBOLS");
	if (name) {
		in = zconf_fopen(name);
	} else {
		char *env;

		name = conf_get_configname();
		in = zconf_fopen(name);
		if (in)
			goto load;
		conf_set_changed(true);

		env = getenv("KCONFIG_DEFCONFIG_LIST");
		if (!env)
			return 1;

		while (1) {
			bool is_last;

			while (isspace(*env))
				env++;

			if (!*env)
				break;

			p = env;
			while (*p && !isspace(*p))
				p++;

			is_last = (*p == '\0');

			*p = '\0';

			name = env;

			in = zconf_fopen(name);
			if (in) {
				conf_message("using defaults found in %s",
					     name);
				goto load;
			}

			if (is_last)
				break;

			env = p + 1;
		}
	}
	if (!in)
		return 1;

load:
	conf_filename = name;
	conf_lineno = 0;
	conf_warnings = 0;

	def_flags = SYMBOL_DEF << def;
	for_all_symbols(sym) {
		sym->flags &= ~def_flags;
		switch (sym->type) {
		case S_INT:
		case S_HEX:
		case S_STRING:
			free(sym->def[def].val);
			/* fall through */
		default:
			sym->def[def].val = NULL;
			sym->def[def].tri = no;
		}
	}

	if (def == S_DEF_USER) {
		for_all_symbols(sym)
			sym->flags &= ~SYMBOL_VALID;
		expr_invalidate_all();
	}

	while (getline_stripped(&line, &line_asize, in) != -1) {
		struct menu *choice;

		conf_lineno++;

		if (!line[0]) /* blank line */
			continue;

		if (line[0] == '#') {
			if (line[1] != ' ')
				continue;
			p = line + 2;
			if (memcmp(p, CONFIG_, strlen(CONFIG_)))
				continue;
			sym_name = p + strlen(CONFIG_);
			p = strchr(sym_name, ' ');
			if (!p)
				continue;
			*p++ = 0;
			if (strcmp(p, "is not set"))
				continue;

			val = "n";
		} else {
			if (memcmp(line, CONFIG_, strlen(CONFIG_))) {
				conf_warning("unexpected data: %s", line);
				continue;
			}

			sym_name = line + strlen(CONFIG_);
			p = strchr(sym_name, '=');
			if (!p) {
				conf_warning("unexpected data: %s", line);
				continue;
			}
			*p = 0;
			val = p + 1;
		}

		sym = sym_find(sym_name);
		if (!sym) {
			if (def == S_DEF_AUTO) {
				/*
				 * Reading from include/config/auto.conf.
				 * If CONFIG_FOO previously existed in auto.conf
				 * but it is missing now, include/config/FOO
				 * must be touched.
				 */
				conf_touch_dep(sym_name);
			} else {
				if (warn_unknown)
					conf_warning("unknown symbol: %s", sym_name);

				conf_set_changed(true);
			}
			continue;
		}

		if (sym->flags & def_flags)
			conf_warning("override: reassigning to symbol %s", sym->name);

		if (conf_set_sym_val(sym, def, def_flags, val))
			continue;

		if (def != S_DEF_USER)
			continue;

		/*
		 * If this is a choice member, give it the highest priority.
		 * If conflicting CONFIG options are given from an input file,
		 * the last one wins.
		 */
		choice = sym_get_choice_menu(sym);
		if (choice)
			list_move(&sym->choice_link, &choice->choice_members);
	}
	free(line);
	fclose(in);

	return 0;
}

int conf_read(const char *name)
{
	struct symbol *sym;

	conf_set_changed(false);

	if (conf_read_simple(name, S_DEF_USER)) {
		sym_calc_value(modules_sym);
		return 1;
	}

	sym_calc_value(modules_sym);

	for_all_symbols(sym) {
		sym_calc_value(sym);
		if (sym_is_choice(sym))
			continue;
		if (sym_has_value(sym) && (sym->flags & SYMBOL_WRITE)) {
			/* check that calculated value agrees with saved value */
			switch (sym->type) {
			case S_BOOLEAN:
			case S_TRISTATE:
				if (sym->def[S_DEF_USER].tri == sym_get_tristate_value(sym))
					continue;
				break;
			default:
				if (!strcmp(sym->curr.val, sym->def[S_DEF_USER].val))
					continue;
				break;
			}
		} else if (!sym_has_value(sym) && !(sym->flags & SYMBOL_WRITE))
			/* no previous value and not saved */
			continue;
		conf_set_changed(true);
		/* maybe print value in verbose mode... */
	}

	if (conf_warnings)
		conf_set_changed(true);

	return 0;
}

struct comment_style {
	const char *decoration;
	const char *prefix;
	const char *postfix;
};

static const struct comment_style comment_style_pound = {
	.decoration = "#",
	.prefix = "#",
	.postfix = "#",
};

static const struct comment_style comment_style_c = {
	.decoration = " *",
	.prefix = "/*",
	.postfix = " */",
};

static void conf_write_heading(FILE *fp, const struct comment_style *cs)
{
	if (!cs)
		return;

	fprintf(fp, "%s\n", cs->prefix);

	fprintf(fp, "%s Automatically generated file; DO NOT EDIT.\n",
		cs->decoration);

	fprintf(fp, "%s %s\n", cs->decoration, rootmenu.prompt->text);

	fprintf(fp, "%s\n", cs->postfix);
}

/* The returned pointer must be freed on the caller side */
static char *escape_string_value(const char *in)
{
	const char *p;
	char *out;
	size_t len;

	len = strlen(in) + strlen("\"\"") + 1;

	p = in;
	while (1) {
		p += strcspn(p, "\"\\");

		if (p[0] == '\0')
			break;

		len++;
		p++;
	}

	out = xmalloc(len);
	out[0] = '\0';

	strcat(out, "\"");

	p = in;
	while (1) {
		len = strcspn(p, "\"\\");
		strncat(out, p, len);
		p += len;

		if (p[0] == '\0')
			break;

		strcat(out, "\\");
		strncat(out, p++, 1);
	}

	strcat(out, "\"");

	return out;
}

enum output_n { OUTPUT_N, OUTPUT_N_AS_UNSET, OUTPUT_N_NONE };

static void __print_symbol(FILE *fp, struct symbol *sym, enum output_n output_n,
			   bool escape_string)
{
	const char *val;
	char *escaped = NULL;

	if (sym->type == S_UNKNOWN)
		return;

	val = sym_get_string_value(sym);

	if ((sym->type == S_BOOLEAN || sym->type == S_TRISTATE) &&
	    output_n != OUTPUT_N && *val == 'n') {
		if (output_n == OUTPUT_N_AS_UNSET)
			fprintf(fp, "# %s%s is not set\n", CONFIG_, sym->name);
		return;
	}

	if (sym->type == S_STRING && escape_string) {
		escaped = escape_string_value(val);
		val = escaped;
	}

	fprintf(fp, "%s%s=%s\n", CONFIG_, sym->name, val);

	free(escaped);
}

static void print_symbol_for_dotconfig(FILE *fp, struct symbol *sym)
{
	__print_symbol(fp, sym, OUTPUT_N_AS_UNSET, true);
}

static void print_symbol_for_autoconf(FILE *fp, struct symbol *sym)
{
	__print_symbol(fp, sym, OUTPUT_N_NONE, false);
}

void print_symbol_for_listconfig(struct symbol *sym)
{
	__print_symbol(stdout, sym, OUTPUT_N, true);
}

static void print_symbol_for_c(FILE *fp, struct symbol *sym)
{
	const char *val;
	const char *sym_suffix = "";
	const char *val_prefix = "";
	char *escaped = NULL;

	if (sym->type == S_UNKNOWN)
		return;

	val = sym_get_string_value(sym);

	switch (sym->type) {
	case S_BOOLEAN:
	case S_TRISTATE:
		switch (*val) {
		case 'n':
			return;
		case 'm':
			sym_suffix = "_MODULE";
			/* fall through */
		default:
			val = "1";
		}
		break;
	case S_HEX:
		if (val[0] != '0' || (val[1] != 'x' && val[1] != 'X'))
			val_prefix = "0x";
		break;
	case S_STRING:
		escaped = escape_string_value(val);
		val = escaped;
	default:
		break;
	}

	fprintf(fp, "#define %s%s%s %s%s\n", CONFIG_, sym->name, sym_suffix,
		val_prefix, val);

	free(escaped);
}

static void print_symbol_for_rustccfg(FILE *fp, struct symbol *sym)
{
	const char *val;
	const char *val_prefix = "";
	char *val_prefixed = NULL;
	size_t val_prefixed_len;
	char *escaped = NULL;

	if (sym->type == S_UNKNOWN)
		return;

	val = sym_get_string_value(sym);

	switch (sym->type) {
	case S_BOOLEAN:
	case S_TRISTATE:
		/*
		 * We do not care about disabled ones, i.e. no need for
		 * what otherwise are "comments" in other printers.
		 */
		if (*val == 'n')
			return;

		/*
		 * To have similar functionality to the C macro `IS_ENABLED()`
		 * we provide an empty `--cfg CONFIG_X` here in both `y`
		 * and `m` cases.
		 *
		 * Then, the common `fprintf()` below will also give us
		 * a `--cfg CONFIG_X="y"` or `--cfg CONFIG_X="m"`, which can
		 * be used as the equivalent of `IS_BUILTIN()`/`IS_MODULE()`.
		 */
		fprintf(fp, "--cfg=%s%s\n", CONFIG_, sym->name);
		break;
	case S_HEX:
		if (val[0] != '0' || (val[1] != 'x' && val[1] != 'X'))
			val_prefix = "0x";
		break;
	default:
		break;
	}

	if (strlen(val_prefix) > 0) {
		val_prefixed_len = strlen(val) + strlen(val_prefix) + 1;
		val_prefixed = xmalloc(val_prefixed_len);
		snprintf(val_prefixed, val_prefixed_len, "%s%s", val_prefix, val);
		val = val_prefixed;
	}

	/* All values get escaped: the `--cfg` option only takes strings */
	escaped = escape_string_value(val);
	val = escaped;

	fprintf(fp, "--cfg=%s%s=%s\n", CONFIG_, sym->name, val);

	free(escaped);
	free(val_prefixed);
}

/*
 * Write out a minimal config.
 * All values that has default values are skipped as this is redundant.
 */
int conf_write_defconfig(const char *filename)
{
	struct symbol *sym;
	struct menu *menu;
	FILE *out;

	out = fopen(filename, "w");
	if (!out)
		return 1;

	sym_clear_all_valid();

	menu_for_each_entry(menu) {
		struct menu *choice;

		sym = menu->sym;

		if (!sym || sym_is_choice(sym))
			continue;

		sym_calc_value(sym);
		if (!(sym->flags & SYMBOL_WRITE))
			continue;
		sym->flags &= ~SYMBOL_WRITE;
		/* Skip unchangeable symbols */
		if (!sym_is_changeable(sym))
			continue;
		/* Skip symbols that are equal to the default */
		if (!strcmp(sym_get_string_value(sym), sym_get_string_default(sym)))
			continue;

		/* Skip choice values that are equal to the default */
		choice = sym_get_choice_menu(sym);
		if (choice) {
			struct symbol *ds;

			ds = sym_choice_default(choice);
			if (sym == ds && sym_get_tristate_value(sym) == yes)
				continue;
		}
		print_symbol_for_dotconfig(out, sym);
	}
	fclose(out);
	return 0;
}

int conf_write(const char *name)
{
	FILE *out;
	struct symbol *sym;
	struct menu *menu;
	const char *str;
	char tmpname[PATH_MAX + 1], oldname[PATH_MAX + 1];
	char *env;
	bool need_newline = false;

	if (!name)
		name = conf_get_configname();

	if (!*name) {
		fprintf(stderr, "config name is empty\n");
		return -1;
	}

	if (is_dir(name)) {
		fprintf(stderr, "%s: Is a directory\n", name);
		return -1;
	}

	if (make_parent_dir(name))
		return -1;

	env = getenv("KCONFIG_OVERWRITECONFIG");
	if (env && *env) {
		*tmpname = 0;
		out = fopen(name, "w");
	} else {
		snprintf(tmpname, sizeof(tmpname), "%s.%d.tmp",
			 name, (int)getpid());
		out = fopen(tmpname, "w");
	}
	if (!out)
		return 1;

	conf_write_heading(out, &comment_style_pound);

	if (!conf_get_changed())
		sym_clear_all_valid();

	menu = rootmenu.list;
	while (menu) {
		sym = menu->sym;
		if (!sym) {
			if (!menu_is_visible(menu))
				goto next;
			str = menu_get_prompt(menu);
			fprintf(out, "\n"
				     "#\n"
				     "# %s\n"
				     "#\n", str);
			need_newline = false;
		} else if (!sym_is_choice(sym) &&
			   !(sym->flags & SYMBOL_WRITTEN)) {
			sym_calc_value(sym);
			if (!(sym->flags & SYMBOL_WRITE))
				goto next;
			if (need_newline) {
				fprintf(out, "\n");
				need_newline = false;
			}
			sym->flags |= SYMBOL_WRITTEN;
			print_symbol_for_dotconfig(out, sym);
		}

next:
		if (menu->list) {
			menu = menu->list;
			continue;
		}

end_check:
		if (!menu->sym && menu_is_visible(menu) && menu != &rootmenu &&
		    menu->prompt->type == P_MENU) {
			fprintf(out, "# end of %s\n", menu_get_prompt(menu));
			need_newline = true;
		}

		if (menu->next) {
			menu = menu->next;
		} else {
			menu = menu->parent;
			if (menu)
				goto end_check;
		}
	}
	fclose(out);

	for_all_symbols(sym)
		sym->flags &= ~SYMBOL_WRITTEN;

	if (*tmpname) {
		if (is_same(name, tmpname)) {
			conf_message("No change to %s", name);
			unlink(tmpname);
			conf_set_changed(false);
			return 0;
		}

		snprintf(oldname, sizeof(oldname), "%s.old", name);
		rename(name, oldname);
		if (rename(tmpname, name))
			return 1;
	}

	conf_message("configuration written to %s", name);

	conf_set_changed(false);

	return 0;
}

/* write a dependency file as used by kbuild to track dependencies */
static int conf_write_autoconf_cmd(const char *autoconf_name)
{
	char name[PATH_MAX], tmp[PATH_MAX];
	FILE *out;
	int ret;

	ret = snprintf(name, sizeof(name), "%s.cmd", autoconf_name);
	if (ret >= sizeof(name)) /* check truncation */
		return -1;

	if (make_parent_dir(name))
		return -1;

	ret = snprintf(tmp, sizeof(tmp), "%s.cmd.tmp", autoconf_name);
	if (ret >= sizeof(tmp)) /* check truncation */
		return -1;

	out = fopen(tmp, "w");
	if (!out) {
		perror("fopen");
		return -1;
	}

	fprintf(out, "autoconfig := %s\n", autoconf_name);

	fputs(str_get(&autoconf_cmd), out);

	fflush(out);
	ret = ferror(out); /* error check for all fprintf() calls */
	fclose(out);
	if (ret)
		return -1;

	if (rename(tmp, name)) {
		perror("rename");
		return -1;
	}

	return 0;
}

static int conf_touch_deps(void)
{
	const char *name, *tmp;
	struct symbol *sym;
	int res;

	name = conf_get_autoconfig_name();
	tmp = strrchr(name, '/');
	depfile_prefix_len = tmp ? tmp - name + 1 : 0;
	if (depfile_prefix_len + 1 > sizeof(depfile_path))
		return -1;

	strncpy(depfile_path, name, depfile_prefix_len);
	depfile_path[depfile_prefix_len] = 0;

	conf_read_simple(name, S_DEF_AUTO);

	for_all_symbols(sym) {
		if (sym_is_choice(sym))
			continue;
		if (sym->flags & SYMBOL_WRITE) {
			if (sym->flags & SYMBOL_DEF_AUTO) {
				/*
				 * symbol has old and new value,
				 * so compare them...
				 */
				switch (sym->type) {
				case S_BOOLEAN:
				case S_TRISTATE:
					if (sym_get_tristate_value(sym) ==
					    sym->def[S_DEF_AUTO].tri)
						continue;
					break;
				case S_STRING:
				case S_HEX:
				case S_INT:
					if (!strcmp(sym_get_string_value(sym),
						    sym->def[S_DEF_AUTO].val))
						continue;
					break;
				default:
					break;
				}
			} else {
				/*
				 * If there is no old value, only 'no' (unset)
				 * is allowed as new value.
				 */
				switch (sym->type) {
				case S_BOOLEAN:
				case S_TRISTATE:
					if (sym_get_tristate_value(sym) == no)
						continue;
					break;
				default:
					break;
				}
			}
		} else if (!(sym->flags & SYMBOL_DEF_AUTO))
			/* There is neither an old nor a new value. */
			continue;
		/* else
		 *	There is an old value, but no new value ('no' (unset)
		 *	isn't saved in auto.conf, so the old value is always
		 *	different from 'no').
		 */

		res = conf_touch_dep(sym->name);
		if (res)
			return res;
	}

	return 0;
}

static int __conf_write_autoconf(const char *filename,
				 void (*print_symbol)(FILE *, struct symbol *),
				 const struct comment_style *comment_style)
{
	char tmp[PATH_MAX];
	FILE *file;
	struct symbol *sym;
	int ret;

	if (make_parent_dir(filename))
		return -1;

	ret = snprintf(tmp, sizeof(tmp), "%s.tmp", filename);
	if (ret >= sizeof(tmp)) /* check truncation */
		return -1;

	file = fopen(tmp, "w");
	if (!file) {
		perror("fopen");
		return -1;
	}

	conf_write_heading(file, comment_style);

	for_all_symbols(sym)
		if ((sym->flags & SYMBOL_WRITE) && sym->name)
			print_symbol(file, sym);

	fflush(file);
	/* check possible errors in conf_write_heading() and print_symbol() */
	ret = ferror(file);
	fclose(file);
	if (ret)
		return -1;

	if (rename(tmp, filename)) {
		perror("rename");
		return -1;
	}

	return 0;
}

int conf_write_autoconf(int overwrite)
{
	struct symbol *sym;
	const char *autoconf_name = conf_get_autoconfig_name();
	int ret;

	if (!overwrite && is_present(autoconf_name))
		return 0;

	ret = conf_write_autoconf_cmd(autoconf_name);
	if (ret)
		return -1;

	for_all_symbols(sym)
		sym_calc_value(sym);

	if (conf_touch_deps())
		return 1;

	ret = __conf_write_autoconf(conf_get_autoheader_name(),
				    print_symbol_for_c,
				    &comment_style_c);
	if (ret)
		return ret;

	ret = __conf_write_autoconf(conf_get_rustccfg_name(),
				    print_symbol_for_rustccfg,
				    NULL);
	if (ret)
		return ret;

	/*
	 * Create include/config/auto.conf. This must be the last step because
	 * Kbuild has a dependency on auto.conf and this marks the successful
	 * completion of the previous steps.
	 */
	ret = __conf_write_autoconf(conf_get_autoconfig_name(),
				    print_symbol_for_autoconf,
				    &comment_style_pound);
	if (ret)
		return ret;

	return 0;
}

static bool conf_changed;
static void (*conf_changed_callback)(bool);

void conf_set_changed(bool val)
{
	if (conf_changed_callback && conf_changed != val)
		conf_changed_callback(val);

	conf_changed = val;
}

bool conf_get_changed(void)
{
	return conf_changed;
}

void conf_set_changed_callback(void (*fn)(bool))
{
	conf_changed_callback = fn;
}

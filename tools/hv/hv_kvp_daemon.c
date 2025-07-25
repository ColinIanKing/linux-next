/*
 * An implementation of key value pair (KVP) functionality for Linux.
 *
 *
 * Copyright (C) 2010, Novell, Inc.
 * Author : K. Y. Srinivasan <ksrinivasan@novell.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE, GOOD TITLE or
 * NON INFRINGEMENT.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */


#include <sys/poll.h>
#include <sys/utsname.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <arpa/inet.h>
#include <linux/hyperv.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <syslog.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <net/if.h>
#include <limits.h>
#include <getopt.h>

/*
 * KVP protocol: The user mode component first registers with the
 * kernel component. Subsequently, the kernel component requests, data
 * for the specified keys. In response to this message the user mode component
 * fills in the value corresponding to the specified key. We overload the
 * sequence field in the cn_msg header to define our KVP message types.
 *
 * We use this infrastructure for also supporting queries from user mode
 * application for state that may be maintained in the KVP kernel component.
 *
 */


enum key_index {
	FullyQualifiedDomainName = 0,
	IntegrationServicesVersion, /*This key is serviced in the kernel*/
	NetworkAddressIPv4,
	NetworkAddressIPv6,
	OSBuildNumber,
	OSName,
	OSMajorVersion,
	OSMinorVersion,
	OSVersion,
	ProcessorArchitecture
};


enum {
	IPADDR = 0,
	NETMASK,
	GATEWAY,
	DNS
};

enum {
	IPV4 = 1,
	IPV6,
	IP_TYPE_MAX
};

static int in_hand_shake;
static int debug;

static char *os_name = "";
static char *os_major = "";
static char *os_minor = "";
static char *processor_arch;
static char *os_build;
static char *os_version;
static char *lic_version = "Unknown version";
static char full_domain_name[HV_KVP_EXCHANGE_MAX_VALUE_SIZE];
static struct utsname uts_buf;

/*
 * The location of the interface configuration file.
 */

#define KVP_CONFIG_LOC	"/var/lib/hyperv"

#ifndef KVP_SCRIPTS_PATH
#define KVP_SCRIPTS_PATH "/usr/libexec/hypervkvpd/"
#endif

#define KVP_NET_DIR "/sys/class/net/"

#define MAX_FILE_NAME 100
#define ENTRIES_PER_BLOCK 50
/*
 * Change this entry if the number of addresses increases in future
 */
#define MAX_IP_ENTRIES 64
#define OUTSTR_BUF_SIZE ((INET6_ADDRSTRLEN + 1) * MAX_IP_ENTRIES)

struct kvp_record {
	char key[HV_KVP_EXCHANGE_MAX_KEY_SIZE];
	char value[HV_KVP_EXCHANGE_MAX_VALUE_SIZE];
};

struct kvp_file_state {
	int fd;
	int num_blocks;
	struct kvp_record *records;
	int num_records;
	char fname[MAX_FILE_NAME];
};

static struct kvp_file_state kvp_file_info[KVP_POOL_COUNT];

static void kvp_acquire_lock(int pool)
{
	struct flock fl = {F_WRLCK, SEEK_SET, 0, 0, 0};
	fl.l_pid = getpid();

	if (fcntl(kvp_file_info[pool].fd, F_SETLKW, &fl) == -1) {
		syslog(LOG_ERR, "Failed to acquire the lock pool: %d; error: %d %s", pool,
				errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
}

static void kvp_release_lock(int pool)
{
	struct flock fl = {F_UNLCK, SEEK_SET, 0, 0, 0};
	fl.l_pid = getpid();

	if (fcntl(kvp_file_info[pool].fd, F_SETLK, &fl) == -1) {
		syslog(LOG_ERR, "Failed to release the lock pool: %d; error: %d %s", pool,
				errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
}

static void kvp_update_file(int pool)
{
	FILE *filep;

	/*
	 * We are going to write our in-memory registry out to
	 * disk; acquire the lock first.
	 */
	kvp_acquire_lock(pool);

	filep = fopen(kvp_file_info[pool].fname, "we");
	if (!filep) {
		syslog(LOG_ERR, "Failed to open file, pool: %d; error: %d %s", pool,
				errno, strerror(errno));
		kvp_release_lock(pool);
		exit(EXIT_FAILURE);
	}

	fwrite(kvp_file_info[pool].records, sizeof(struct kvp_record),
				kvp_file_info[pool].num_records, filep);

	if (ferror(filep) || fclose(filep)) {
		kvp_release_lock(pool);
		syslog(LOG_ERR, "Failed to write file, pool: %d", pool);
		exit(EXIT_FAILURE);
	}

	kvp_release_lock(pool);
}

static void kvp_dump_initial_pools(int pool)
{
	int i;

	syslog(LOG_DEBUG, "===Start dumping the contents of pool %d ===\n",
	       pool);

	for (i = 0; i < kvp_file_info[pool].num_records; i++)
		syslog(LOG_DEBUG, "pool: %d, %d/%d key=%s val=%s\n",
		       pool, i + 1, kvp_file_info[pool].num_records,
		       kvp_file_info[pool].records[i].key,
		       kvp_file_info[pool].records[i].value);
}

static void kvp_update_mem_state(int pool)
{
	FILE *filep;
	size_t records_read = 0;
	struct kvp_record *record = kvp_file_info[pool].records;
	struct kvp_record *readp;
	int num_blocks = kvp_file_info[pool].num_blocks;
	int alloc_unit = sizeof(struct kvp_record) * ENTRIES_PER_BLOCK;

	kvp_acquire_lock(pool);

	filep = fopen(kvp_file_info[pool].fname, "re");
	if (!filep) {
		syslog(LOG_ERR, "Failed to open file, pool: %d; error: %d %s", pool,
				errno, strerror(errno));
		kvp_release_lock(pool);
		exit(EXIT_FAILURE);
	}
	for (;;) {
		readp = &record[records_read];
		records_read += fread(readp, sizeof(struct kvp_record),
				ENTRIES_PER_BLOCK * num_blocks - records_read,
				filep);

		if (ferror(filep)) {
			syslog(LOG_ERR,
				"Failed to read file, pool: %d; error: %d %s",
				 pool, errno, strerror(errno));
			kvp_release_lock(pool);
			exit(EXIT_FAILURE);
		}

		if (!feof(filep)) {
			/*
			 * We have more data to read.
			 */
			num_blocks++;
			record = realloc(record, alloc_unit * num_blocks);

			if (record == NULL) {
				syslog(LOG_ERR, "malloc failed");
				kvp_release_lock(pool);
				exit(EXIT_FAILURE);
			}
			continue;
		}
		break;
	}

	kvp_file_info[pool].num_blocks = num_blocks;
	kvp_file_info[pool].records = record;
	kvp_file_info[pool].num_records = records_read;

	fclose(filep);
	kvp_release_lock(pool);
}

static int kvp_file_init(void)
{
	int  fd;
	char *fname;
	int i;
	int alloc_unit = sizeof(struct kvp_record) * ENTRIES_PER_BLOCK;

	if (access(KVP_CONFIG_LOC, F_OK)) {
		if (mkdir(KVP_CONFIG_LOC, 0755 /* rwxr-xr-x */)) {
			syslog(LOG_ERR, "Failed to create '%s'; error: %d %s", KVP_CONFIG_LOC,
					errno, strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	for (i = 0; i < KVP_POOL_COUNT; i++) {
		fname = kvp_file_info[i].fname;
		sprintf(fname, "%s/.kvp_pool_%d", KVP_CONFIG_LOC, i);
		fd = open(fname, O_RDWR | O_CREAT | O_CLOEXEC, 0644 /* rw-r--r-- */);

		if (fd == -1)
			return 1;

		kvp_file_info[i].fd = fd;
		kvp_file_info[i].num_blocks = 1;
		kvp_file_info[i].records = malloc(alloc_unit);
		if (kvp_file_info[i].records == NULL)
			return 1;
		kvp_file_info[i].num_records = 0;
		kvp_update_mem_state(i);
		if (debug)
			kvp_dump_initial_pools(i);
	}

	return 0;
}

static int kvp_key_delete(int pool, const __u8 *key, int key_size)
{
	int i;
	int j, k;
	int num_records;
	struct kvp_record *record;

	/*
	 * First update the in-memory state.
	 */
	kvp_update_mem_state(pool);

	num_records = kvp_file_info[pool].num_records;
	record = kvp_file_info[pool].records;

	for (i = 0; i < num_records; i++) {
		if (memcmp(key, record[i].key, key_size))
			continue;
		/*
		 * Found a match; just move the remaining
		 * entries up.
		 */
		if (debug)
			syslog(LOG_DEBUG, "%s: deleting the KVP: pool=%d key=%s val=%s",
			       __func__, pool, record[i].key, record[i].value);
		if (i == (num_records - 1)) {
			kvp_file_info[pool].num_records--;
			kvp_update_file(pool);
			return 0;
		}

		j = i;
		k = j + 1;
		for (; k < num_records; k++) {
			strcpy(record[j].key, record[k].key);
			strcpy(record[j].value, record[k].value);
			j++;
		}

		kvp_file_info[pool].num_records--;
		kvp_update_file(pool);
		return 0;
	}

	if (debug)
		syslog(LOG_DEBUG, "%s: could not delete KVP: pool=%d key=%s. Record not found",
		       __func__, pool, key);

	return 1;
}

static int kvp_key_add_or_modify(int pool, const __u8 *key, int key_size,
				 const __u8 *value, int value_size)
{
	struct kvp_record *record;
	int num_records;
	int num_blocks;
	int i;

	if ((key_size > HV_KVP_EXCHANGE_MAX_KEY_SIZE) ||
		(value_size > HV_KVP_EXCHANGE_MAX_VALUE_SIZE)) {
		syslog(LOG_ERR, "%s: Too long key or value: pool=%d key=%s, val=%s",
		       __func__, pool, key, value);
		return 1;
	}

	if (debug)
		syslog(LOG_DEBUG, "%s: got a KVP: pool=%d key=%s val=%s",
		       __func__, pool, key, value);

	/*
	 * First update the in-memory state.
	 */
	kvp_update_mem_state(pool);

	num_records = kvp_file_info[pool].num_records;
	record = kvp_file_info[pool].records;
	num_blocks = kvp_file_info[pool].num_blocks;

	for (i = 0; i < num_records; i++) {
		if (memcmp(key, record[i].key, key_size))
			continue;
		/*
		 * Found a match; just update the value -
		 * this is the modify case.
		 */
		memcpy(record[i].value, value, value_size);
		kvp_update_file(pool);
		if (debug)
			syslog(LOG_DEBUG, "%s: updated: pool=%d key=%s val=%s",
			       __func__, pool, key, value);
		return 0;
	}

	/*
	 * Need to add a new entry;
	 */
	if (num_records == (ENTRIES_PER_BLOCK * num_blocks)) {
		/* Need to allocate a larger array for reg entries. */
		record = realloc(record, sizeof(struct kvp_record) *
			 ENTRIES_PER_BLOCK * (num_blocks + 1));

		if (!record) {
			syslog(LOG_ERR, "%s: Memory alloc failure", __func__);
			return 1;
		}
		kvp_file_info[pool].num_blocks++;

	}
	memcpy(record[i].value, value, value_size);
	memcpy(record[i].key, key, key_size);
	kvp_file_info[pool].records = record;
	kvp_file_info[pool].num_records++;

	if (debug)
		syslog(LOG_DEBUG, "%s: added: pool=%d key=%s val=%s",
		       __func__, pool, key, value);

	kvp_update_file(pool);
	return 0;
}

static int kvp_get_value(int pool, const __u8 *key, int key_size, __u8 *value,
			int value_size)
{
	int i;
	int num_records;
	struct kvp_record *record;

	if ((key_size > HV_KVP_EXCHANGE_MAX_KEY_SIZE) ||
		(value_size > HV_KVP_EXCHANGE_MAX_VALUE_SIZE))
		return 1;

	/*
	 * First update the in-memory state.
	 */
	kvp_update_mem_state(pool);

	num_records = kvp_file_info[pool].num_records;
	record = kvp_file_info[pool].records;

	for (i = 0; i < num_records; i++) {
		if (memcmp(key, record[i].key, key_size))
			continue;
		/*
		 * Found a match; just copy the value out.
		 */
		memcpy(value, record[i].value, value_size);
		return 0;
	}

	return 1;
}

static int kvp_pool_enumerate(int pool, int index, __u8 *key, int key_size,
				__u8 *value, int value_size)
{
	struct kvp_record *record;

	/*
	 * First update our in-memory database.
	 */
	kvp_update_mem_state(pool);
	record = kvp_file_info[pool].records;

	if (index >= kvp_file_info[pool].num_records) {
		return 1;
	}

	memcpy(key, record[index].key, key_size);
	memcpy(value, record[index].value, value_size);
	return 0;
}


void kvp_get_os_info(void)
{
	FILE	*file;
	char	*p, buf[512];

	uname(&uts_buf);
	os_version = uts_buf.release;
	os_build = strdup(uts_buf.release);

	os_name = uts_buf.sysname;
	processor_arch = uts_buf.machine;

	/*
	 * The current windows host (win7) expects the build
	 * string to be of the form: x.y.z
	 * Strip additional information we may have.
	 */
	p = strchr(os_version, '-');
	if (p)
		*p = '\0';

	/*
	 * Parse the /etc/os-release file if present:
	 * https://www.freedesktop.org/software/systemd/man/os-release.html
	 */
	file = fopen("/etc/os-release", "r");
	if (file != NULL) {
		while (fgets(buf, sizeof(buf), file)) {
			char *value, *q;

			/* Ignore comments */
			if (buf[0] == '#')
				continue;

			/* Split into name=value */
			p = strchr(buf, '=');
			if (!p)
				continue;
			*p++ = 0;

			/* Remove quotes and newline; un-escape */
			value = p;
			q = p;
			while (*p) {
				if (*p == '\\') {
					++p;
					if (!*p)
						break;
					*q++ = *p++;
				} else if (*p == '\'' || *p == '"' ||
					   *p == '\n') {
					++p;
				} else {
					*q++ = *p++;
				}
			}
			*q = 0;

			if (!strcmp(buf, "NAME")) {
				p = strdup(value);
				if (!p)
					break;
				os_name = p;
			} else if (!strcmp(buf, "VERSION_ID")) {
				p = strdup(value);
				if (!p)
					break;
				os_major = p;
			}
		}
		fclose(file);
		return;
	}

	/* Fallback for older RH/SUSE releases */
	file = fopen("/etc/SuSE-release", "r");
	if (file != NULL)
		goto kvp_osinfo_found;
	file  = fopen("/etc/redhat-release", "r");
	if (file != NULL)
		goto kvp_osinfo_found;

	/*
	 * We don't have information about the os.
	 */
	return;

kvp_osinfo_found:
	/* up to three lines */
	p = fgets(buf, sizeof(buf), file);
	if (p) {
		p = strchr(buf, '\n');
		if (p)
			*p = '\0';
		p = strdup(buf);
		if (!p)
			goto done;
		os_name = p;

		/* second line */
		p = fgets(buf, sizeof(buf), file);
		if (p) {
			p = strchr(buf, '\n');
			if (p)
				*p = '\0';
			p = strdup(buf);
			if (!p)
				goto done;
			os_major = p;

			/* third line */
			p = fgets(buf, sizeof(buf), file);
			if (p)  {
				p = strchr(buf, '\n');
				if (p)
					*p = '\0';
				p = strdup(buf);
				if (p)
					os_minor = p;
			}
		}
	}

done:
	fclose(file);
	return;
}



/*
 * Retrieve an interface name corresponding to the specified guid.
 * If there is a match, the function returns a pointer
 * to the interface name and if not, a NULL is returned.
 * If a match is found, the caller is responsible for
 * freeing the memory.
 */

static char *kvp_get_if_name(char *guid)
{
	DIR *dir;
	struct dirent *entry;
	FILE    *file;
	char    *p, *x;
	char    *if_name = NULL;
	char    buf[256];
	char dev_id[PATH_MAX];

	dir = opendir(KVP_NET_DIR);
	if (dir == NULL)
		return NULL;

	while ((entry = readdir(dir)) != NULL) {
		/*
		 * Set the state for the next pass.
		 */
		snprintf(dev_id, sizeof(dev_id), "%s%s/device/device_id",
			 KVP_NET_DIR, entry->d_name);

		file = fopen(dev_id, "r");
		if (file == NULL)
			continue;

		p = fgets(buf, sizeof(buf), file);
		if (p) {
			x = strchr(p, '\n');
			if (x)
				*x = '\0';

			if (!strcmp(p, guid)) {
				/*
				 * Found the guid match; return the interface
				 * name. The caller will free the memory.
				 */
				if_name = strdup(entry->d_name);
				fclose(file);
				break;
			}
		}
		fclose(file);
	}

	closedir(dir);
	return if_name;
}

/*
 * Retrieve the MAC address given the interface name.
 */

static char *kvp_if_name_to_mac(char *if_name)
{
	FILE    *file;
	char    *p, *x;
	char    buf[256];
	char addr_file[PATH_MAX];
	unsigned int i;
	char *mac_addr = NULL;

	snprintf(addr_file, sizeof(addr_file), "%s%s%s", KVP_NET_DIR,
		 if_name, "/address");

	file = fopen(addr_file, "r");
	if (file == NULL)
		return NULL;

	p = fgets(buf, sizeof(buf), file);
	if (p) {
		x = strchr(p, '\n');
		if (x)
			*x = '\0';
		for (i = 0; i < strlen(p); i++)
			p[i] = toupper(p[i]);
		mac_addr = strdup(p);
	}

	fclose(file);
	return mac_addr;
}

static void kvp_process_ipconfig_file(char *cmd,
					char *config_buf, unsigned int len,
					int element_size, int offset)
{
	char buf[256];
	char *p;
	char *x;
	FILE *file;

	/*
	 * First execute the command.
	 */
	file = popen(cmd, "r");
	if (file == NULL)
		return;

	if (offset == 0)
		memset(config_buf, 0, len);
	while ((p = fgets(buf, sizeof(buf), file)) != NULL) {
		if (len < strlen(config_buf) + element_size + 1)
			break;

		x = strchr(p, '\n');
		if (x)
			*x = '\0';

		strcat(config_buf, p);
		strcat(config_buf, ";");
	}
	pclose(file);
}

static bool kvp_verify_ip_address(const void *address_string)
{
	char verify_buf[sizeof(struct in6_addr)];

	if (inet_pton(AF_INET, address_string, verify_buf) == 1)
		return true;
	if (inet_pton(AF_INET6, address_string, verify_buf) == 1)
		return true;
	return false;
}

static void kvp_extract_routes(const char *line, void **output, size_t *remaining)
{
	static const char needle[] = "via ";
	const char *match, *haystack = line;

	while ((match = strstr(haystack, needle))) {
		const char *address, *next_char;

		/* Address starts after needle. */
		address = match + strlen(needle);

		/* The char following address is a space or end of line. */
		next_char = strpbrk(address, " \t\\");
		if (!next_char)
			next_char = address + strlen(address) + 1;

		/* Enough room for address and semicolon. */
		if (*remaining >= (next_char - address) + 1) {
			memcpy(*output, address, next_char - address);
			/* Terminate string for verification. */
			memcpy(*output + (next_char - address), "", 1);
			if (kvp_verify_ip_address(*output)) {
				/* Advance output buffer. */
				*output += next_char - address;
				*remaining -= next_char - address;

				/* Each address needs a trailing semicolon. */
				memcpy(*output, ";", 1);
				*output += 1;
				*remaining -= 1;
			}
		}
		haystack = next_char;
	}
}

static void kvp_get_gateway(void *buffer, size_t buffer_len)
{
	static const char needle[] = "default ";
	FILE *f;
	void *output = buffer;
	char *line = NULL;
	size_t alloc_size = 0, remaining = buffer_len - 1;
	ssize_t num_chars;

	/* Show route information in a single line, for each address family */
	f = popen("ip --oneline -4 route show;ip --oneline -6 route show", "r");
	if (!f) {
		/* Convert buffer into C-String. */
		memcpy(output, "", 1);
		return;
	}
	while ((num_chars = getline(&line, &alloc_size, f)) > 0) {
		/* Skip short lines. */
		if (num_chars <= strlen(needle))
			continue;
		/* Skip lines without default route. */
		if (memcmp(line, needle, strlen(needle)))
			continue;
		/* Remove trailing newline to simplify further parsing. */
		if (line[num_chars - 1] == '\n')
			line[num_chars - 1] = '\0';
		/* Search routes after match. */
		kvp_extract_routes(line + strlen(needle), &output, &remaining);
	}
	/* Convert buffer into C-String. */
	memcpy(output, "", 1);
	free(line);
	pclose(f);
}

static void kvp_get_ipconfig_info(char *if_name,
				 struct hv_kvp_ipaddr_value *buffer)
{
	char cmd[512];
	char dhcp_info[128];
	char *p;
	FILE *file;

	kvp_get_gateway(buffer->gate_way, sizeof(buffer->gate_way));

	/*
	 * Gather the DNS state.
	 * Since there is no standard way to get this information
	 * across various distributions of interest; we just invoke
	 * an external script that needs to be ported across distros
	 * of interest.
	 *
	 * Following is the expected format of the information from the script:
	 *
	 * ipaddr1 (nameserver1)
	 * ipaddr2 (nameserver2)
	 * .
	 * .
	 */

	sprintf(cmd, "exec %s %s", KVP_SCRIPTS_PATH "hv_get_dns_info", if_name);

	/*
	 * Execute the command to gather DNS info.
	 */
	kvp_process_ipconfig_file(cmd, (char *)buffer->dns_addr,
				(MAX_IP_ADDR_SIZE * 2), INET_ADDRSTRLEN, 0);

	/*
	 * Gather the DHCP state.
	 * We will gather this state by invoking an external script.
	 * The parameter to the script is the interface name.
	 * Here is the expected output:
	 *
	 * Enabled: DHCP enabled.
	 */

	sprintf(cmd, "exec %s %s", KVP_SCRIPTS_PATH "hv_get_dhcp_info", if_name);

	file = popen(cmd, "r");
	if (file == NULL)
		return;

	p = fgets(dhcp_info, sizeof(dhcp_info), file);
	if (p == NULL) {
		pclose(file);
		return;
	}

	if (!strncmp(p, "Enabled", 7))
		buffer->dhcp_enabled = 1;
	else
		buffer->dhcp_enabled = 0;

	pclose(file);
}


static unsigned int hweight32(unsigned int *w)
{
	unsigned int res = *w - ((*w >> 1) & 0x55555555);
	res = (res & 0x33333333) + ((res >> 2) & 0x33333333);
	res = (res + (res >> 4)) & 0x0F0F0F0F;
	res = res + (res >> 8);
	return (res + (res >> 16)) & 0x000000FF;
}

static int kvp_process_ip_address(void *addrp,
				int family, char *buffer,
				int length,  int *offset)
{
	struct sockaddr_in *addr;
	struct sockaddr_in6 *addr6;
	int addr_length;
	char tmp[50];
	const char *str;

	if (family == AF_INET) {
		addr = addrp;
		str = inet_ntop(family, &addr->sin_addr, tmp, 50);
		addr_length = INET_ADDRSTRLEN;
	} else {
		addr6 = addrp;
		str = inet_ntop(family, &addr6->sin6_addr.s6_addr, tmp, 50);
		addr_length = INET6_ADDRSTRLEN;
	}

	if ((length - *offset) < addr_length + 2)
		return HV_E_FAIL;
	if (str == NULL) {
		strcpy(buffer, "inet_ntop failed\n");
		return HV_E_FAIL;
	}
	if (*offset == 0)
		strcpy(buffer, tmp);
	else {
		strcat(buffer, ";");
		strcat(buffer, tmp);
	}

	*offset += strlen(str) + 1;

	return 0;
}

static int
kvp_get_ip_info(int family, char *if_name, int op,
		 void  *out_buffer, unsigned int length)
{
	struct ifaddrs *ifap;
	struct ifaddrs *curp;
	int offset = 0;
	int sn_offset = 0;
	int error = 0;
	char *buffer;
	struct hv_kvp_ipaddr_value *ip_buffer = NULL;
	char cidr_mask[5]; /* /xyz */
	int weight;
	int i;
	unsigned int *w;
	char *sn_str;
	struct sockaddr_in6 *addr6;

	if (op == KVP_OP_ENUMERATE) {
		buffer = out_buffer;
	} else {
		ip_buffer = out_buffer;
		buffer = (char *)ip_buffer->ip_addr;
		ip_buffer->addr_family = 0;
	}
	/*
	 * On entry into this function, the buffer is capable of holding the
	 * maximum key value.
	 */

	if (getifaddrs(&ifap)) {
		strcpy(buffer, "getifaddrs failed\n");
		return HV_E_FAIL;
	}

	curp = ifap;
	while (curp != NULL) {
		if (curp->ifa_addr == NULL) {
			curp = curp->ifa_next;
			continue;
		}

		if ((if_name != NULL) &&
			(strncmp(curp->ifa_name, if_name, strlen(if_name)))) {
			/*
			 * We want info about a specific interface;
			 * just continue.
			 */
			curp = curp->ifa_next;
			continue;
		}

		/*
		 * We only support two address families: AF_INET and AF_INET6.
		 * If a family value of 0 is specified, we collect both
		 * supported address families; if not we gather info on
		 * the specified address family.
		 */
		if ((((family != 0) &&
			 (curp->ifa_addr->sa_family != family))) ||
			 (curp->ifa_flags & IFF_LOOPBACK)) {
			curp = curp->ifa_next;
			continue;
		}
		if ((curp->ifa_addr->sa_family != AF_INET) &&
			(curp->ifa_addr->sa_family != AF_INET6)) {
			curp = curp->ifa_next;
			continue;
		}

		if (op == KVP_OP_GET_IP_INFO) {
			/*
			 * Gather info other than the IP address.
			 * IP address info will be gathered later.
			 */
			if (curp->ifa_addr->sa_family == AF_INET) {
				ip_buffer->addr_family |= ADDR_FAMILY_IPV4;
				/*
				 * Get subnet info.
				 */
				error = kvp_process_ip_address(
							     curp->ifa_netmask,
							     AF_INET,
							     (char *)
							     ip_buffer->sub_net,
							     length,
							     &sn_offset);
				if (error)
					goto gather_ipaddr;
			} else {
				ip_buffer->addr_family |= ADDR_FAMILY_IPV6;

				/*
				 * Get subnet info in CIDR format.
				 */
				weight = 0;
				sn_str = (char *)ip_buffer->sub_net;
				addr6 = (struct sockaddr_in6 *)
					curp->ifa_netmask;
				w = addr6->sin6_addr.s6_addr32;

				for (i = 0; i < 4; i++)
					weight += hweight32(&w[i]);

				sprintf(cidr_mask, "/%d", weight);
				if (length < sn_offset + strlen(cidr_mask) + 1)
					goto gather_ipaddr;

				if (sn_offset == 0)
					strcpy(sn_str, cidr_mask);
				else {
					strcat((char *)ip_buffer->sub_net, ";");
					strcat(sn_str, cidr_mask);
				}
				sn_offset += strlen(sn_str) + 1;
			}

			/*
			 * Collect other ip related configuration info.
			 */

			kvp_get_ipconfig_info(if_name, ip_buffer);
		}

gather_ipaddr:
		error = kvp_process_ip_address(curp->ifa_addr,
						curp->ifa_addr->sa_family,
						buffer,
						length, &offset);
		if (error)
			goto getaddr_done;

		curp = curp->ifa_next;
	}

getaddr_done:
	freeifaddrs(ifap);
	return error;
}

/*
 * Retrieve the IP given the MAC address.
 */
static int kvp_mac_to_ip(struct hv_kvp_ipaddr_value *kvp_ip_val)
{
	char *mac = (char *)kvp_ip_val->adapter_id;
	DIR *dir;
	struct dirent *entry;
	FILE    *file;
	char    *p, *x;
	char    *if_name = NULL;
	char    buf[256];
	char dev_id[PATH_MAX];
	unsigned int i;
	int error = HV_E_FAIL;

	dir = opendir(KVP_NET_DIR);
	if (dir == NULL)
		return HV_E_FAIL;

	while ((entry = readdir(dir)) != NULL) {
		/*
		 * Set the state for the next pass.
		 */
		snprintf(dev_id, sizeof(dev_id), "%s%s/address", KVP_NET_DIR,
			 entry->d_name);

		file = fopen(dev_id, "r");
		if (file == NULL)
			continue;

		p = fgets(buf, sizeof(buf), file);
		fclose(file);
		if (!p)
			continue;

		x = strchr(p, '\n');
		if (x)
			*x = '\0';

		for (i = 0; i < strlen(p); i++)
			p[i] = toupper(p[i]);

		if (strcmp(p, mac))
			continue;

		/*
		 * Found the MAC match.
		 * A NIC (e.g. VF) matching the MAC, but without IP, is skipped.
		 */
		if_name = entry->d_name;
		if (!if_name)
			continue;

		error = kvp_get_ip_info(0, if_name, KVP_OP_GET_IP_INFO,
					kvp_ip_val, MAX_IP_ADDR_SIZE * 2);

		if (!error && strlen((char *)kvp_ip_val->ip_addr))
			break;
	}

	closedir(dir);
	return error;
}

static int expand_ipv6(char *addr, int type)
{
	int ret;
	struct in6_addr v6_addr;

	ret = inet_pton(AF_INET6, addr, &v6_addr);

	if (ret != 1) {
		if (type == NETMASK)
			return 1;
		return 0;
	}

	sprintf(addr, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
		"%02x%02x:%02x%02x:%02x%02x",
		(int)v6_addr.s6_addr[0], (int)v6_addr.s6_addr[1],
		(int)v6_addr.s6_addr[2], (int)v6_addr.s6_addr[3],
		(int)v6_addr.s6_addr[4], (int)v6_addr.s6_addr[5],
		(int)v6_addr.s6_addr[6], (int)v6_addr.s6_addr[7],
		(int)v6_addr.s6_addr[8], (int)v6_addr.s6_addr[9],
		(int)v6_addr.s6_addr[10], (int)v6_addr.s6_addr[11],
		(int)v6_addr.s6_addr[12], (int)v6_addr.s6_addr[13],
		(int)v6_addr.s6_addr[14], (int)v6_addr.s6_addr[15]);

	return 1;

}

static int is_ipv4(char *addr)
{
	int ret;
	struct in_addr ipv4_addr;

	ret = inet_pton(AF_INET, addr, &ipv4_addr);

	if (ret == 1)
		return 1;
	return 0;
}

static int parse_ip_val_buffer(char *in_buf, int *offset,
				char *out_buf, int out_len)
{
	char *x;
	char *start;

	/*
	 * in_buf has sequence of characters that are separated by
	 * the character ';'. The last sequence does not have the
	 * terminating ";" character.
	 */
	start = in_buf + *offset;

	x = strchr(start, ';');
	if (x)
		*x = 0;
	else
		x = start + strlen(start);

	if (strlen(start) != 0) {
		int i = 0;
		/*
		 * Get rid of leading spaces.
		 */
		while (start[i] == ' ')
			i++;

		if ((x - start) <= out_len) {
			strcpy(out_buf, (start + i));
			*offset += (x - start) + 1;
			return 1;
		}
	}
	return 0;
}

static int kvp_write_file(FILE *f, char *s1, char *s2, char *s3)
{
	int ret;

	ret = fprintf(f, "%s%s%s%s\n", s1, s2, "=", s3);

	if (ret < 0)
		return HV_E_FAIL;

	return 0;
}


static int process_ip_string(FILE *f, char *ip_string, int type)
{
	int error = 0;
	char addr[INET6_ADDRSTRLEN];
	int i = 0;
	int j = 0;
	char str[256];
	char sub_str[13];
	int offset = 0;

	memset(addr, 0, sizeof(addr));

	while (parse_ip_val_buffer(ip_string, &offset, addr,
					(MAX_IP_ADDR_SIZE * 2))) {

		sub_str[0] = 0;
		if (is_ipv4(addr)) {
			switch (type) {
			case IPADDR:
				snprintf(str, sizeof(str), "%s", "IPADDR");
				break;
			case NETMASK:
				snprintf(str, sizeof(str), "%s", "NETMASK");
				break;
			case GATEWAY:
				snprintf(str, sizeof(str), "%s", "GATEWAY");
				break;
			case DNS:
				snprintf(str, sizeof(str), "%s", "DNS");
				break;
			}

			if (type == DNS) {
				snprintf(sub_str, sizeof(sub_str), "%d", ++i);
			} else if (type == GATEWAY && i == 0) {
				++i;
			} else {
				snprintf(sub_str, sizeof(sub_str), "%d", i++);
			}


		} else if (expand_ipv6(addr, type)) {
			switch (type) {
			case IPADDR:
				snprintf(str, sizeof(str), "%s", "IPV6ADDR");
				break;
			case NETMASK:
				snprintf(str, sizeof(str), "%s", "IPV6NETMASK");
				break;
			case GATEWAY:
				snprintf(str, sizeof(str), "%s",
					"IPV6_DEFAULTGW");
				break;
			case DNS:
				snprintf(str, sizeof(str), "%s",  "DNS");
				break;
			}

			if (type == DNS) {
				snprintf(sub_str, sizeof(sub_str), "%d", ++i);
			} else if (j == 0) {
				++j;
			} else {
				snprintf(sub_str, sizeof(sub_str), "_%d", j++);
			}
		} else {
			return  HV_INVALIDARG;
		}

		error = kvp_write_file(f, str, sub_str, addr);
		if (error)
			return error;
		memset(addr, 0, sizeof(addr));
	}

	return 0;
}

int ip_version_check(const char *input_addr)
{
	struct in6_addr addr;

	if (inet_pton(AF_INET, input_addr, &addr))
		return IPV4;
	else if (inet_pton(AF_INET6, input_addr, &addr))
		return IPV6;

	return -EINVAL;
}

/*
 * Only IPv4 subnet strings needs to be converted to plen
 * For IPv6 the subnet is already privided in plen format
 */
static int kvp_subnet_to_plen(char *subnet_addr_str)
{
	int plen = 0;
	struct in_addr subnet_addr4;

	/*
	 * Convert subnet address to binary representation
	 */
	if (inet_pton(AF_INET, subnet_addr_str, &subnet_addr4) == 1) {
		uint32_t subnet_mask = ntohl(subnet_addr4.s_addr);

		while (subnet_mask & 0x80000000) {
			plen++;
			subnet_mask <<= 1;
		}
	} else {
		return -1;
	}

	return plen;
}

static int process_dns_gateway_nm(FILE *f, char *ip_string, int type,
				  int ip_sec)
{
	char addr[INET6_ADDRSTRLEN], *output_str;
	int ip_offset = 0, error = 0, ip_ver;
	char *param_name;

	if (type == DNS)
		param_name = "dns";
	else if (type == GATEWAY)
		param_name = "gateway";
	else
		return -EINVAL;

	output_str = (char *)calloc(OUTSTR_BUF_SIZE, sizeof(char));
	if (!output_str)
		return -ENOMEM;

	while (1) {
		memset(addr, 0, sizeof(addr));

		if (!parse_ip_val_buffer(ip_string, &ip_offset, addr,
					 (MAX_IP_ADDR_SIZE * 2)))
			break;

		ip_ver = ip_version_check(addr);
		if (ip_ver < 0)
			continue;

		if ((ip_ver == IPV4 && ip_sec == IPV4) ||
		    (ip_ver == IPV6 && ip_sec == IPV6)) {
			/*
			 * do a bound check to avoid out-of bound writes
			 */
			if ((OUTSTR_BUF_SIZE - strlen(output_str)) >
			    (strlen(addr) + 1)) {
				strncat(output_str, addr,
					OUTSTR_BUF_SIZE -
					strlen(output_str) - 1);
				strncat(output_str, ",",
					OUTSTR_BUF_SIZE -
					strlen(output_str) - 1);
			}
		} else {
			continue;
		}
	}

	if (strlen(output_str)) {
		/*
		 * This is to get rid of that extra comma character
		 * in the end of the string
		 */
		output_str[strlen(output_str) - 1] = '\0';
		error = fprintf(f, "%s=%s\n", param_name, output_str);
	}

	free(output_str);
	return error;
}

static int process_ip_string_nm(FILE *f, char *ip_string, char *subnet,
				int ip_sec)
{
	char addr[INET6_ADDRSTRLEN];
	char subnet_addr[INET6_ADDRSTRLEN];
	int error = 0, i = 0;
	int ip_offset = 0, subnet_offset = 0;
	int plen, ip_ver;

	memset(addr, 0, sizeof(addr));
	memset(subnet_addr, 0, sizeof(subnet_addr));

	while (parse_ip_val_buffer(ip_string, &ip_offset, addr,
				   (MAX_IP_ADDR_SIZE * 2)) &&
				   parse_ip_val_buffer(subnet,
						       &subnet_offset,
						       subnet_addr,
						       (MAX_IP_ADDR_SIZE *
							2))) {
		ip_ver = ip_version_check(addr);
		if (ip_ver < 0)
			continue;

		if (ip_ver == IPV4 && ip_sec == IPV4)
			plen = kvp_subnet_to_plen((char *)subnet_addr);
		else if (ip_ver == IPV6 && ip_sec == IPV6)
			plen = atoi(subnet_addr);
		else
			continue;

		if (plen < 0)
			return plen;

		error = fprintf(f, "address%d=%s/%d\n", ++i, (char *)addr,
				plen);
		if (error < 0)
			return error;

		memset(addr, 0, sizeof(addr));
		memset(subnet_addr, 0, sizeof(subnet_addr));
	}

	return error;
}

static int kvp_set_ip_info(char *if_name, struct hv_kvp_ipaddr_value *new_val)
{
	int error = 0, ip_ver;
	char if_filename[PATH_MAX];
	char nm_filename[PATH_MAX];
	FILE *ifcfg_file, *nmfile;
	char cmd[PATH_MAX];
	char *mac_addr;
	int str_len;

	/*
	 * Set the configuration for the specified interface with
	 * the information provided. Since there is no standard
	 * way to configure an interface, we will have an external
	 * script that does the job of configuring the interface and
	 * flushing the configuration.
	 *
	 * The parameters passed to this external script are:
	 * 1. A configuration file that has the specified configuration.
	 *
	 * We will embed the name of the interface in the configuration
	 * file: ifcfg-ethx (where ethx is the interface name).
	 *
	 * The information provided here may be more than what is needed
	 * in a given distro to configure the interface and so are free
	 * ignore information that may not be relevant.
	 *
	 * Here is the ifcfg format of the ip configuration file:
	 *
	 * HWADDR=macaddr
	 * DEVICE=interface name
	 * BOOTPROTO=<protocol> (where <protocol> is "dhcp" if DHCP is configured
	 *                       or "none" if no boot-time protocol should be used)
	 *
	 * IPADDR0=ipaddr1
	 * IPADDR1=ipaddr2
	 * IPADDRx=ipaddry (where y = x + 1)
	 *
	 * NETMASK0=netmask1
	 * NETMASKx=netmasky (where y = x + 1)
	 *
	 * GATEWAY=ipaddr1
	 * GATEWAYx=ipaddry (where y = x + 1)
	 *
	 * DNSx=ipaddrx (where first DNS address is tagged as DNS1 etc)
	 *
	 * IPV6 addresses will be tagged as IPV6ADDR, IPV6 gateway will be
	 * tagged as IPV6_DEFAULTGW and IPV6 NETMASK will be tagged as
	 * IPV6NETMASK.
	 *
	 * Here is the keyfile format of the ip configuration file:
	 *
	 * [ethernet]
	 * mac-address=macaddr
	 * [connection]
	 * interface-name=interface name
	 *
	 * [ipv4]
	 * method=<protocol> (where <protocol> is "auto" if DHCP is configured
	 *                       or "manual" if no boot-time protocol should be used)
	 *
	 * address1=ipaddr1/plen
	 * address2=ipaddr2/plen
	 *
	 * gateway=gateway1;gateway2
	 *
	 * dns=dns1;dns2
	 *
	 * [ipv6]
	 * address1=ipaddr1/plen
	 * address2=ipaddr2/plen
	 *
	 * gateway=gateway1;gateway2
	 *
	 * dns=dns1;dns2
	 *
	 * The host can specify multiple ipv4 and ipv6 addresses to be
	 * configured for the interface. Furthermore, the configuration
	 * needs to be persistent. A subsequent GET call on the interface
	 * is expected to return the configuration that is set via the SET
	 * call.
	 */

	/*
	 * We are populating both ifcfg and nmconnection files
	 */
	snprintf(if_filename, sizeof(if_filename), "%s%s%s", KVP_CONFIG_LOC,
		 "/ifcfg-", if_name);

	ifcfg_file = fopen(if_filename, "w");

	if (!ifcfg_file) {
		syslog(LOG_ERR, "Failed to open config file; error: %d %s",
		       errno, strerror(errno));
		return HV_E_FAIL;
	}

	snprintf(nm_filename, sizeof(nm_filename), "%s%s%s%s", KVP_CONFIG_LOC,
		 "/", if_name, ".nmconnection");

	nmfile = fopen(nm_filename, "w");

	if (!nmfile) {
		syslog(LOG_ERR, "Failed to open config file; error: %d %s",
		       errno, strerror(errno));
		fclose(ifcfg_file);
		return HV_E_FAIL;
	}

	/*
	 * First write out the MAC address.
	 */

	mac_addr = kvp_if_name_to_mac(if_name);
	if (mac_addr == NULL) {
		error = HV_E_FAIL;
		goto setval_error;
	}

	error = kvp_write_file(ifcfg_file, "HWADDR", "", mac_addr);
	if (error < 0)
		goto setmac_error;

	error = kvp_write_file(ifcfg_file, "DEVICE", "", if_name);
	if (error < 0)
		goto setmac_error;

	error = fprintf(nmfile, "\n[connection]\n");
	if (error < 0)
		goto setmac_error;

	error = kvp_write_file(nmfile, "interface-name", "", if_name);
	if (error)
		goto setmac_error;

	error = fprintf(nmfile, "\n[ethernet]\n");
	if (error < 0)
		goto setmac_error;

	error = kvp_write_file(nmfile, "mac-address", "", mac_addr);
	if (error)
		goto setmac_error;

	free(mac_addr);

	/*
	 * The dhcp_enabled flag is only for IPv4. In the case the host only
	 * injects an IPv6 address, the flag is true, but we still need to
	 * proceed to parse and pass the IPv6 information to the
	 * disto-specific script hv_set_ifconfig.
	 */

	/*
	 * First populate the ifcfg file format
	 */
	if (new_val->dhcp_enabled) {
		error = kvp_write_file(ifcfg_file, "BOOTPROTO", "", "dhcp");
		if (error)
			goto setval_error;
	} else {
		error = kvp_write_file(ifcfg_file, "BOOTPROTO", "", "none");
		if (error)
			goto setval_error;
	}

	error = process_ip_string(ifcfg_file, (char *)new_val->ip_addr,
				  IPADDR);
	if (error)
		goto setval_error;

	error = process_ip_string(ifcfg_file, (char *)new_val->sub_net,
				  NETMASK);
	if (error)
		goto setval_error;

	error = process_ip_string(ifcfg_file, (char *)new_val->gate_way,
				  GATEWAY);
	if (error)
		goto setval_error;

	error = process_ip_string(ifcfg_file, (char *)new_val->dns_addr, DNS);
	if (error)
		goto setval_error;

	/*
	 * Now we populate the keyfile format
	 *
	 * The keyfile format expects the IPv6 and IPv4 configuration in
	 * different sections. Therefore we iterate through the list twice,
	 * once to populate the IPv4 section and the next time for IPv6
	 */
	ip_ver = IPV4;
	do {
		if (ip_ver == IPV4) {
			error = fprintf(nmfile, "\n[ipv4]\n");
			if (error < 0)
				goto setval_error;
		} else {
			error = fprintf(nmfile, "\n[ipv6]\n");
			if (error < 0)
				goto setval_error;
		}

		/*
		 * Write the configuration for ipaddress, netmask, gateway and
		 * name services
		 */
		error = process_ip_string_nm(nmfile, (char *)new_val->ip_addr,
					     (char *)new_val->sub_net,
					     ip_ver);
		if (error < 0)
			goto setval_error;

		/*
		 * As dhcp_enabled is only valid for ipv4, we do not set dhcp
		 * methods for ipv6 based on dhcp_enabled flag.
		 *
		 * For ipv4, set method to manual only when dhcp_enabled is
		 * false and specific ipv4 addresses are configured. If neither
		 * dhcp_enabled is true and no ipv4 addresses are configured,
		 * set method to 'disabled'.
		 *
		 * For ipv6, set method to manual when we configure ipv6
		 * addresses. Otherwise set method to 'auto' so that SLAAC from
		 * RA may be used.
		 */
		if (ip_ver == IPV4) {
			if (new_val->dhcp_enabled) {
				error = kvp_write_file(nmfile, "method", "",
						       "auto");
				if (error < 0)
					goto setval_error;
			} else if (error) {
				error = kvp_write_file(nmfile, "method", "",
						       "manual");
				if (error < 0)
					goto setval_error;
			} else {
				error = kvp_write_file(nmfile, "method", "",
						       "disabled");
				if (error < 0)
					goto setval_error;
			}
		} else if (ip_ver == IPV6) {
			if (error) {
				error = kvp_write_file(nmfile, "method", "",
						       "manual");
				if (error < 0)
					goto setval_error;
			} else {
				error = kvp_write_file(nmfile, "method", "",
						       "auto");
				if (error < 0)
					goto setval_error;
			}
		}

		error = process_dns_gateway_nm(nmfile,
					       (char *)new_val->gate_way,
					       GATEWAY, ip_ver);
		if (error < 0)
			goto setval_error;

		error = process_dns_gateway_nm(nmfile,
					       (char *)new_val->dns_addr, DNS,
					       ip_ver);
		if (error < 0)
			goto setval_error;

		ip_ver++;
	} while (ip_ver < IP_TYPE_MAX);

	fclose(nmfile);
	fclose(ifcfg_file);

	/*
	 * Now that we have populated the configuration file,
	 * invoke the external script to do its magic.
	 */

	str_len = snprintf(cmd, sizeof(cmd), "exec %s %s %s",
			   KVP_SCRIPTS_PATH "hv_set_ifconfig",
			   if_filename, nm_filename);
	/*
	 * This is a little overcautious, but it's necessary to suppress some
	 * false warnings from gcc 8.0.1.
	 */
	if (str_len <= 0 || (unsigned int)str_len >= sizeof(cmd)) {
		syslog(LOG_ERR, "Cmd '%s' (len=%d) may be too long",
		       cmd, str_len);
		return HV_E_FAIL;
	}

	if (system(cmd)) {
		syslog(LOG_ERR, "Failed to execute cmd '%s'; error: %d %s",
		       cmd, errno, strerror(errno));
		return HV_E_FAIL;
	}
	return 0;
setmac_error:
	free(mac_addr);
setval_error:
	syslog(LOG_ERR, "Failed to write config file");
	fclose(ifcfg_file);
	fclose(nmfile);
	return error;
}


static void
kvp_get_domain_name(char *buffer, int length)
{
	struct addrinfo	hints, *info ;
	int error = 0;

	gethostname(buffer, length);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET; /*Get only ipv4 addrinfo. */
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_CANONNAME;

	error = getaddrinfo(buffer, NULL, &hints, &info);
	if (error != 0) {
		snprintf(buffer, length, "getaddrinfo failed: 0x%x %s",
			error, gai_strerror(error));
		return;
	}
	snprintf(buffer, length, "%s", info->ai_canonname);
	freeaddrinfo(info);
}

void print_usage(char *argv[])
{
	fprintf(stderr, "Usage: %s [options]\n"
		"Options are:\n"
		"  -n, --no-daemon        stay in foreground, don't daemonize\n"
		"  -d, --debug            Enable debug logs(syslog debug by default)\n"
		"  -h, --help             print this help\n", argv[0]);
}

int main(int argc, char *argv[])
{
	int kvp_fd = -1, len;
	int error;
	struct pollfd pfd;
	char    *p;
	struct hv_kvp_msg hv_msg[1];
	char	*key_value;
	char	*key_name;
	int	op;
	int	pool;
	char	*if_name;
	struct hv_kvp_ipaddr_value *kvp_ip_val;
	int daemonize = 1, long_index = 0, opt;

	static struct option long_options[] = {
		{"help",	no_argument,	   0,  'h' },
		{"no-daemon",	no_argument,	   0,  'n' },
		{"debug",	no_argument,	   0,  'd' },
		{0,		0,		   0,  0   }
	};

	while ((opt = getopt_long(argc, argv, "hnd", long_options,
				  &long_index)) != -1) {
		switch (opt) {
		case 'n':
			daemonize = 0;
			break;
		case 'h':
			print_usage(argv);
			exit(0);
		case 'd':
			debug = 1;
			break;
		default:
			print_usage(argv);
			exit(EXIT_FAILURE);
		}
	}

	if (daemonize && daemon(1, 0))
		return 1;

	openlog("KVP", 0, LOG_USER);
	syslog(LOG_INFO, "KVP starting; pid is:%d", getpid());

	/*
	 * Retrieve OS release information.
	 */
	kvp_get_os_info();
	/*
	 * Cache Fully Qualified Domain Name because getaddrinfo takes an
	 * unpredictable amount of time to finish.
	 */
	kvp_get_domain_name(full_domain_name, sizeof(full_domain_name));

	if (debug)
		syslog(LOG_INFO, "Logging debug info in syslog(debug)");

	if (kvp_file_init()) {
		syslog(LOG_ERR, "Failed to initialize the pools");
		exit(EXIT_FAILURE);
	}

reopen_kvp_fd:
	if (kvp_fd != -1)
		close(kvp_fd);
	in_hand_shake = 1;
	kvp_fd = open("/dev/vmbus/hv_kvp", O_RDWR | O_CLOEXEC);

	if (kvp_fd < 0) {
		syslog(LOG_ERR, "open /dev/vmbus/hv_kvp failed; error: %d %s",
		       errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	/*
	 * Register ourselves with the kernel.
	 */
	hv_msg->kvp_hdr.operation = KVP_OP_REGISTER1;
	len = write(kvp_fd, hv_msg, sizeof(struct hv_kvp_msg));
	if (len != sizeof(struct hv_kvp_msg)) {
		syslog(LOG_ERR, "registration to kernel failed; error: %d %s",
		       errno, strerror(errno));
		close(kvp_fd);
		exit(EXIT_FAILURE);
	}

	pfd.fd = kvp_fd;

	while (1) {
		pfd.events = POLLIN;
		pfd.revents = 0;

		if (poll(&pfd, 1, -1) < 0) {
			syslog(LOG_ERR, "poll failed; error: %d %s", errno, strerror(errno));
			if (errno == EINVAL) {
				close(kvp_fd);
				exit(EXIT_FAILURE);
			}
			else
				continue;
		}

		len = read(kvp_fd, hv_msg, sizeof(struct hv_kvp_msg));

		if (len != sizeof(struct hv_kvp_msg)) {
			syslog(LOG_ERR, "read failed; error:%d %s",
			       errno, strerror(errno));
			goto reopen_kvp_fd;
		}

		/*
		 * We will use the KVP header information to pass back
		 * the error from this daemon. So, first copy the state
		 * and set the error code to success.
		 */
		op = hv_msg->kvp_hdr.operation;
		pool = hv_msg->kvp_hdr.pool;
		hv_msg->error = HV_S_OK;

		if ((in_hand_shake) && (op == KVP_OP_REGISTER1)) {
			/*
			 * Driver is registering with us; stash away the version
			 * information.
			 */
			in_hand_shake = 0;
			p = (char *)hv_msg->body.kvp_register.version;
			lic_version = malloc(strlen(p) + 1);
			if (lic_version) {
				strcpy(lic_version, p);
				syslog(LOG_INFO, "KVP LIC Version: %s",
				       lic_version);
			} else {
				syslog(LOG_ERR, "malloc failed");
			}
			continue;
		}

		switch (op) {
		case KVP_OP_GET_IP_INFO:
			kvp_ip_val = &hv_msg->body.kvp_ip_val;

			error = kvp_mac_to_ip(kvp_ip_val);

			if (error)
				hv_msg->error = error;

			break;

		case KVP_OP_SET_IP_INFO:
			kvp_ip_val = &hv_msg->body.kvp_ip_val;
			if_name = kvp_get_if_name(
					(char *)kvp_ip_val->adapter_id);
			if (if_name == NULL) {
				/*
				 * We could not map the guid to an
				 * interface name; return error.
				 */
				hv_msg->error = HV_GUID_NOTFOUND;
				break;
			}
			error = kvp_set_ip_info(if_name, kvp_ip_val);
			if (error)
				hv_msg->error = error;

			free(if_name);
			break;

		case KVP_OP_SET:
			if (kvp_key_add_or_modify(pool,
					hv_msg->body.kvp_set.data.key,
					hv_msg->body.kvp_set.data.key_size,
					hv_msg->body.kvp_set.data.value,
					hv_msg->body.kvp_set.data.value_size))
					hv_msg->error = HV_S_CONT;
			break;

		case KVP_OP_GET:
			if (kvp_get_value(pool,
					hv_msg->body.kvp_set.data.key,
					hv_msg->body.kvp_set.data.key_size,
					hv_msg->body.kvp_set.data.value,
					hv_msg->body.kvp_set.data.value_size))
					hv_msg->error = HV_S_CONT;
			break;

		case KVP_OP_DELETE:
			if (kvp_key_delete(pool,
					hv_msg->body.kvp_delete.key,
					hv_msg->body.kvp_delete.key_size))
					hv_msg->error = HV_S_CONT;
			break;

		default:
			break;
		}

		if (op != KVP_OP_ENUMERATE)
			goto kvp_done;

		/*
		 * If the pool is KVP_POOL_AUTO, dynamically generate
		 * both the key and the value; if not read from the
		 * appropriate pool.
		 */
		if (pool != KVP_POOL_AUTO) {
			if (kvp_pool_enumerate(pool,
					hv_msg->body.kvp_enum_data.index,
					hv_msg->body.kvp_enum_data.data.key,
					HV_KVP_EXCHANGE_MAX_KEY_SIZE,
					hv_msg->body.kvp_enum_data.data.value,
					HV_KVP_EXCHANGE_MAX_VALUE_SIZE))
					hv_msg->error = HV_S_CONT;
			goto kvp_done;
		}

		key_name = (char *)hv_msg->body.kvp_enum_data.data.key;
		key_value = (char *)hv_msg->body.kvp_enum_data.data.value;

		switch (hv_msg->body.kvp_enum_data.index) {
		case FullyQualifiedDomainName:
			strcpy(key_value, full_domain_name);
			strcpy(key_name, "FullyQualifiedDomainName");
			break;
		case IntegrationServicesVersion:
			strcpy(key_name, "IntegrationServicesVersion");
			strcpy(key_value, lic_version);
			break;
		case NetworkAddressIPv4:
			kvp_get_ip_info(AF_INET, NULL, KVP_OP_ENUMERATE,
				key_value, HV_KVP_EXCHANGE_MAX_VALUE_SIZE);
			strcpy(key_name, "NetworkAddressIPv4");
			break;
		case NetworkAddressIPv6:
			kvp_get_ip_info(AF_INET6, NULL, KVP_OP_ENUMERATE,
				key_value, HV_KVP_EXCHANGE_MAX_VALUE_SIZE);
			strcpy(key_name, "NetworkAddressIPv6");
			break;
		case OSBuildNumber:
			strcpy(key_value, os_build);
			strcpy(key_name, "OSBuildNumber");
			break;
		case OSName:
			strcpy(key_value, os_name);
			strcpy(key_name, "OSName");
			break;
		case OSMajorVersion:
			strcpy(key_value, os_major);
			strcpy(key_name, "OSMajorVersion");
			break;
		case OSMinorVersion:
			strcpy(key_value, os_minor);
			strcpy(key_name, "OSMinorVersion");
			break;
		case OSVersion:
			strcpy(key_value, os_version);
			strcpy(key_name, "OSVersion");
			break;
		case ProcessorArchitecture:
			strcpy(key_value, processor_arch);
			strcpy(key_name, "ProcessorArchitecture");
			break;
		default:
			hv_msg->error = HV_S_CONT;
			break;
		}

		/*
		 * Send the value back to the kernel. Note: the write() may
		 * return an error due to hibernation; we can ignore the error
		 * by resetting the dev file, i.e. closing and re-opening it.
		 */
kvp_done:
		len = write(kvp_fd, hv_msg, sizeof(struct hv_kvp_msg));
		if (len != sizeof(struct hv_kvp_msg)) {
			syslog(LOG_ERR, "write failed; error: %d %s", errno,
			       strerror(errno));
			goto reopen_kvp_fd;
		}
	}

	close(kvp_fd);
	exit(0);
}

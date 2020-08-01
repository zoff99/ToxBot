/*
 *
 *
 * skupina robot
 *
 * Copyright (C) 2017 - 2020 by Zoff
 *
 */

/*  toxbot.c
 *
 *
 *  Copyright (C) 2014 toxbot All Rights Reserved.
 *
 *  This file is part of toxbot.
 *
 *  toxbot is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  toxbot is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with toxbot. If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <time.h>
#include <limits.h>
#include <signal.h>
#include <inttypes.h>
#include <fcntl.h>

#include <tox/tox.h>
#include <tox/toxav.h>

#include "misc.h"
#include "commands.h"
#include "toxbot.h"
#include "groupchats.h"

#define VERSION "0.99.7"
#define FRIEND_PURGE_INTERVAL (60) /* very often */
#define GROUP_PURGE_INTERVAL 1728000 /* 20 days */
#define DEFAULT_GROUP_PASSWORD "not-used-anymore-734hfdo!383wl?r3ewr$9ia3wR"
#define DEFAULT_GROUP_TITLE "[Toktok] PublicChat"
#define MAX_LOG_LINE_LENGTH 1000

bool FLAG_EXIT = false;    /* set on SIGINT */
const char *log_filename = "toxbot.log";
char *DATA_FILE = "toxbot_save.dat";
char *MASTERLIST_FILE = "masterkeys.txt";
char *DEFAULT_GROUP_PASSWORD_FILE = "default_group_pass.txt";
char *BOTNAME = "Skupina Robot [Toktok]";
FILE *logfile = NULL;
int global_change_title_back = 0;

struct Tox_Bot Tox_Bot;

static void init_toxbot_state(void)
{
    Tox_Bot.start_time = (uint64_t) time(NULL);
    Tox_Bot.default_groupnum = 0;
    Tox_Bot.chats_idx = 0;
    Tox_Bot.num_online_friends = 0;

    /* 1 year default; anything lower should be explicitly set until we have a config file */
    Tox_Bot.inactive_limit = 864000; // 10 days     // OLD // 31536000; // about 365 days
}

static void catch_SIGINT(int sig)
{
    FLAG_EXIT = true;
}

void dbg(int level, const char *fmt, ...)
{
	char *level_and_format = NULL;
	char *fmt_copy = NULL;

	if (fmt == NULL)
	{
		return;
	}

	if (strlen(fmt) < 1)
	{
		return;
	}

	if (!logfile)
	{
		return;
	}

	if ((level < 0) || (level > 9))
	{
		level = 0;
	}

	level_and_format = malloc(strlen(fmt) + 3 + 1);

	if (!level_and_format)
	{
		// fprintf(stderr, "free:000a\n");
		return;
	}

	fmt_copy = level_and_format + 2;
	strcpy(fmt_copy, fmt);
	level_and_format[1] = ':';
	if (level == 0)
	{
		level_and_format[0] = 'E';
	}
	else if (level == 1)
	{
		level_and_format[0] = 'W';
	}
	else if (level == 2)
	{
		level_and_format[0] = 'I';
	}
	else
	{
		level_and_format[0] = 'D';
	}

	level_and_format[(strlen(fmt) + 2)] = '\n';
	level_and_format[(strlen(fmt) + 3)] = '\0';

        time_t t3 = time(NULL);
        struct tm tm3 = *localtime(&t3);

	char *level_and_format_2 = malloc(strlen(level_and_format) + 5 + 3 + 3 + 1 + 3 + 3 + 3 + 1);
	level_and_format_2[0] = '\0';
	snprintf(level_and_format_2, (strlen(level_and_format) + 5 + 3 + 3 + 1 + 3 + 3 + 3 + 1), "%04d-%02d-%02d %02d:%02d:%02d:%s",
		 tm3.tm_year + 1900, tm3.tm_mon + 1, tm3.tm_mday,
                 tm3.tm_hour, tm3.tm_min, tm3.tm_sec, level_and_format);	
	
	if (level <= CURRENT_LOG_LEVEL)
	{
		va_list ap;
		va_start(ap, fmt);
		vfprintf(logfile, level_and_format_2, ap);
		va_end(ap);
	}

	// fprintf(stderr, "free:001\n");
	if (level_and_format)
	{
		// fprintf(stderr, "free:001.a\n");
		free(level_and_format);
	}
	
	if (level_and_format_2)
	{
		free(level_and_format_2);
	}
	// fprintf(stderr, "free:002\n");
}


void tox_log_cb__custom(Tox *tox, TOX_LOG_LEVEL level, const char *file, uint32_t line, const char *func, const char *message, void *user_data)
{
	dbg(9, "%d:%s:%d:%s:%s", (int)level, file, (int)line, func, message);
}

// --- autoinvite friend to default group ---
// --- autoinvite friend to default group ---
// --- autoinvite friend to default group ---
static void invite_friendnum_to_groupchat(Tox *tox, uint32_t friend_number)
{
    TOX_ERR_CONFERENCE_INVITE error;
    bool res = tox_conference_invite(tox, friend_number, 0, &error);

}

void autoinvite_friendnum_to_default_group(Tox *m, uint32_t friendnumber, int silent)
{
	// dbg(2, "friend invite to default group fnum=%d", (int)friendnumber);

	// const char *password = DEFAULT_GROUP_PASSWORD;
	// batch_invite(m, friendnumber, password, silent);
    invite_friendnum_to_groupchat(m, friendnumber);
}
// --- autoinvite friend to default group ---
// --- autoinvite friend to default group ---
// --- autoinvite friend to default group ---


static void exit_toxbot(Tox *m)
{
    size_t numchats = tox_conference_get_chatlist_size(m);

    save_data(m, DATA_FILE);
    tox_kill(m);

	if (logfile)
	{
		fclose(logfile);
		logfile = NULL;
	}

    exit(EXIT_SUCCESS);
}

/* Returns true if friendnumber's Tox ID is in the masterkeys list, false otherwise.
   Note that it only compares the public key portion of the IDs. */
bool friend_is_master(Tox *m, uint32_t friendnumber)
{
    if (!file_exists(MASTERLIST_FILE)) {
        FILE *fp = fopen(MASTERLIST_FILE, "w");

        if (fp == NULL) {
            dbg(1, "Warning: failed to create masterkeys file");
            return false;
        }

        fclose(fp);
        dbg(1, "Warning: creating new masterkeys file. Did you lose the old one?");
        return false;
    }

    FILE *fp = fopen(MASTERLIST_FILE, "r");

    if (fp == NULL) {
        dbg(1, "Warning: failed to read masterkeys file");
        return false;
    }

    char friend_key[TOX_PUBLIC_KEY_SIZE];
    if (tox_friend_get_public_key(m, friendnumber, (uint8_t *) friend_key, NULL) == 0) {
        fclose(fp);
        return false;
    }

    char id[256];

    while (fgets(id, sizeof(id), fp)) {
        int len = strlen(id);

        if (--len < TOX_PUBLIC_KEY_SIZE)
            continue;

        char *key_bin = hex_string_to_bin(id);

        if (memcmp(key_bin, friend_key, TOX_PUBLIC_KEY_SIZE) == 0) {
            free(key_bin);
            fclose(fp);
            return true;
        }

        free(key_bin);
    }

    fclose(fp);
    return false;
}

/* START CALLBACKS */
static void cb_self_connection_change(Tox *m, TOX_CONNECTION connection_status, void *userdata)
{
    switch (connection_status) {
        case TOX_CONNECTION_NONE:
            dbg(1, "Connection to Tox network has been lost");
            break;

        case TOX_CONNECTION_TCP:
            dbg(1, "Connection to Tox network is weak (using TCP)");
            break;

        case TOX_CONNECTION_UDP:
            dbg(1, "Connection to Tox network is strong (using UDP)");
            break;
    }
}

static void cb_friend_connection_change(Tox *m, uint32_t friendnumber, TOX_CONNECTION connection_status, void *userdata)
{
    /* Count the number of online friends.
     *
     * We have to do this the hard way because our convenient API function to get
     * the number of online friends has mysteriously vanished
     */

	// dbg(2, "friend connection change fnum=%d stats=%d", (int)friendnumber, (int)connection_status);

	int online_friends_previous = (int)Tox_Bot.num_online_friends;

    Tox_Bot.num_online_friends = 0;    
    size_t i, size = tox_self_get_friend_list_size(m);

    if (size == 0)
    {
        return;
    }


    uint32_t list[size];
    tox_self_get_friend_list(m, list);

    for (i = 0; i < size; ++i)
	{
        if (tox_friend_get_connection_status(m, list[i], NULL) != TOX_CONNECTION_NONE)
		{
            ++Tox_Bot.num_online_friends;
		}
    }

	// dbg(2, "friend connection change fnum=%d online friends prev=%d online friends now=%d", (int)friendnumber, (int)online_friends_previous, (int)Tox_Bot.num_online_friends);

    if (connection_status != TOX_CONNECTION_NONE)
    {
		if ((int)Tox_Bot.num_online_friends > online_friends_previous)
		{
			autoinvite_friendnum_to_default_group(m, friendnumber, 0);
		}
    }
}


static void cb_friend_request(Tox *m, const uint8_t *public_key, const uint8_t *data, size_t length,
                              void *userdata)
{
    TOX_ERR_FRIEND_ADD err;
    uint32_t new_friend_number = tox_friend_add_norequest(m, public_key, &err);

	dbg(2, "friend request fnum=%d", (int)new_friend_number);

    if (err != TOX_ERR_FRIEND_ADD_OK)
	{
        dbg(0, "tox_friend_add_norequest failed (error %d)", err);
	}
	else
	{
		// ** error when doing it here ** // autoinvite_friendnum_to_default_group(m, new_friend_number, 0);
	}
    
    save_data(m, DATA_FILE);
}

static void cb_friend_message(Tox *m, uint32_t friendnumber, TOX_MESSAGE_TYPE type, const uint8_t *string,
                              size_t length, void *userdata)
{
    if (type != TOX_MESSAGE_TYPE_NORMAL)
	{
        return;
	}

    const char *outmsg;
    char message[TOX_MAX_MESSAGE_LENGTH];
    length = copy_tox_str(message, sizeof(message), (const char *) string, length);
    message[length] = '\0';

	dbg(2, "friend message fnum=%d message=%s", (int)friendnumber, (char*)message);


    if (length && execute(m, friendnumber, message, length) == -1)
	{
        outmsg = "Invalid command. Type help for a list of commands";
        tox_friend_send_message(m, friendnumber, TOX_MESSAGE_TYPE_NORMAL, (uint8_t *) outmsg, strlen(outmsg), NULL);
    }
}

static void cb_group_connected(Tox *tox, uint32_t conference_number, void *user_data)
{
    // TODO: write me
    // dummy for now
}

static void cb_group_invite(Tox *m, uint32_t friendnumber, TOX_CONFERENCE_TYPE type,
                            const uint8_t *cookie, size_t length, void *userdata)
{
    if (!friend_is_master(m, friendnumber))
	{
        return;
	}

    char name[TOX_MAX_NAME_LENGTH];
    tox_friend_get_name(m, friendnumber, (uint8_t *) name, NULL);
    size_t len = tox_friend_get_name_size(m, friendnumber, NULL);
    name[len] = '\0';

    int groupnum = -1;

    if (type == TOX_CONFERENCE_TYPE_TEXT) {
        TOX_ERR_CONFERENCE_JOIN err;
        groupnum = tox_conference_join(m, friendnumber, cookie, length, &err);

        if (err != TOX_ERR_CONFERENCE_JOIN_OK) {
            goto on_error;
        }
    } else if (type == TOX_CONFERENCE_TYPE_AV) {
        //groupnum = toxav_join_av_groupchat(m, friendnumber, cookie, length, NULL, NULL);

        //if (groupnum == -1) {
            goto on_error;
        //}
    }

    save_data(m, DATA_FILE);

    if (group_add(groupnum, type, NULL) == -1)
	{
        dbg(0, "Invite from %s failed (group_add failed)", name);
        tox_conference_delete(m, groupnum, NULL);
		dbg(2, "group removed [2] gnum=%d", (int)groupnum);
        return;
    }

    dbg(2, "Accepted groupchat invite from %s [%d]", name, groupnum);
    return;

on_error:
    dbg(0, "Invite from %s failed (core failure)", name);
    save_data(m, DATA_FILE);

}

static void cb_group_titlechange(Tox *m, uint32_t groupnumber, uint32_t peernumber, const uint8_t *title,
                                 size_t length, void *userdata)
{
    global_change_title_back = 1;

    char message[TOX_MAX_MESSAGE_LENGTH];
    length = copy_tox_str(message, sizeof(message), (const char *) title, length);

    int idx = group_index(groupnumber);

    if (idx == -1)
    {
        return;
    }

    memcpy(Tox_Bot.g_chats[idx].title, message, length + 1);
    Tox_Bot.g_chats[idx].title_len = length;

    save_data(m, DATA_FILE);

    dbg(2, "somebody changed the group title");
}
/* END CALLBACKS */

int save_data(Tox *m, const char *path)
{
    if (path == NULL)
    {
        goto on_error;
    }

    FILE *fp = fopen(path, "wb");

    if (fp == NULL)
    {
        return -1;
    }

    size_t data_len = tox_get_savedata_size(m);
    char *data = malloc(data_len);

    if (data == NULL)
    {
        goto on_error;
    }

    tox_get_savedata(m, (uint8_t *) data);

    if (fwrite(data, data_len, 1, fp) != 1) {
        free(data);
        fclose(fp);
        goto on_error;
    }

    free(data);
    fclose(fp);
    return 0;

on_error:
    dbg(0, "Warning: save_data failed");
    return -1;
}

static Tox *load_tox(struct Tox_Options *options, char *path)
{
    FILE *fp = fopen(path, "rb");
    Tox *m = NULL;

    if (fp == NULL)
    {
        TOX_ERR_NEW err;
        m = tox_new(options, &err);

        if (err != TOX_ERR_NEW_OK)
        {
            dbg(0, "tox_new failed with error %d", err);
            return NULL;
        }

        save_data(m, path);
        return m;
    }

    off_t data_len = file_size(path);

    if (data_len == 0) {
        fclose(fp);
        return NULL;
    }

    char *data = calloc(1, data_len);

    dbg(9, "load toxsave:001");

    if (fread(data, data_len, 1, fp) != 1) {
        dbg(9, "load toxsave:ERR:001");
        fclose(fp);
        return NULL;
    }

    dbg(9, "load toxsave:002");

    TOX_ERR_NEW err;
    options->savedata_type = TOX_SAVEDATA_TYPE_TOX_SAVE;
    options->savedata_data = (uint8_t *) data;
    options->savedata_length = data_len;

    options->log_callback = tox_log_cb__custom;

    m = tox_new(options, &err);

    if (err != TOX_ERR_NEW_OK) {
        dbg(0, "tox_new failed with error %d", err);
        return NULL;
    }

    fclose(fp);

    free(data);

    return m;
}

static Tox *init_tox(void)
{
    struct Tox_Options tox_opts;
    memset(&tox_opts, 0, sizeof(struct Tox_Options));
    tox_options_default(&tox_opts);

    Tox *m = load_tox(&tox_opts, DATA_FILE);

    if (!m)
        return NULL;

    tox_callback_self_connection_status(m, cb_self_connection_change);
    tox_callback_friend_connection_status(m, cb_friend_connection_change);
    tox_callback_friend_request(m, cb_friend_request);
    tox_callback_friend_message(m, cb_friend_message);
    tox_callback_conference_invite(m, cb_group_invite);
    tox_callback_conference_title(m, cb_group_titlechange);
    tox_callback_conference_connected(m, cb_group_connected);


    size_t s_len = tox_self_get_status_message_size(m);

    if (s_len == 0)
    {
        const char *statusmsg = "Send me the the command 'help' for more info";
        tox_self_set_status_message(m, (uint8_t *) statusmsg, strlen(statusmsg), NULL);
    }

    size_t n_len = tox_self_get_name_size(m);

    if (n_len == 0)
    {
        tox_self_set_name(m, (uint8_t *) BOTNAME, strlen(BOTNAME), NULL);
    }

    return m;
}

/* TODO: hardcoding is bad stop being lazy */
static struct toxNodes {
    const char *ip;
    uint16_t    port;
    const char *key;
} nodes[] = {

{"85.172.30.117",33445,"8E7D0B859922EF569298B4D261A8CCB5FEA14FB91ED412A7603A585A25698832", },
{"85.143.221.42",33445,"DA4E4ED4B697F2E9B000EEFE3A34B554ACD3F45F5C96EAEA2516DD7FF9AF7B43", },
{"tox.verdict.gg",33445,"1C5293AEF2114717547B39DA8EA6F1E331E5E358B35F9B6B5F19317911C5F976", },
{"78.46.73.141",33445,"02807CF4F8BB8FB390CC3794BDF1E8449E9A8392C5D3F2200019DA9F1E812E46", },
{"tox.initramfs.io",33445,"3F0A45A268367C1BEA652F258C85F4A66DA76BCAA667A49E770BCC4917AB6A25", },
{"46.229.52.198",33445,"813C8F4187833EF0655B10F7752141A352248462A567529A38B6BBF73E979307", },
{"144.217.167.73",33445,"7E5668E0EE09E19F320AD47902419331FFEE147BB3606769CFBE921A2A2FD34C", },
{"tox.abilinski.com",33445,"10C00EB250C3233E343E2AEBA07115A5C28920E9C8D29492F6D00B29049EDC7E", },
{"tox.novg.net",33445,"D527E5847F8330D628DAB1814F0A422F6DC9D0A300E6C357634EE2DA88C35463", },
{"95.31.18.227",33445,"257744DBF57BE3E117FE05D145B5F806089428D4DCE4E3D0D50616AA16D9417E", },
{"198.199.98.108",33445,"BEF0CFB37AF874BD17B9A8F9FE64C75521DB95A37D33C5BDB00E9CF58659C04F", },
{"tox.kurnevsky.net",33445,"82EF82BA33445A1F91A7DB27189ECFC0C013E06E3DA71F588ED692BED625EC23", },
{"87.118.126.207",33445,"0D303B1778CA102035DA01334E7B1855A45C3EFBC9A83B9D916FFDEBC6DD3B2E", },
{"81.169.136.229",33445,"E0DB78116AC6500398DDBA2AEEF3220BB116384CAB714C5D1FCD61EA2B69D75E", },
{"205.185.115.131",53,"3091C6BEB2A993F1C6300C16549FABA67098FF3D62C6D253828B531470B53D68", },
{"tox2.abilinski.com",33445,"7A6098B590BDC73F9723FC59F82B3F9085A64D1B213AAF8E610FD351930D052D", },
{"floki.blog",33445,"6C6AF2236F478F8305969CCFC7A7B67C6383558FF87716D38D55906E08E72667", },
{"51.158.146.76",33445,"E940D8FA9B07C1D13EA4ECF9F06B66F565F1CF61F094F60C67FDC8ADD3F4BA59", },
{"46.101.197.175",33445,"CD133B521159541FB1D326DE9850F5E56A6C724B5B8E5EB5CD8D950408E95707", },
{"tox1.mf-net.eu",33445,"B3E5FA80DC8EBD1149AD2AB35ED8B85BD546DEDE261CA593234C619249419506", },
{"tox2.mf-net.eu",33445,"70EA214FDE161E7432530605213F18F7427DC773E276B3E317A07531F548545F", },
{"46.146.229.184",33445,"94750E94013586CCD989233A621747E2646F08F31102339452CADCF6DC2A760A", },

//    { "178.62.250.138",     33445, "788236D34978D1D5BD822F0A5BEBD2C53C64CC31CD3149350EE27D4D9A2F9B6B" },
//    { "130.133.110.14",     33445, "461FA3776EF0FA655F1A05477DF1B3B614F7D6B124F7DB1DD4FE3C08B03B640F" },
//    { "128.199.199.197",    33445, "B05C8869DBB4EDDD308F43C1A974A20A725A36EACCA123862FDE9945BF9D3E09" },
//    { "146.185.136.123",    33445, "09993FAF174DFFDC515B398A2EFC5639C4E6D7B736FC864F89786B50EAF88C1A" },
//    { "193.124.186.205",    5228,  "9906D65F2A4751068A59D30505C5FC8AE1A95E0843AE9372EAFA3BAB6AC16C2C" },
//    { "185.25.116.107",     33445, "DA4E4ED4B697F2E9B000EEFE3A34B554ACD3F45F5C96EAEA2516DD7FF9AF7B43" },
//    { "5.189.176.217",      33445, "2B2137E094F743AC8BD44652C55F41DFACC502F125E99E4FE24D40537489E32F" },
//    { "46.101.197.175",     443,   "CD133B521159541FB1D326DE9850F5E56A6C724B5B8E5EB5CD8D950408E95707" },
    { NULL, 0, NULL },
};

static void bootstrap_DHT(Tox *m)
{
    int i;

    for (i = 0; nodes[i].ip; ++i) {
        char *key = hex_string_to_bin(nodes[i].key);

        TOX_ERR_BOOTSTRAP err;
        tox_bootstrap(m, nodes[i].ip, nodes[i].port, (uint8_t *) key, &err);
        free(key);

        if (err != TOX_ERR_BOOTSTRAP_OK)
            dbg(0, "Failed to bootstrap DHT via: %s %d (error %d)", nodes[i].ip, nodes[i].port, err);
    }
}

static void print_profile_info(Tox *m)
{
    dbg(2, "ToxBot version %s", VERSION);

    char address[TOX_ADDRESS_SIZE];
	char my_tox_id[TOX_ADDRESS_SIZE * 3];
    tox_self_get_address(m, (uint8_t *) address);
    int i;

	CLEAR(my_tox_id);

	int j = 0;
    for (i = 0; i < TOX_ADDRESS_SIZE; ++i)
    {
        char d[3];
        snprintf(d, sizeof(d), "%02X", address[i] & 0xff);
        // dbg(2, "%s", d);

		my_tox_id[j] = d[0];
		j++;
		my_tox_id[j] = d[1];
		j++;
    }

	dbg(2, "my ToxID:%s", my_tox_id);

    char name[TOX_MAX_NAME_LENGTH];
    size_t len = tox_self_get_name_size(m);
    tox_self_get_name(m, (uint8_t *) name);
    name[len] = '\0';

    size_t numfriends = tox_self_get_friend_list_size(m);
    dbg(2, "Name: %s", name);
    dbg(2, "Contacts: %d", (int) numfriends);
    
    TOX_ERR_CONFERENCE_PEER_QUERY error;
    uint32_t group_members = tox_conference_peer_count(m, 0, &error);

    dbg(2, "Inactive contacts purged after %"PRIu64" seconds offline", Tox_Bot.inactive_limit);
}

static void purge_inactive_friends(Tox *m)
{
    size_t numfriends = tox_self_get_friend_list_size(m);

    if (numfriends == 0)
    {
        return;
    }

    uint32_t *friend_list = calloc(1, numfriends * sizeof(uint32_t));
    tox_self_get_friend_list(m, friend_list);

    dbg(2, "numfriends=%d", numfriends);

    size_t i;
    for (i = 0; i < numfriends; ++i)
    {
        uint32_t friendnum = friend_list[i];

        if (!tox_friend_exists(m, friendnum))
        {
            continue;
        }

        TOX_ERR_FRIEND_GET_LAST_ONLINE err;
        uint64_t last_online = tox_friend_get_last_online(m, friendnum, &err);

        if (err != TOX_ERR_FRIEND_GET_LAST_ONLINE_OK)
        {
            continue;
        }

        // dbg(2, "deleting friend: time=%d last_online=%d limit=%d : fnum=%d", (int) time(NULL), (int)last_online, (int)Tox_Bot.inactive_limit, friendnum);

        if (((uint64_t) time(NULL)) - last_online > Tox_Bot.inactive_limit)
        {
            dbg(2, "deleting friend %d", friendnum);
            tox_friend_delete(m, friendnum, NULL);
        }
    }
}

int main(int argc, char **argv)
{
    signal(SIGINT, catch_SIGINT);
    umask(S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);

	logfile = fopen(log_filename, "wb");
	setvbuf(logfile, NULL, _IONBF, 0);

    dbg(2, "-- log test --");

    Tox *m = init_tox();

    if (m == NULL)
    {
        exit(EXIT_FAILURE);
    }

    init_toxbot_state();
    print_profile_info(m);
    bootstrap_DHT(m);

	// -- wait until bot is online --
	long long unsigned int cur_time1 = time(NULL);
	uint8_t off = 1;
	long long loop_counter = 0;
	while (1)
	{
        tox_iterate(m, NULL);
        usleep(tox_iteration_interval(m) * 1000);
        if (tox_self_get_connection_status(m) && off)
		{
            dbg(2, "Tox online, took %llu seconds", time(NULL) - cur_time1);
            off = 0;
			break;
        }
        c_sleep(20);
		loop_counter++;
		
		if (loop_counter > (50 * 20))
		{
			loop_counter = 0;
			// if not yet online, bootstrap every 20 seconds
			dbg(1, "Tox NOT online yet, bootstrapping again");
			bootstrap_DHT(m);
		}
    }
	// -- wait until bot is online --

	// -- wait 3 seconds before creating default group --
	c_sleep(3 * 1000);
	// create_default_group(m);

	uint64_t cur_time = (uint64_t) time(NULL);
    uint64_t last_friend_purge = cur_time;
    uint64_t last_group_purge = cur_time;

    TOX_ERR_CONFERENCE_SET_MAX_OFFLINE error;
    tox_conference_set_max_offline(m, 0, 100, &error);

    dbg(1, "set title ...");
    tox_conference_set_title(m, 0, (const uint8_t *)(DEFAULT_GROUP_TITLE), (size_t)(strlen(DEFAULT_GROUP_TITLE)), NULL);
    dbg(1, "set title ... DONE");

	int ease_off = 0;
	int max_ease_off = 20;
    while (!FLAG_EXIT)
	{

        uint64_t cur_time = (uint64_t) time(NULL);

        if (timed_out(last_friend_purge, cur_time, FRIEND_PURGE_INTERVAL))
        {
            // dbg(1, "purging friends ...");
            purge_inactive_friends(m);
            save_data(m, DATA_FILE);
            last_friend_purge = cur_time;
        }

        tox_iterate(m, NULL);
        usleep(120 * 1000);

        // check if we lost connection to the Tox network
        if (tox_self_get_connection_status(m) == TOX_CONNECTION_NONE)
        {
            if (ease_off == 0)
            {
                bootstrap_DHT(m);
                ease_off++;
            }
            else
            {
                ease_off++;
                if (ease_off > max_ease_off)
                {
                    ease_off = 0;
                }
            }
        }

        if (global_change_title_back == 1)
        {
            if (tox_conference_set_title(m, 0, (const uint8_t *)(DEFAULT_GROUP_TITLE), (size_t)(strlen(DEFAULT_GROUP_TITLE)), NULL))
            {
                global_change_title_back = 0;
                dbg(1, "changing title back again");
                save_data(m, DATA_FILE);
            }
        }
    }

    exit_toxbot(m);

	if (logfile)
	{
		fclose(logfile);
		logfile = NULL;
	}

    return 0;
}

#define _GNU_SOURCE

#include <assert.h>
// #include <ctype.h>
// #include <dlfcn.h>
#include <err.h>
#include <fcntl.h>
// #include <gmp.h>
// #include <openssl/evp.h>
#include <signal.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// #include <sys/ptrace.h>
#include <sys/personality.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "anti_debugger.h"
#include "tic.h"
#include "utils.h"

#define NAMELEN 32
#define KEYLEN 128

static sqlite3 *db = NULL;

static char *login;

static void *one = NULL;
static void *two = NULL;
static void *three = NULL;
static void *four = NULL;
static void *five = NULL;
static void *six = NULL;
static void *seven = NULL;

typedef struct user {
    char name[NAMELEN];
    char key[KEYLEN];
    int score;
} user_t;

static void init(int, char **);
static void user_register(int);
static void logi(int);
static void loggedin();
static int own_cmp(char *, char *);
static user_t *get_user_by_name(char *, int);
static void help();
static char *calc_addr(char *);
// void loop(int);
// void laap(int);
// void debug(int);
// void list_users();

static int own_cmp(char *s1, char *s2) {
    int n = strlen(s2);
    unsigned char c1 = '\0';
    unsigned char c2 = '\0';

    if (n >= 4) {
        size_t n4 = n >> 2;
        do {
            c1 = (unsigned char)*s1++;
            c2 = (unsigned char)*s2++;
            if (c1 == '\0' || c1 != c2)
                return c1 - c2;
            c1 = (unsigned char)*s1++;
            c2 = (unsigned char)*s2++;
            if (c1 == '\0' || c1 != c2)
                return c1 - c2;
            c1 = (unsigned char)*s1++;
            c2 = (unsigned char)*s2++;
            if (c1 == '\0' || c1 != c2)
                return c1 - c2;
            c1 = (unsigned char)*s1++;
            c2 = (unsigned char)*s2++;
            if (c1 == '\0' || c1 != c2)
                return c1 - c2;
        } while (--n4 > 0);
        n &= 3;
    }

    while (n > 0) {
        c1 = (unsigned char)*s1++;
        c2 = (unsigned char)*s2++;
        if (c1 == '\0' || c1 != c2)
            return c1 - c2;
        n--;
    }

    return c1 - c2;
}

#pragma GCC push_options
#pragma GCC optimize("O0")
static char *get_sql_password(void) {
    char ssql[] = "SELECT key FROM users WHERE name = ?";
    return strdup(ssql);
}
#pragma GCC pop_options

static void __attribute__((optimize("O1"))) show_password(int i) {
    const char *text;
    sqlite3_stmt *res;
    int status;
    char *tmp = get_sql_password();

    char *label_address = calc_addr(((char *)&&start_show_ps) - 0x400000);
    __asm__ volatile("push %0\n"
                     "ret\n"
                     :
                     : "g"(label_address));

start_show_ps:
    status = sqlite3_prepare_v2(db, tmp, -1, &res, NULL);
    free(tmp);
    status = sqlite3_bind_text(res, 1, login, -1, NULL);
    status = sqlite3_step(res);
    if (status == SQLITE_ROW) {
        text = (const char *)sqlite3_column_text(res, 0);
        if (text == NULL) {
            return;
        }
        printf("'%s' ", text);
        // is your password
        puts("\x42\x58\x0b\x52\x44\x5e\x59\x0b\x5b\x4a\x58\x58\x5c\x44"
             "\x59\x4f");
    }
    sqlite3_finalize(res);
}

#pragma GCC push_options
#pragma GCC optimize("O0")
static char *get_sql_update(void) {
    char ssql[] = "UPDATE users SET score = ? WHERE name = ?";
    return strdup(ssql);
}
#pragma GCC pop_options

static void update_user_by_name(char *username, int option) {
    user_t *user;
    sqlite3_stmt *res;
    int status;
    char str[10];

    if (username == NULL) {
        return;
    }

    user = get_user_by_name(username, option);
    if (user == NULL) {
        exit(EXIT_FAILURE);
    }
    user->score += 1;

    char *tmp = get_sql_update();
    status = sqlite3_prepare_v2(db, tmp, -1, &res, NULL);
    free(tmp);
    if (status != SQLITE_OK) {
        free(user);
        return;
    }
    sprintf(str, "%d", user->score);
    status = sqlite3_bind_text(res, 1, str, -1, NULL);
    status = sqlite3_bind_text(res, 2, user->name, -1, NULL);
    status = sqlite3_bind_int(res, 3, user->score);
    status = sqlite3_step(res);
    if (status == SQLITE_ROW) {
        free(user);
        return;
    }
    sqlite3_finalize(res);
    free(user);
}

#pragma GCC push_options
#pragma GCC optimize("O0")
static char *get_sql_select(int i) {
    if (i == 0) {
        char ssql[] = "SELECT name, key, score FROM users WHERE name = ?";
        return strdup(ssql);
    } else if (i == 1) {
        char ssql[] = "SELECT name, key FROM users WHERE name = ?";
        return strdup(ssql);
    }
    return NULL;
}
#pragma GCC pop_options

static user_t *get_user_by_name(char *username, int option) {
    user_t *user;
    sqlite3_stmt *res;
    int status;
    const char *text;

    user = NULL;
    char *tmp;
    if (option == 1) {
        tmp = get_sql_select(0);
    } else {
        tmp = get_sql_select(1);
    }
    status = sqlite3_prepare_v2(db, tmp, -1, &res, NULL);
    free(tmp);
    status = sqlite3_bind_text(res, 1, username, -1, NULL);
    status = sqlite3_step(res);
    /* if the user exists */
    if (status == SQLITE_ROW) {
        user = (user_t *)malloc(sizeof(user_t));
        if (user == NULL) {
            // report_err("fail to allocate memory for user");
            exit(EXIT_FAILURE);
        }
        text = (const char *)sqlite3_column_text(res, 0);
        if (text == NULL) {
            free(user);
            // report_err("select name fail");
            return NULL;
        }
        strncpy(user->name, text, NAMELEN - 1);
        /* crash if the record does not have a pubkey or profile */
        text = (const char *)sqlite3_column_text(res, 1);
        if (text == NULL) {
            free(user);
            // report_err("select key fail");
            return NULL;
        }
        strncpy(user->key, text, KEYLEN - 1);
        if (option == 1) {
            // char *score_str = (char *)sqlite3_column_text(res, 2);
            user->score = sqlite3_column_int64(res, 2);
        } else {
            user->score = -1;
        }
    }
    sqlite3_finalize(res);
    return user;
}

#pragma GCC push_options
#pragma GCC optimize("O0")
static char *get_sql_insert(void) {
    char ssql[] = "INSERT INTO users (name, key, score) VALUES (?, ?, ?);";
    return strdup(ssql);
}
#pragma GCC pop_options

static void user_register(int i) {
    if (i == 1) {
        user_t *new_user, *db_user;
        sqlite3_stmt *res;
        int status;

        new_user = (user_t *)malloc(sizeof(user_t));
        if (new_user == NULL) {
            // report_err("fail to allocate memory for user");
            exit(EXIT_FAILURE);
        }
        puts("\x4e\x45\x5f\x4e\x59\x0b\x5f\x43\x4e\x0b\x5e\x58\x4e\x59\x45\x4a\x46\x4e\x11");
        read_input(new_user->name, NAMELEN);
        //read_input("enter the username: ", new_user->name, NAMELEN);
        if (strlen(new_user->name) <= 0) {
            return;
        }
        if ((db_user = get_user_by_name(new_user->name, 0)) != NULL) {
            free(new_user);
            free(db_user);
            // puts("user exists");
            puts("\x5e\x58\x4e\x59\x0b\x4e\x53\x42\x58\x5f\x58");
            return;
        }
        char input_key[KEYLEN];
        puts("\x4e\x45\x5f\x4e\x59\x0b\x5f\x43\x4e\x0b\x40\x4e\x52\x11");
        read_input(input_key, KEYLEN);
        //read_input("enter the key: ", input_key, KEYLEN);
        if (strlen(input_key) <= 1) {
            free(new_user);
            free(db_user);
            // puts("too short");
            puts("\x5f\x44\x44\x0b\x58\x43\x44\x59\x5f");
            return;
        }

        strcpy(new_user->key, input_key);
        // printf("username: %s\nkey: %s\n", new_user->name, new_user->key);
        char *tmp = get_sql_insert();
        status = sqlite3_prepare_v2(db, tmp, -1, &res, NULL);
        free(tmp);
        assert(status == SQLITE_OK);
        status = sqlite3_bind_text(res, 1, new_user->name, -1, NULL);
        status = sqlite3_bind_text(res, 2, new_user->key, -1, NULL);
        status = sqlite3_bind_int(res, 3, 0);
        status = sqlite3_step(res);
        sqlite3_finalize(res);
        free(new_user);
        free(db_user);
        // printf("register successful!\n");
        puts("\x59\x4e\x4c\x42\x58\x5f\x4e\x59\x0b\x58\x5e\x48\x48\x4e\x58"
             "\x58\x4d"
             "\x5e\x47\x0a");

        return;
    } else {
        user_t *new_user, *db_user;
        sqlite3_stmt *res;
        int status;

        new_user = (user_t *)malloc(sizeof(user_t));
        if (new_user == NULL)
            exit(EXIT_FAILURE);
        puts("\x4e\x45\x5f\x4e\x59\x0b\x5f\x43\x4e\x0b\x5e\x58\x4e\x59\x45\x4a\x46\x4e\x11");
        read_input(new_user->name, NAMELEN);
        //read_input("enter the username: ", new_user->name, NAMELEN);
        if ((db_user = get_user_by_name(new_user->name, 1)) != NULL) {
            free(new_user);
            free(db_user);
            puts("user exists");
            return;
        }
        puts("\x4e\x45\x5f\x4e\x59\x0b\x5f\x43\x4e\x0b\x5b\x5e\x49\x47\x42\x48\x0b\x40\x4e\x52\x11");
        read_input(new_user->key, 18);
        //read_input("enter the public key: ", new_user->key, 18);
        if (own_cmp(new_user->name, db_user->key) == 0) {
            free(new_user);
            puts("invalid key");
            return;
        }
        puts("\x4e\x45\x5f\x4e\x59\x0b\x5f\x43\x4e\x0b\x5b\x59\x44\x4d\x42\x47\x4e\x11");
        read_input(new_user->key, 18);
        //read_input("enter the profile: ", new_user->key, 18);
        printf("username: %s\npublic key: %s\nprofile: %s\n", new_user->name,
               new_user->key, new_user->name);
        status = sqlite3_prepare_v2(
            db, "INSERT INTO users (name, pubkey, profile) VALUES (?, ?, ?);",
            -1, &res, NULL);
        assert(status == SQLITE_OK);
        status = sqlite3_bind_text(res, 1, new_user->name, -1, NULL);
        status = sqlite3_bind_text(res, 2, new_user->key, -1, NULL);
        status = sqlite3_bind_text(res, 3, new_user->name, -1, NULL);
        status = sqlite3_step(res);
        sqlite3_finalize(res);
        free(new_user);
        printf("register successful!\n");
        return;
    }
}

#pragma GCC push_options
#pragma GCC optimize("O0")
static char *get_sql_create(void) {
    char ssql[] = "CREATE TABLE IF NOT EXISTS users(uid INTEGER PRIMARY KEY,"
                  " name TEXT, key TEXT, score INTEGER);";
    return strdup(ssql);
}
#pragma GCC pop_options

static void init(int argc, char **argv) {
    const char *dbpath;
    int status;

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    dbpath = "dsa.sqlite3";
    if (argc > 1)
        dbpath = argv[1];
    status = sqlite3_open(dbpath, &db);
    assert(status == SQLITE_OK);

    if ((personality(0xffffffff) & ADDR_NO_RANDOMIZE) != 0) {
        char *dead = NULL;
        printf("%c\n", *dead);
    }

    status = sqlite3_busy_timeout(db, 10000);
    assert(status == SQLITE_OK);

    char *ssql = get_sql_create();
    status = sqlite3_exec(db, ssql, 0, 0, NULL);
    free(ssql);
    assert(status == SQLITE_OK);
}

static void logi(int i) {

    //printf("begining: %p, %ld\tend: %p, %ld\ndiff: %ld\n", (logi), (long)(logi),
    //       &&end, (long)&&end, ((long)&&end - (long)logi));

    if (i == 2) {
        char input_name[NAMELEN];
        puts("\x5e\x58\x4e\x59\x11\x0b");
        read_input(input_name, NAMELEN);
        //read_input("user: ", input_name, NAMELEN);
        if (strlen(input_name) <= 0) {
            return;
        }
        user_t *user;
        user = get_user_by_name(input_name, 0);
        if (user == NULL) {
            char input_key[KEYLEN];
            puts("\x5b\x4a\x58\x58\x5c\x44\x59\x4f\x11");
            read_input(input_key, KEYLEN);
            //read_input("password: ", input_key, KEYLEN);
            // printf("not avaliable\n");
            // puts("\x45\x44\x5f\x0b\x4a\x5d\x4a\x47\x42\x4a\x49\x47\x4e");

            // printf("invalid key or username\n");
            puts("\x42\x45\x5d\x4a\x47\x42\x4f\x0b\x40\x4e\x52\x0b\x44\x59"
                 "\x0b\x5e"
                 "\x58\x4e\x59\x45\x4a\x46\x4e");
            return;
        }
        char input_key[KEYLEN];
        puts("\x5b\x4a\x58\x58\x5c\x44\x59\x4f\x11");
        read_input(input_key, KEYLEN);
        //read_input("password: ", input_key, KEYLEN);
        if (strlen(input_key) <= 1) {
            // printf("invalid key or username\n");
            puts("\x42\x45\x5d\x4a\x47\x42\x4f\x0b\x40\x4e\x52\x0b\x44\x59"
                 "\x0b\x5e"
                 "\x58\x4e\x59\x45\x4a\x46\x4e");
            free(user);
            return;
        }
        if (own_cmp(user->key, input_key) != 0) {
            // if (strncmp(user->key, input_key, strlen(input_key)) != 0) {
            //  printf("invalid key or username\n");
            puts("\x42\x45\x5d\x4a\x47\x42\x4f\x0b\x40\x4e\x52\x0b\x44\x59"
                 "\x0b\x5e"
                 "\x58\x4e\x59\x45\x4a\x46\x4e");
            goto end;
        }
        if (login != NULL) {
            free(login);
        }
        login = strdup(user->name);
        if (login == NULL) {
            // report_err("strdup");
            exit(EXIT_FAILURE);
        }
        printf("%s: ", user->name);
        // your logged in
        puts("\x52\x44\x5e\x59\x0b\x47\x44\x4c\x4c\x4e\x4f\x0b\x42\x45");
    end:
        free(user);
        return;
    } else {
        user_t *u;
        char username[NAMELEN];
        char r[14];
        char s[34];
        char _y[93];
        char chall[17] = {'\0'};
        char *pub;

        puts("\x4e\x45\x5f\x4e\x59\x0b\x5f\x43\x4e\x0b\x5e\x58\x4e\x59\x45\x4a\x46\x4e\x11");
        read_input(username, NAMELEN);
        //read_input("enter the username: ", username, NAMELEN);
        u = get_user_by_name(username, 2);
        if (u == NULL)
            exit(EXIT_FAILURE);
        if (own_cmp(_y, pub) == -1)
            exit(EXIT_FAILURE);
        printf("challenge: %s\n", chall);
        if (own_cmp(r, chall) == 0) {
            puts("invalid signature format");
            free(u);
            return;
        }
        if (*_y == '\0')
            pub = u->key;
        else
            pub = _y;
        if (own_cmp(s, r))
            printf("user %s's profile is %d\n", u->name, u->score);
        else
            puts("invalid signature");
        free(u);
    }
}

static void loggedin() {
    if (login != NULL)
        printf("%s\n", login);
    else
        // printf("not logged in\n");
        puts("\x45\x44\x5f\x0b\x47\x44\x4c\x4c\x4e\x4f\x0b\x42\x45");
}

static void debug(int i) {
    (void)i;
    int status;
    sqlite3_stmt *res;

    char *query = "SELECT * FROM users";

    status = sqlite3_prepare_v2(db, query, -1, &res, NULL);
    if (status != SQLITE_OK)
        printf("kacke\n");
    printf("|%-2s %-*s %-*s %-5s|\n", "id", 18, "name", 37, "password",
           "score");
    while (sqlite3_step(res) == SQLITE_ROW)
        printf("|%-2s %-*s %-*s %-5s|\n", sqlite3_column_text(res, 0), 18,
               sqlite3_column_text(res, 1), 37, sqlite3_column_text(res, 2),
               sqlite3_column_text(res, 3));
    sqlite3_finalize(res);
}

#pragma GCC push_options
#pragma GCC optimize("O0")
static char *get_sql_all(int i) {
    if (i == 0) {
        char ssql[] = "SELECT MAX(LENGTH(name)) FROM users";
        return strdup(ssql);
    } else if (i == 1) {
        char ssql[] = "SELECT * FROM users";
        return strdup(ssql);
    }
    return NULL;
}
#pragma GCC pop_options

static void list_users() {
    int status;
    sqlite3_stmt *res;
    char *tmp = get_sql_all(0);
    status = sqlite3_prepare_v2(db, tmp, -1, &res, NULL);
    free(tmp);
    if (status != SQLITE_OK) {
        printf("sqlstatus = %d\n", status);
        return;
    }
    if (sqlite3_step(res) != SQLITE_ROW) {
        return;
    }
    int max = sqlite3_column_int(res, 0);
    sqlite3_finalize(res);

    tmp = get_sql_all(1);
    status = sqlite3_prepare_v2(db, tmp, -1, &res, NULL);
    free(tmp);
    if (status != SQLITE_OK)
        return;
    while (sqlite3_step(res) == SQLITE_ROW)
        printf("|%-*s %*s|\n", max, sqlite3_column_text(res, 1), 2,
               sqlite3_column_text(res, 3));
    sqlite3_finalize(res);
}

static void help() {
    //{"help      print this message"},
    puts("\x43\x4e\x47\x5b\x0b\x0b\x0b\x0b\x0b\x0b\x5b\x59\x42\x45\x5f"
         "\x0b\x5f"
         "\x43\x42\x58\x0b\x46\x4e\x58\x58\x4a\x4c\x4e");
    //{"login       log in"},
    puts("\x47\x44\x4c\x42\x45\x0b\x0b\x0b\x0b\x0b\x47\x44\x4c"
         "\x0b\x42\x45");
    //{"test      prints test"},
    // puts("\x5f\x4e\x58\x5f\x0b\x0b\x0b\x0b\x0b\x0b\x5b\x59\x42\x45\x5f\x58\x0b"
    //     "\x5f\x4e\x58\x5f");
    //{"reg       register new user"},
    puts("\x59\x4e\x4c\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x59\x4e\x4c\x42\x58"
         "\x5f\x4e"
         "\x59\x0b\x45\x4e\x5c\x0b\x5e\x58\x4e\x59");
    //{"score     prints score of all users"},
    puts("\x58\x48\x44\x59\x4e\x0b\x0b\x0b\x0b\x0b\x5b\x59\x42\x45\x5f"
         "\x58\x0b"
         "\x58\x48\x44\x59\x4e\x0b\x44\x4d\x0b\x4a\x47\x47\x0b\x5e\x58"
         "\x4e\x59"
         "\x58");
    //{"loop      recursin"},
    // puts("\x47\x44\x44\x5b\x0b\x0b\x0b\x0b\x0b\x0b\x59\x4e\x48\x5e\x59\x58\x42"
    //     "\x45");
    //{"play      play a game of TicTacToe"},
    puts("\x5b\x47\x4a\x52\x0b\x0b\x0b\x0b\x0b\x0b\x5b\x47\x4a\x52\x0b"
         "\x4a\x0b"
         "\x4c\x4a\x46\x4e\x0b\x44\x4d\x0b\x7f\x42\x48\x7f\x4a\x48\x7f"
         "\x44"
         "\x4e");
    //{"logedin   as who am i logged in"}};
    puts("\x47\x44\x4c\x4c\x4e\x4f\x42\x45\x0b\x0b\x4a\x58\x0b\x5c"
         "\x43\x44"
         "\x0b"
         "\x4a\x46\x0b\x42\x0b\x47\x44\x4c\x4c\x4e\x4f\x0b\x42\x45");
}

// int __real_puts(const char *s);
//
// int __wrap_puts(const char *s) {
//     char new[strlen(s) + 1];
//     for (int i = 0; i < strlen(s) + 1; i++) {
//         new[i] = '\0';
//     }
//     for (int i = 0; i < strlen(s); i++) {
//         new[i] = s[i] ^ 0b101011;
//     }
//     return __real_puts((char *)new);
// }

// int puts(const char *s) {
//     int (*libc_puts)(const char *) = dlsym(RTLD_NEXT, "puts");
//     char new[strlen(s) + 1];
//     for (int i = 0; i < strlen(s) + 1; i++) {
//         new[i] = '\0';
//     }
//     // printf("\t");
//     for (int i = 0; i < strlen(s); i++) {
//         new[i] = s[i] ^ 0b101011;
//         // new[i] = s[i] - 19;
//         // printf("%c", s[i]-19);
//     }
//     // printf("\n");
//     return libc_puts(new);
// }

// void loop(int i) {
//     if (i == 5) {
//         laap(i);
//     }
//     printf("loop %d\n", i);
//     //\n == 10 -> 0xa -> 00001010
//     puts("_NX_");
// }
//
// void laap(int x) {
//     printf("laap %d\n", x);
//     if (x != 5)
//         loop(9);
//     printf("laap\n");
//     puts("\x41\x4a\x0b\x46\x44\x42\x45\x21");
// }

void trap_handler() {
    one = user_register;
    two = logi;
    three = help;
    four = tictactoe;
    five = loggedin;
    six = list_users;
    seven = show_password;
}

static void check_proc_status() {
    FILE *proc_status = fopen("/proc/self/status", "r");
    if (proc_status == NULL) {
        return;
    }
    char line[1024] = {};
    char *fgets(char *s, int size, FILE *stream);
    while (fgets(line, sizeof(line), proc_status) != NULL) {
        const char traceString[] = "TracerPid:";
        char *tracer = strstr(line, traceString);
        if (tracer != NULL) {
            int pid = atoi(tracer + sizeof(traceString) - 1);
            if (pid != 0) {
                fclose(proc_status);
                kill(getppid(), SIGKILL);
                exit(EXIT_FAILURE);
            }
        }
    }
    fclose(proc_status);
}

void __attribute__((constructor)) before_main() { check_proc_status(); }

static char *calc_addr(char *p_addr) { return p_addr + 0x400000; }

void __attribute__((optimize("O1"))) test(const char *str) {
    char pass[200] = {};
    char *label_address = calc_addr(((char *)&&return_here) - 0x400000);
    __asm__ volatile(
        "push %0\n"
        "ret\n"
        ".string \"\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\""
        :
        : "g"(label_address));

return_here:
    printf("shit\n");
}

int checksum_file() {
    FILE *fp = fopen("tic-tac-toe", "rb");
    int checksum = 0;
    int c = fgetc(fp);
    while (c != EOF) {
        checksum ^= c;
        c = fgetc(fp);
    }
    return checksum;
}

static int checksum(int i) {
    void *c = logi;
    int checksum = i;

    for (int j = 0; j < 400; j++) {
        checksum ^= *(int *)c++;
    }

    return checksum;
}

static void __attribute__((optimize("O1"))) checkjmp() {
    //printf("%d\n", checksum(4));
    return;
    char *label_address =
        calc_addr(((char *)&&first) - 0x400000) + (checksum(4) + 189908230);
    __asm__ volatile("push %0\n"
                     "ret\n"
                     :
                     : "g"(label_address));

first:
    return;
}

int main(int argc, char *argv[]) {
    // printf("file: %d\n", checksum_file());
    struct sigaction sVal;
    sVal.sa_sigaction = trap_handler;
    sigemptyset(&sVal.sa_mask);
    sVal.sa_flags = SA_SIGINFO;
    sigaction(SIGTRAP, &sVal, NULL);

    kill(getpid(), SIGTRAP);
    checkjmp();

    // if (ptrace(PTRACE_TRACEME, 0, NULL, 0) == -1) {
    if (detect_debugger()) {
    dead:;
        char *dead = NULL;
        printf("%c\n", *dead);
    }

    init(argc, argv);

    if (prctl(PR_SET_DUMPABLE, 0) < 0) {
        goto dead;
    }

    char cmd[16];

    // printf(" __ __ _____ __ __ \n");
    // printf("|  |  |  _  |  |  |\n");
    // printf("|_   _|     |_   _|\n");
    // printf("  |_| |__|__| |_|  \n");

    // printf("  _______     ______          ______\n");
    puts("\x0b\x0b\x74\x74\x74\x74\x74\x74\x74\x0b\x0b\x0b\x0b\x0b\x74"
         "\x74\x74"
         "\x74\x74\x74\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x74\x74"
         "\x74\x74"
         "\x74\x74");
    // printf(" /_  __(_)___/_  __/___ _____/_  __/___  ___\n");
    puts("\x0b\x04\x74\x0b\x0b\x74\x74\x03\x74\x02\x74\x74\x74\x04\x74"
         "\x0b\x0b"
         "\x74\x74\x04\x74\x74\x74\x0b\x74\x74\x74\x74\x74\x04\x74\x0b"
         "\x0b\x74"
         "\x74\x04\x74\x74\x74\x0b\x0b\x74\x74\x74");
    // printf("  / / / / ___// / / __ `/ ___// / / __ \\/ _ \\\n");
    puts("\x0b\x0b\x04\x0b\x04\x0b\x04\x0b\x04\x0b\x74\x74\x74\x04\x04"
         "\x0b\x04"
         "\x0b\x04\x0b\x74\x74\x0b\x4b\x04\x0b\x74\x74\x74\x04\x04\x0b"
         "\x04\x0b"
         "\x04\x0b\x74\x74\x0b\x77\x04\x0b\x74\x0b\x77");
    // printf(" / / / / /__ / / / /_/ / /__ / / / /_/ /  __/\n");
    puts("\x0b\x04\x0b\x04\x0b\x04\x0b\x04\x0b\x04\x74\x74\x0b\x04\x0b"
         "\x04\x0b"
         "\x04\x0b\x04\x74\x04\x0b\x04\x0b\x04\x74\x74\x0b\x04\x0b\x04"
         "\x0b\x04"
         "\x0b\x04\x74\x04\x0b\x04\x0b\x0b\x74\x74\x04");
    // printf("/_/ /_/\___//_/  \__,_/\___//_/  \____/\___/ \n");
    puts("\x04\x74\x04\x0b\x04\x74\x04\x77\x74\x74\x74\x04\x04\x74\x04"
         "\x0b\x0b"
         "\x77\x74\x74\x07\x74\x04\x77\x74\x74\x74\x04\x04\x74\x04\x0b"
         "\x0b\x77"
         "\x74\x74\x74\x74\x04\x77\x74\x74\x74\x04\x0b");

    // test("");

    //trollolo
    char secret[] = {'t', 'r', 'o', 'l', 'l', 'o', 'l', 'o', '\0'};

    if (ptrace(PTRACE_TRACEME, 0, 1, 0) != 0) {
        goto dead;
    }

    while (1) {
        // alarm(120 * 30);
        alarm(10 * 60);
        printf("$ ");
        if (fgets(cmd, 16, stdin) == NULL) {
            break;
        }
        if (cmd[strlen(cmd) - 1] != '\n') {
            int c;
            while ((c = getchar()) != '\n' && c != EOF) {
            }
        }

        remove_new_line(cmd);

        if (strcmp(cmd, "play") == 0) {
            if (login == NULL) {
                // printf("log in first\n");
                puts("\x47\x44\x4c\x0b\x42\x45\x0b\x4d\x42\x59\x58"
                     "\x5f");
                continue;
            }
            int *ret = malloc(sizeof(int));
            if (ret == NULL) {
                perror("malloc");
                exit(EXIT_FAILURE);
            }
            ((void (*)(int *))four)(ret);
            if (*ret > 0) {
                // login user += 1 score
                update_user_by_name(login, 1);
            }
        } else if (strcmp(cmd, "reg") == 0) {
            ((void (*)(int))one)(1);
        } else if (strcmp(cmd, "login") == 0) {
            ((void (*)(int))two)(2);
        } else if (strcmp(cmd, "help") == 0) {
            ((void (*)(int))three)(4);
        } else if (strcmp(cmd, "loggedin") == 0) {
            ((void (*)(int))five)(7);
        } else if (strcmp(cmd, "score") == 0) {
            ((void (*)(int))six)(2);
        } else if (strcmp(cmd, secret) == 0) {
            if (login == NULL) {
                // printf("log in first\n");
                puts("\x47\x44\x4c\x0b\x42\x45\x0b\x4d\x42\x59\x58"
                     "\x5f");
                continue;
            }
            ((void (*)(int))seven)(3);
        } else if (strcmp(cmd, "exit") == 0) {
            break;
            //} else if (strcmp(cmd, "debug") == 0) {
            //    debug(3);
        } else {
            // unknown command
            puts("\x5e\x45\x40\x45\x44\x5c\x45\x0b\x48\x44\x46\x46\x4a"
                 "\x45\x4f");
        }

        if (feof(stdin)) {
            break;
        }
    }
    puts("");
    if (ferror(stdin)) {
        exit(EXIT_FAILURE);
    }
    exit(EXIT_SUCCESS);
}

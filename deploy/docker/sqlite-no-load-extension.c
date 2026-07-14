#include "sqlite3.h"

/*
 * CPython's official binary extension was linked against these symbols. The
 * release SQLite library is compiled with SQLITE_OMIT_LOAD_EXTENSION, so the
 * compatibility symbols must remain fail-closed rather than disappearing and
 * preventing _sqlite3 from loading.
 */
int sqlite3_enable_load_extension(sqlite3 *database, int enabled) {
    (void)database;
    (void)enabled;
    return SQLITE_AUTH;
}

int sqlite3_load_extension(
    sqlite3 *database,
    const char *file_name,
    const char *entry_point,
    char **error_message
) {
    (void)database;
    (void)file_name;
    (void)entry_point;
    if (error_message != 0) {
        *error_message = sqlite3_mprintf("loadable extensions are disabled");
    }
    return SQLITE_AUTH;
}

#pragma once

#ifdef __cplusplus
extern "C" { // only need to export C interface if
             // used by C++ source code
#endif

#include "dictionary.h"
#include <rasta/config.h>

/**
 * The config key for the value of the initial sequence number of the SR layer
 */
#define RASTA_CONFIG_KEY_INITIAL_SEQ_NUM "RASTA_INITIAL_SEQ"

#define RASTA_CONFIG_KEY_LOGGER_TYPE "LOGGER_TYPE"
#define RASTA_CONFIG_KEY_LOGGER_FILE "LOGGER_FILE"
#define RASTA_CONFIG_KEY_LOGGER_MAX_LEVEL "LOGGER_MAX_LEVEL"
#define RASTA_CONFIG_KEY_ACCEPTED_VERSIONS "RASTA_ACCEPTED_VERSIONS"

void load_configfile(struct RastaConfigInfo *config, struct logger_t *logger, const char *config_file_path);

/**
 * represents a rasta config
 * NOTE: please use the functions provided in config.h to access the dictionarys elements or use values for standard values
 */
struct RastaConfig {
    /**
     * the dictionary
     */
    struct Dictionary dictionary;

    /**
     * console logger for debug information
     */
    struct logger_t logger;

    /**
     * the filename (do not set manually)
     */
    char filename[512];
    /*
     * the standard values
     */
    struct RastaConfigInfo values;
};

/**
 * loads a config file and fills the config with the values in the file
 * @param config the loaded config
 * @param filename
 * @return 0 if success
 */
int config_load(struct RastaConfig *config, const char *filename);

/**
 * returns the entry behind the key
 * NOTE: check the type before accessing the value. ERROR means, the key is not in the dictionary
 * @param cfg
 * @param key
 * @return
 */
struct DictionaryEntry config_get(struct RastaConfig *cfg, const char *key);

/**
 * frees the config
 * @param cfg
 */
void config_free(struct RastaConfig *cfg);

#ifdef __cplusplus
}
#endif

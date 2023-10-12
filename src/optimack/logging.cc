
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <sys/stat.h>


#define LOG_FILE "/var/optack.log"


static FILE *log_file;
static FILE *exp_log_file;
static FILE *time_file;// = fopen("/var/time_file.log", "a");

// 0 - print log to stdout, 1 - output log to file
int opt_logging_to_file = 1;

// Logging level: 0 - error, 1 - warning, 2 - info, 3 - debug, 4 - debug (verbose)
int opt_logging_level = 3;


int init_log()
{
    if (opt_logging_to_file) {
        log_file = fopen(LOG_FILE, "w");
        if (log_file == NULL) {
            fprintf(stderr, "Failed to open or create log file %s\n", LOG_FILE);
            return -1;
        }
        chmod(LOG_FILE, 0644);
        setbuf(log_file, NULL);

        time_file = fopen("/var/time_file.log", "a");
        setbuf(time_file, NULL);

    }
    return 0;
}

int init_exp_log(const char *filepath)
{
    exp_log_file = fopen(filepath, "w");
    if (exp_log_file == NULL) {
        fprintf(stderr, "Failed to open or create log file %s\n", filepath);
        return -1;
    }
    chmod(filepath, 0644);
    setbuf(exp_log_file, NULL);
    return 0;
}


int fin_log()
{
    if (opt_logging_to_file && log_file != NULL) {
        fclose(log_file);
    }
    if (exp_log_file != NULL) {
        fclose(exp_log_file);
    }
    return 0;
}

const char LEVEL_STR[][10] = {
    "ERROR", 
    "WARNING",
    "INFO",
    "DEBUG",
    "DEBUGV",
};

void log_func(int level, const char *fmt, ...)
{
    va_list ap;
    char buffer[1024];
    char time_str[64];
    time_t rawtime;
    struct tm timeinfo;
    struct timespec ts;
    double time_ts;

    if (level == 99) {
        /* experiment log */
        time(&rawtime);
        localtime_r(&rawtime, &timeinfo);
        strftime(time_str, 20, "%Y-%m-%d %H:%M:%S", &timeinfo);

        va_start(ap, fmt);
        vsnprintf(buffer, sizeof(buffer), fmt, ap);
        if (exp_log_file != NULL) {
            //fprintf(log_file, "%lf [EXP] %s\n", time_ts, buffer);
            fprintf(exp_log_file, "%s [EXP] %s\n", time_str, buffer);
            if (opt_logging_to_file == 0) {
                //fprintf(log_file, "%lf [EXP] %s\n", time_ts, buffer);
                fprintf(stdout, "%s [EXP] %s\n", time_str, buffer);
            }
        }
        va_end(ap);
    
        return;
    }

    if (level > opt_logging_level)
        return;

    time(&rawtime);
    localtime_r(&rawtime, &timeinfo);
    strftime(time_str, 20, "%Y-%m-%d %H:%M:%S", &timeinfo);

    /* a more acurate timestamp */
    clock_gettime(CLOCK_REALTIME, &ts);
    time_ts = ts.tv_sec + ts.tv_nsec / 1000000000.0;

    va_start(ap, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, ap);
    // if (log_file != NULL) {
    //     fprintf(log_file, "%s [%s] %s\n", time_str, LEVEL_STR[level], buffer);
    //     if (opt_logging_to_file == 0) {
    //         fprintf(stdout, "%s [%s] %s\n", time_str, LEVEL_STR[level], buffer);
    //     }
    // }
    if (opt_logging_to_file && log_file != NULL) {
        //fprintf(log_file, "%lf [%s] %s\n", time_ts, LEVEL_STR[level], buffer);
        fprintf(log_file, "%s [%s] %s\n", time_str, LEVEL_STR[level], buffer);
    } else {
        //fprintf(stdout, "%lf [%s] %s\n", time_ts, LEVEL_STR[level], buffer);
        fprintf(stdout, "%s [%s] %s\n", time_str, LEVEL_STR[level], buffer);
    }
    va_end(ap);
}


void print_func(const char *fmt, ...)
{
    va_list ap;
    char buffer[1024];
    char time_str[64];
    time_t rawtime;
    struct tm timeinfo;
    struct timespec ts;
    double time_ts;

    // time(&rawtime);
    // localtime_r(&rawtime, &timeinfo);
    // strftime(time_str, 20, "%Y-%m-%d %H:%M:%S", &timeinfo);

    /* a more acurate timestamp */
    clock_gettime(CLOCK_REALTIME, &ts);
    time_ts = ts.tv_sec + ts.tv_nsec / 1000000000.0;
    fprintf(time_file, "%lf\n", time_ts);

    va_start(ap, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, ap);
    fprintf(stdout, "%lf [%s] %s\n", time_ts, "INFO", buffer);
    // fprintf(stdout, "%s [%s] %s", time_str, "INFO", buffer);
    va_end(ap);
}

#define IO_LIST _IOWR('N', 1, char)
#define IO_FG _IOWR('N', 2, char)
#define IO_KILL _IOWR('N', 3, char)
#define IO_WAIT _IOWR('N', 4, char)
#define IO_MEM _IOWR('N', 5, char)
#define IO_MOD _IOWR('N', 6, char)

struct work_data {
    struct work_struct* work;
    struct file  *file;
    char* arg;
};
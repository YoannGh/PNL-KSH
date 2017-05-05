#define LIST _IOWR('N', 1, char)
#define FG _IOWR('N', 2, char)
#define KILL _IOWR('N', 3, char)
#define WAIT _IOWR('N', 4, char)
#define MEM _IOWR('N', 5, char)
#define MOD _IOWR('N', 6, char)

struct work_data {
    struct work_struct* work;
    struct file  *file;
    char* arg;
};
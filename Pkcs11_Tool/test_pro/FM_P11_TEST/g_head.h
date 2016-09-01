
#define  LOOPTIMES 10
#define  MAX_THREAD_NUM 100
#define  MAX_PROCESS_NUM 5

//#define OS_WINDOWS 1
#define  OS_LINUX 1

#define DEVICE_CARD 
//#define DEVICE_KEY

#ifdef OS_WINDOWS
#define  FLAG  DWORD WINAPI
#else
#define  FLAG  int
#endif

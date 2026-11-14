/* Attach a new System V shared memory segment with execute permission */

#include <err.h>
#include <stddef.h>
#include <sys/shm.h>

int main(void) {
    /* Execute permission for the owner, so attaching needs no CAP_IPC_OWNER */
    int id = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0700);
    if (id == -1) {
        err(1, "shmget");
    }
    if (shmat(id, NULL, SHM_EXEC) == (void *)-1) {
        err(1, "shmat");
    }
    if (shmctl(id, IPC_RMID, NULL) == -1) {
        err(1, "shmctl");
    }
    return 0;
}

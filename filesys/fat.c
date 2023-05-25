#include "filesys/fat.h"
#include "devices/disk.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include <stdio.h>
#include <string.h>

/* Should be less than DISK_SECTOR_SIZE */
struct fat_boot {
	unsigned int magic;
	unsigned int sectors_per_cluster; /* Fixed to 1 */
	unsigned int total_sectors;
	unsigned int fat_start;
	unsigned int fat_sectors; /* Size of FAT in sectors. // 디스크 공간 크기를 sectors 단위로 표시 */
	unsigned int root_dir_cluster;
};

/* FAT FS */
struct fat_fs {
	struct fat_boot bs;
	unsigned int *fat;
	unsigned int fat_length; /* fat_sectors / size of FAT entry  // FAT 테이블이 포함하는 엔트리의 개수 // FAT 테이블의 논리적인 크기를 엔트리 단위로 표시 */
	disk_sector_t data_start;
	cluster_t last_clst;
	struct lock write_lock;
};

static struct fat_fs *fat_fs;

void fat_boot_create (void);
void fat_fs_init (void);

void
fat_init (void) {
	fat_fs = calloc (1, sizeof (struct fat_fs));
	if (fat_fs == NULL)
		PANIC ("FAT init failed");

	// Read boot sector from the disk
	unsigned int *bounce = malloc (DISK_SECTOR_SIZE);
	if (bounce == NULL)
		PANIC ("FAT init failed");
	disk_read (filesys_disk, FAT_BOOT_SECTOR, bounce);
	memcpy (&fat_fs->bs, bounce, sizeof (fat_fs->bs));
	free (bounce);

	// Extract FAT info
	if (fat_fs->bs.magic != FAT_MAGIC)
		fat_boot_create ();
	fat_fs_init ();
}

void
fat_open (void) {
	fat_fs->fat = calloc (fat_fs->fat_length, sizeof (cluster_t));
	if (fat_fs->fat == NULL)
		PANIC ("FAT load failed");

	// Load FAT directly from the disk
	uint8_t *buffer = (uint8_t *) fat_fs->fat;
	off_t bytes_read = 0;
	off_t bytes_left = sizeof (fat_fs->fat);
	const off_t fat_size_in_bytes = fat_fs->fat_length * sizeof (cluster_t);
	for (unsigned i = 0; i < fat_fs->bs.fat_sectors; i++) {
		bytes_left = fat_size_in_bytes - bytes_read;
		if (bytes_left >= DISK_SECTOR_SIZE) {
			disk_read (filesys_disk, fat_fs->bs.fat_start + i,
			           buffer + bytes_read);
			bytes_read += DISK_SECTOR_SIZE;
		} else {
			uint8_t *bounce = malloc (DISK_SECTOR_SIZE);
			if (bounce == NULL)
				PANIC ("FAT load failed");
			disk_read (filesys_disk, fat_fs->bs.fat_start + i, bounce);
			memcpy (buffer + bytes_read, bounce, bytes_left);
			bytes_read += bytes_left;
			free (bounce);
		}
	}
}

void
fat_close (void) {
	// Write FAT boot sector
	uint8_t *bounce = calloc (1, DISK_SECTOR_SIZE);
	if (bounce == NULL)
		PANIC ("FAT close failed");
	memcpy (bounce, &fat_fs->bs, sizeof (fat_fs->bs));
	disk_write (filesys_disk, FAT_BOOT_SECTOR, bounce);
	free (bounce);

	// Write FAT directly to the disk
	uint8_t *buffer = (uint8_t *) fat_fs->fat;
	off_t bytes_wrote = 0;
	off_t bytes_left = sizeof (fat_fs->fat);
	const off_t fat_size_in_bytes = fat_fs->fat_length * sizeof (cluster_t);
	for (unsigned i = 0; i < fat_fs->bs.fat_sectors; i++) {
		bytes_left = fat_size_in_bytes - bytes_wrote;
		if (bytes_left >= DISK_SECTOR_SIZE) {
			disk_write (filesys_disk, fat_fs->bs.fat_start + i,
			            buffer + bytes_wrote);
			bytes_wrote += DISK_SECTOR_SIZE;
		} else {
			bounce = calloc (1, DISK_SECTOR_SIZE);
			if (bounce == NULL)
				PANIC ("FAT close failed");
			memcpy (bounce, buffer + bytes_wrote, bytes_left);
			disk_write (filesys_disk, fat_fs->bs.fat_start + i, bounce);
			bytes_wrote += bytes_left;
			free (bounce);
		}
	}
}

void
fat_create (void) {
	// Create FAT boot
	fat_boot_create ();
	fat_fs_init ();

	// Create FAT table
	fat_fs->fat = calloc (fat_fs->fat_length, sizeof (cluster_t));
	if (fat_fs->fat == NULL)
		PANIC ("FAT creation failed");

	// Set up ROOT_DIR_CLST
	fat_put (ROOT_DIR_CLUSTER, EOChain);

	// Fill up ROOT_DIR_CLUSTER region with 0
	uint8_t *buf = calloc (1, DISK_SECTOR_SIZE);
	if (buf == NULL)
		PANIC ("FAT create failed due to OOM");
	disk_write (filesys_disk, cluster_to_sector (ROOT_DIR_CLUSTER), buf);
	free (buf);
}

void
fat_boot_create (void) {
	unsigned int fat_sectors =
	    (disk_size (filesys_disk) - 1)
	    / (DISK_SECTOR_SIZE / sizeof (cluster_t) * SECTORS_PER_CLUSTER + 1) + 1;
	fat_fs->bs = (struct fat_boot){
	    .magic = FAT_MAGIC,
	    .sectors_per_cluster = SECTORS_PER_CLUSTER,
	    .total_sectors = disk_size (filesys_disk),
	    .fat_start = 1,
	    .fat_sectors = fat_sectors,
	    .root_dir_cluster = ROOT_DIR_CLUSTER,
	};
}

// fat_fs의 fat_length와 data_start 필드를 초기화해야 합니다. fat_length는 파일시스템에 몇 개의 클러스터가 있는지에 대한 정보를 저장하고, data_start는 어떤 섹터에서 파일 저장을 시작할 수 있는지에 대한 정보를 저장합니다.
void
fat_fs_init (void) {
	/* TODO: Your code goes here. */
	/* data_start 는 fat_table 크기 */
	fat_fs->data_start = fat_fs->bs.fat_start+fat_fs->bs.fat_sectors;
	fat_fs->fat_length = fat_fs->bs.fat_sectors/(sizeof(cluster_t)*SECTORS_PER_CLUSTER);
}

/*----------------------------------------------------------------------------*/
/* FAT handling                                                               */
/*----------------------------------------------------------------------------*/

/* Add a cluster to the chain.
 * If CLST is 0, start a new chain.
 * Returns 0 if fails to allocate a new cluster. */
/* clst 인자(클러스터 인덱싱 넘버)로 특정된 클러스터 뒤에 다른 클러스터를 추가함으로써 체인을 연장합니다.
만약 clst가 0이라면, 새로운 체인을 만듭니다.
새롭게 할당된 클러스터의 넘버를 리턴합니다.*/
cluster_t
fat_create_chain (cluster_t clst) {
	/* TODO: Your code goes here. */
	int i = fat_fs->bs.fat_start+1;
	if (clst == 0){
		for (i ; i < fat_fs->fat_length ; i++){
			if (fat_get(i) == 0){
				fat_put(i,EOChain);
				return i;
			}
		}
	}
	// EOC 찾기
	int temp = 0;
	for (i ; i < fat_fs->fat_length ; i++){
		if (fat_get(i) == EOChain) {
			temp = i;
		}
	}
	// 0찾기
	for (i ; i < fat_fs->fat_length ; i++){
		if (fat_get(i) == 0){
			fat_put(i,EOChain);
			fat_put(temp,i);
		}
	}
	return i;
}

/* Remove the chain of clusters starting from CLST.
 * If PCLST is 0, assume CLST as the start of the chain. */

/* clst로부터 시작하여, 체인으로부터 클러스터를 제거합니다. pclst는 체인에서의 clst 직전 클러스터여야 합니다. 이 말은, 이 함수가 실행되고 나면 pclst가 업데이트된 체인의 마지막 원소가 될 거라는 말입니다. 만일 clst가 체인의 첫 번째 원소라면, pclst의 값은 0이어야 할 겁니다. */
void
fat_remove_chain (cluster_t clst, cluster_t pclst) {
	/* TODO: Your code goes here. */
	fat_put(pclst,EOChain);
	for (clst ; clst< fat_fs->fat_length; clst = fat_get(clst)){
		fat_put(clst,0);
	}
}

/* Update a value in the FAT table. */
/* 클러스터 넘버 clst 가 가리키는 FAT 엔트리를 val로 업데이트합니다. FAT에 있는 각 엔트리는 체인에서의 다음 클러스터를 가리키고 있기 때문에 (만약 존재한다면 그렇다는 거고, 다음 클러스터가 존재하지 않으면 EOChain (End Of Chain)입니다), 이 함수는 연결관계를 업데이트하기 위해 사용될 수 있습니다. */
void
fat_put (cluster_t clst, cluster_t val) {
	/* TODO: Your code goes here. */
	*(fat_fs->fat + clst) = val;
}

/* Fetch a value in the FAT table. */
/* clst가 가리키는 클러스터 넘버를 리턴합니다. */
cluster_t
fat_get (cluster_t clst) {
	/* TODO: Your code goes here. */
	int i = *(fat_fs->fat + clst);
	return i;
}

/* Covert a cluster # to a sector number. */
/* 클러스터 넘버 clst를 상응하는 섹터 넘버로 변환하고, 그 섹터 넘버를 리턴합니다. */
disk_sector_t
cluster_to_sector (cluster_t clst) {
	/* TODO: Your code goes here. */
	// fat_fs->data_start * DISK_SECTOR_SIZE;
	// fat_fs->fat_length = fat_fs->bs.fat_sectors/(sizeof(cluster_t)*SECTORS_PER_CLUSTER);
	return clst * sizeof(cluster_t);

}

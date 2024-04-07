#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#define READING_SIZE 4096
/*
	待定：
	时间戳
	帮助显示

	各种参数的两种方向
	两种方向下的设备文件操作
	设备文件的删除


*/
// isloated
// level 1
#define FILE_PATH_BLACK_1 "pre_routing/file_black_1.txt"
#define FILE_COUNT_PATH_BLACK_1 "pre_routing/file_count_black_1.txt"
#define DEVICE_FILE_PATH_BLACK_1 "/dev/controlinfo_black_1"
#define FILE_PATH_WHITE_1 "pre_routing/file_white_1.txt"
#define FILE_COUNT_PATH_WHITE_1 "pre_routing/file_count_white_1.txt"
#define DEVICE_FILE_PATH_WHITE_1 "/dev/controlinfo_white_1"
#define FILE_MODE_PATH_1 "pre_routing/mode_1.txt"
// level 2
#define FILE_PATH_BLACK_2 "local_in/file_black_2.txt"
#define FILE_COUNT_PATH_BLACK_2 "local_in/file_count_black_2.txt"
#define DEVICE_FILE_PATH_BLACK_2 "/dev/controlinfo_black_2"
#define FILE_PATH_WHITE_2 "local_in/file_white_2.txt"
#define FILE_COUNT_PATH_WHITE_2 "local_in/file_count_white_2.txt"
#define DEVICE_FILE_PATH_WHITE_2 "/dev/controlinfo_white_2"
#define FILE_MODE_PATH_2 "local_in/mode_2.txt"
// level 3
#define FILE_PATH_BLACK_3 "file_black_3.txt"
#define FILE_COUNT_PATH_BLACK_3 "file_count_black_3.txt"
#define DEVICE_FILE_PATH_BLACK_3 "/dev/controlinfo_black_3"
#define FILE_PATH_WHITE_3 "file_white_3.txt"
#define FILE_COUNT_PATH_WHITE_3 "file_count_white_3.txt"
#define DEVICE_FILE_PATH_WHITE_3 "/dev/controlinfo_white_3"
#define FILE_MODE_PATH_3 "mode_3.txt"
// level 4
#define FILE_PATH_BLACK_4 "local_out/file_black_4.txt"
#define FILE_COUNT_PATH_BLACK_4 "local_out/file_count_black_4.txt"
#define DEVICE_FILE_PATH_BLACK_4 "/dev/controlinfo_black_4"
#define FILE_PATH_WHITE_4 "local_out/file_white_4.txt"
#define FILE_COUNT_PATH_WHITE_4 "local_out/file_count_white_4.txt"
#define DEVICE_FILE_PATH_WHITE_4 "/dev/controlinfo_white_4"
#define FILE_MODE_PATH_4 "local_out/mode_4.txt"
// level 5
#define FILE_PATH_BLACK_5 "post_routing/file_black_5.txt"
#define FILE_COUNT_PATH_BLACK_5 "post_routing/file_count_black_5.txt"
#define DEVICE_FILE_PATH_BLACK_5 "/dev/controlinfo_black_5"
#define FILE_PATH_WHITE_5 "post_routing/file_white_5.txt"
#define FILE_COUNT_PATH_WHITE_5 "post_routing/file_count_white_5.txt"
#define DEVICE_FILE_PATH_WHITE_5 "/dev/controlinfo_white_5"
#define FILE_MODE_PATH_5 "post_routing/mode_5.txt"

// shared
#define FILE_MODE_PATH "mode.txt"			  // mode = 0:BLACK, mode = 1:WHITE
#define FILE_WORK_LEVEL_PATH "work_level.txt" // work_level:1-5

#define FILE_TIME_PATH_1 "/dev/controlinfo_time_1"
#define FILE_TIME_PATH_5 "/dev/controlinfo_time_5"

unsigned int controlled_protocol = 0;
unsigned short controlled_srcport = 0;
unsigned short controlled_dstport = 0;
unsigned int controlled_saddr = 0;
unsigned int controlled_daddr = 0;
int count = -1;				// the sequence of the record
char file_path[128];		// the file to save the filter
char file_count_path[128];	// the file to save the number of filter
char file_mode_path[128];	// the file to save the mode
char device_file_path[128]; // the device file to send the filter to kernel
char file_mode[128];		// 0 or 1 , mode = 0 :BLACK, mode = 1:WHITE
char file_work_level[128];	// 1-5；1 NF_INET_PRE_ROUTING 2 NF_INET_LOCAL_IN 3 NF_INET_FORWARD 4 NF_INET_LOCAL_OUT 5 NF_INET_POST_ROUTING
struct control_message
{
	char controlled_protocol[20];
	char controlled_srcport[20];
	char controlled_dstport[20];
	char controlled_saddr[20];
	char controlled_daddr[20];
};

struct time_message
{
	char hour[128];
	char minute[128];
	char second[128];
};

void message_saved(int savefd, struct control_message message); // save the input message to file.txt

void device_info_saved(int fd, char controlinfo[]); // save the input message to device file

void add_function(int argc, char *argv[]);

void display_usage(char *commandname);

int getpara(int argc, char *argv[], struct control_message *message); // Parsing command line

void parse_command(int argc, char *argv[]);

void list_function();

void delete_function();

void delete_record(char *filename, int assignment_record, char buf[]);

void clear_function();

void mode_change();

void time_function();

void time_input_get(char low[], char high[], char time[]);

void time_add_file();

void time_add_device_file();

void time_stamp_set(struct time_message *time_message);

int time_stamp_check(struct time_message start_time_message, struct time_message end_time_message);

int time_check(char low[], char high[], char time[]); // 1 : time is in the range, 0 : time is out of the range

void corresponding_mode_change();

void time_transfer(char time[]);

void work_level_change();

void create_mode_file(char *file_mode_path);

void Create_Mode_File();

int level_check(char level[]); // 0 is 1 or 5  ; 1 is 2,3,4

void surprise();

void clear(char *filename);

void cut_record(char buf1[], char buf2[]);

void check_devicefile(char *filename); // check the state of device file

void check_out_of_number(int assignment_record);
void choose(char *filename, int assignment_record, char p[]); // choose the record to delete or modify
void device_file_create(char mode, char level);				  // create the device file

void init();											// init the mode and work_level
void time_file_init();									// init the time file
void time_file_create(char *file_time_path);			// create the time file
void init_path(char *file_mode, char *file_work_level); // init the file_path and file_count_path and device_file_path
void level_and_mode_show(char mode, char level);		// show the mode and work_level
void mode_level_cover_mode();

void count_delete();	 // delete the record number
void count_add();		 // add the record number
void count_delete_all(); // clear the record number
void count_get();		 // get the record number

int main(int argc, char *argv[])
{
	init();
	if (argc == 1)
	{
		display_usage(argv[0]);
		exit(1);
	}

	else if (argc > 1)
	{
		parse_command(argc, argv);
	}
	return 0;
}

void parse_command(int argc, char *argv[])
{
	if (strcmp(argv[1], "-p") == 0) // add the filter
	{

		add_function(argc, argv);
		exit(1);
	}
	else if ((strcmp(argv[1], "-h") == 0) || (strcmp(argv[1], "-?") == 0)) // display the usage
	{
		display_usage(argv[0]);
		exit(1);
	}
	else if (strcmp(argv[1], "-ls") == 0) // list the filter
	{
		list_function();
		exit(1);
	}
	else if (strcmp(argv[1], "-d") == 0) // delete the filter
	{
		delete_function();
		exit(1);
	}
	else if (strcmp(argv[1], "-dl") == 0) // clear the filter
	{
		clear_function();
		exit(1);
	}
	else if (strcmp(argv[1], "-c") == 0)
	{
		mode_change();
		exit(1);
	}
	else if (strcmp(argv[1], "-k") == 0)
	{
		work_level_change();
		exit(1);
	}
	else if (strcmp(argv[1], "-t") == 0)
	{
		time_function();
		exit(1);
	}
	else if (strcmp(argv[1], "-surprise") == 0)
	{
		surprise();
		exit(1);
	}
	else
	{
		printf("Invalid parameters!\n");
		display_usage(argv[0]);
		exit(1);
	}
}

void add_function(int argc, char *argv[])
{
	if (level_check(file_work_level) == 0)
	{
		printf("Invalid work_level! \n");
		printf("the work_level is %c\n", file_work_level[0]);
		printf("Please change the work_level to 2,3,4 \n");
		exit(1);
	}
	struct control_message message =
		{
			"0",
			"0",
			"0",
			"0.0.0.0",
			"0.0.0.0"};
	char controlinfo[32];
	int controlinfo_len = 0;
	int fd, savefd;
	char option;
	getpara(argc, argv, &message);
	*(int *)controlinfo = controlled_protocol;
	*(int *)(controlinfo + 4) = controlled_saddr;
	*(int *)(controlinfo + 8) = controlled_daddr;
	*(int *)(controlinfo + 12) = controlled_srcport;
	*(int *)(controlinfo + 16) = controlled_dstport;
	controlinfo_len = 20;

	// printf("message---input info: pn = %s, x = %s y = %s m = %s n = %s \n", message.controlled_protocol, message.controlled_saddr, message.controlled_daddr, message.controlled_srcport, message.controlled_dstport);
	// printf("device---input info: p = %d, x = %d y = %d m = %d n = %d \n", controlled_protocol, controlled_saddr, controlled_daddr, controlled_srcport, controlled_dstport);

	check_devicefile(device_file_path);

	int fds = open(file_count_path, O_RDWR | O_CREAT, 0666);
	close(fds); // the two are not working, just some kind of protection

	// fd = open(device_file_path, O_RDWR | O_APPEND, S_IRUSR | S_IWUSR);
	savefd = open(file_path, O_CREAT | O_RDWR | O_APPEND, S_IRUSR | S_IWUSR);

	/*if (fd > 0)
	{
		// device_info_saved(fd, controlinfo);
		write(fd, controlinfo, controlinfo_len);
		write(fd, "\n", 1);
	}
	else
	{
		printf("can't open %s \n", device_file_path);
		exit(1);
	}
	close(fd);
*/
	if (savefd < 0)
	{
		printf("can't open %s \n", file_path);
		exit(1);
	}
	else
	{
		message_saved(savefd, message);
	}
	close(savefd);

	count_add(file_count_path); // add the record number
}

void delete_function()
{
	printf("delete the filter: \n");
	list_function();
	printf("sure to delete?  (y/n) \n");
	char option;
	scanf("%c", &option);
	if (option == 'y')
	{
		if (level_check(file_work_level) == 0)
		{
			remove(file_path);
			time_file_create(file_path);
		}
		else
		{
			printf("please input the number of the record you want to delete: \n");
			scanf("%c", &option); // to delete the '\n'
			int assignment_record;
			scanf("%d", &assignment_record);
			check_out_of_number(assignment_record);
			char buf1[1024];
			char buf2[1024];
			choose(file_path, assignment_record, buf1);

			printf("the record you choose to delete is :\n%d %s\n", assignment_record, buf1);

			// printf("%c\n", buf[0]); // the first character
			// printf("%d\n", strlen(buf));
			// printf("%c\n", buf[strlen(buf) - 1]); // the last character, not \n

			delete_record(file_path, assignment_record, buf1);
			count_delete(); // delete the record number
							// delete_record(device_file_path, assignment_record, buf2);
		}
		printf("delete the record successfully! \n");
	}
	else
	{
		printf("cancel the delete \n");
		exit(1);
	}
}

void delete_record(char *filename, int assignment_record, char buf1[])
{
	if (strcmp(filename, file_path) == 0)
	{

		int fd;
		char buf2[1024];
		fd = open("tmp.txt", O_RDWR | O_CREAT, 0666);
		if (fd < 0)
		{
			printf("unpredictable fault happens! \n");
			exit(1);
		}
		else
		{ // write the record to tmp.txt
			int i = 0;
			for (i = 0; i <= count; i++)
			{
				choose(filename, i, buf2);

				if (strcmp(buf1, buf2) != 0)
				{
					write(fd, buf2, strlen(buf2));
					write(fd, "\n", 1);
				}
			}
		}
		close(fd);
		remove(filename);
		rename("tmp.txt", filename);
	}
	else
	{
		unlink(filename);
		check_devicefile(filename);
		int fd;
		char buf2[1024];
		fd = open(filename, O_RDWR);
		// remove("test.txt");
		// int fd2 = open("test.txt", O_RDWR | O_CREAT, 0666);
		if (fd < 0)
		{
			printf("unpredictable fault happens! \n");
			exit(1);
		}
		else
		{
			int i = 0;
			for (i = 0; i <= count; i++)
			{
				choose(file_path, i, buf2);
				char controlinfo[32];
				char tmp[32];
				int controlinfo_len = 0;

				// printf("buf2 = %s\n", buf2);

				cut_record(buf2, tmp);
				// write(fd2, tmp, strlen(tmp));
				// write(fd2, " ", 1);
				// printf("tmp = %s\n", tmp);
				if (strncmp(tmp, "ping", 4) == 0)
				{
					controlled_protocol = 1;
				}
				else if (strncmp(tmp, "tcp", 3) == 0)
				{
					controlled_protocol = 6;
				}
				else if (strncmp(tmp, "udp", 3) == 0)
				{
					controlled_protocol = 17;
				}

				cut_record(buf2, tmp);
				inet_aton(tmp, (struct in_addr *)&controlled_saddr) == 0;
				// write(fd2, tmp, strlen(tmp));
				// printf("tmp = %s\n", tmp);
				// write(fd2, " ", 1);

				cut_record(buf2, tmp);
				inet_aton(tmp, (struct in_addr *)&controlled_daddr) == 0;
				// write(fd2, tmp, strlen(tmp));
				// printf("tmp = %s\n", tmp);
				// write(fd2, " ", 1);

				cut_record(buf2, tmp);
				controlled_srcport = htons(atoi(tmp));
				// write(fd2, tmp, strlen(tmp));
				// printf("tmp = %s\n", tmp);
				// write(fd2, " ", 1);

				controlled_dstport = htons(atoi(buf2));
				// write(fd2, buf2, strlen(buf2));
				// printf("buf2 = %s\n", buf2);
				// write(fd2, " ", 1);

				*(int *)controlinfo = controlled_protocol;
				*(int *)(controlinfo + 4) = controlled_saddr;
				*(int *)(controlinfo + 8) = controlled_daddr;
				*(int *)(controlinfo + 12) = controlled_srcport;
				*(int *)(controlinfo + 16) = controlled_dstport;
				controlinfo_len = 20;

				write(fd, controlinfo, controlinfo_len);

				write(fd, "\n", 1);
				// write(fd2, "\n", 1);
			}
		}
		close(fd);
	}
}

void cut_record(char buf1[], char buf2[])
{
	int i = 0;
	int j = 0;
	char tmp1[128];
	for (i = 0; i < strlen(buf1); i++)
	{
		if (buf1[i] == ' ')
		{
			break;
		}
		tmp1[j] = buf1[i];
		j++;
	}
	strcpy(buf2, tmp1);
	buf2[j] = '\0';
	char tmp2[128];
	strcpy(tmp2, buf1 + i + 1);
	strcpy(buf1, tmp2);
}

void list_function()
{
	printf("list the filter \n");

	level_and_mode_show(file_mode[0], file_work_level[0]); // show the level and mode
	int fd;
	char buf[1024];
	fd = open(file_path, O_RDONLY);
	if (fd < 0)
	{
		printf("can't open %s ,it is not created.\n", file_path);
		exit(1);
	}
	else
	{
		printf("the form:\n");
		if (level_check(file_work_level) == 1)
		{
			printf("ID protocol source_ip destination_ip source_port destination_port \n");
			count_get();
			int i = 0;
			for (i = 0; i <= count; i++)
			{
				choose(file_path, i, buf);
				printf("%d %s \n", i, buf);
			}
		}
		else
		{
			printf("hour:minute:second \n");
			printf("start_time:\n");
			choose(file_path, 0, buf);
			printf("%s \n", buf);
			printf("end_time:\n");
			choose(file_path, 1, buf);
			printf("%s \n", buf);
		}
		close(fd);
	}
}

void clear_function()
{
	printf("sure to clear?  (y/n)\n");
	char option;
	scanf("%c", &option);
	if (option == 'y')
	{
		check_devicefile(device_file_path);
		// clear(device_file_path);
		clear(file_path);
		count_delete_all(); // clear the record number
		printf("clear the filter \n");
	}
	else
	{
		printf("cancel the clear \n");
		exit(1);
	}
}

void mode_change()
{
	level_and_mode_show(file_mode[0], file_work_level[0]);
	printf("change the mode : black list or white list \n");
	printf("sure to change the mode?  (y/n)\n");
	char option;
	scanf("%c", &option);
	if (option == 'y')
	{
		if (file_mode[0] == '0')
		{
			file_mode[0] = '1';
		}
		else
		{
			file_mode[0] = '0';
		}
		int fd = open(FILE_MODE_PATH, O_RDWR | O_CREAT, 0666);
		if (fd < 0)
		{
			printf("can't open %s \n", FILE_MODE_PATH);
			exit(1);
		}
		lseek(fd, 0, SEEK_SET);
		write(fd, file_mode, 1);
		close(fd);
		corresponding_mode_change();
		level_and_mode_show(file_mode[0], file_work_level[0]);
	}
	else
	{
		printf("cancel the change \n");
		exit(1);
	}
}

void corresponding_mode_change()
{
	int fd;
	char buf[128];
	switch (file_work_level[0])
	{
	case '1':
		strcpy(buf, FILE_MODE_PATH_1);
		break;
	case '2':
		strcpy(buf, FILE_MODE_PATH_2);
		break;
	case '3':
		strcpy(buf, FILE_MODE_PATH_3);
		break;
	case '4':
		strcpy(buf, FILE_MODE_PATH_4);
		break;
	case '5':
		strcpy(buf, FILE_MODE_PATH_5);
		break;
	default:
		printf("unpredictable fault happens! \n");
		exit(1);
	}
	fd = open(buf, O_RDWR | O_CREAT, 0666);
	if (fd < 0)
	{
		printf("can't open %s \n", buf);
		exit(1);
	}
	lseek(fd, 0, SEEK_SET);
	write(fd, file_mode, 1);
	close(fd);
}

void create_mode_file(char *file_mode_path)
{
	int fd;
	fd = open(file_mode_path, O_RDWR | O_CREAT, 0666);
	if (fd < 0)
	{
		printf("can't open %s \n", file_mode_path);
		exit(1);
	}
	char buf[24];
	if (read(fd, buf, 24) == 0)
	{
		write(fd, "0", 1);
	}
	close(fd);
}

void Create_Mode_File()
{
	// The default mode is blacklist mode
	create_mode_file(FILE_MODE_PATH_1);
	create_mode_file(FILE_MODE_PATH_2);
	create_mode_file(FILE_MODE_PATH_3);
	create_mode_file(FILE_MODE_PATH_4);
	create_mode_file(FILE_MODE_PATH_5);
}

void work_level_change()
{
	level_and_mode_show(file_mode[0], file_work_level[0]);
	printf("change the work_level: 1-5 \n");
	printf("sure to change the work_level?  (y/n)\n");
	char option;
	scanf("%c", &option);
	if (option == 'y')
	{
		printf("here are the options: \n");
		printf("1 NF_INET_PRE_ROUTING \n");
		printf("2 NF_INET_LOCAL_IN \n");
		printf("3 NF_INET_FORWARD \n");
		printf("4 NF_INET_LOCAL_OUT \n");
		printf("5 NF_INET_POST_ROUTING \n");
		printf("please input the number of the option: \n");
		char level;
		scanf("%c", &level);
		scanf("%c", &level);
		if ((level < '1') || (level > '5'))
		{
			printf("Invalid work_level! \n");
			exit(1);
		}
		file_work_level[0] = level;
		int fd = open(FILE_WORK_LEVEL_PATH, O_RDWR | O_CREAT, 0666);
		if (fd < 0)
		{
			printf("can't open %s \n", FILE_WORK_LEVEL_PATH);
			exit(1);
		}
		lseek(fd, 0, SEEK_SET);
		write(fd, file_work_level, 1);
		close(fd);
		mode_level_cover_mode();
		level_and_mode_show(file_mode[0], file_work_level[0]);
	}
	else
	{
		printf("cancel the change \n");
		exit(1);
	}
}

void clear(char *filename)
{
	if (strcmp(filename, file_path) == 0)
	{
		if (remove(filename) == 0)
		{
			int fd;
			fd = open(filename, O_RDWR | O_CREAT, 0666);
			if (fd < 0)
			{
				printf("unpredictable fault happens");
				exit(1);
			}
			if (level_check(file_work_level) == 0)
			{
				time_file_create(filename);
			}
			printf("clear the %s \n", filename);
			close(fd);
		}
		else
		{
			printf("can't clear the %s \n", filename);
		}
	}
	else
	{
		if (unlink(filename) == 0)
		{
			check_devicefile(filename);
			if (level_check(file_work_level) == 0)
			{
				time_file_create(filename);
			}
		}
		else
		{
			printf("can't clear the %s \n", filename);
		}
	}
}

void count_delete()
{
	int fd;
	char buf[128];
	fd = open(file_count_path, O_RDWR | O_CREAT, 0666);
	if (fd < 0)
	{
		printf("can't open %s \n", file_count_path);
		exit(1);
	}
	if (read(fd, buf, 128) != 0)
	{
		count = atoi(buf);
		if (count == -1)
		{
			printf("the count in %s is empty! \n", file_count_path);
			exit(1);
		}
		count--;
	}
	else
	{
		printf("the count in %s is empty! \n", file_count_path);
		exit(1);
	}
	sprintf(buf, "%d", count);
	lseek(fd, 0, SEEK_SET);
	write(fd, buf, 1);
	close(fd);
}

void count_add()
{
	int fd;
	char buf[128] = "";
	count_get();

	fd = open(file_count_path, O_RDWR | O_CREAT, 0666);

	if (fd < 0)
	{
		printf("can't open %s \n", file_count_path);
		exit(1);
	}
	if (read(fd, buf, 128) != 0)
	{
		count = atoi(buf);
		count++;
	}
	else
	{
		count = 0;
	}
	sprintf(buf, "%d", count);

	buf[strlen(buf) + 1] = '\0';
	close(fd);
	remove(file_count_path);
	fd = open(file_count_path, O_RDWR | O_CREAT, 0666);
	write(fd, buf, strlen(buf));
	close(fd);
}

void count_delete_all()
{
	int fd;
	remove(file_count_path);
	fd = open(file_count_path, O_RDWR | O_CREAT, 0666);
	if (fd < 0)
	{
		printf("can't open %s \n", file_count_path);
		exit(1);
	}
	write(fd, "-1", 2);

	close(fd);
}

void count_get()
{
	int fd;
	char buf[128];
	fd = open(file_count_path, O_RDWR | O_CREAT, 0666);
	if (fd < 0)
	{
		printf("can't open %s \n", file_count_path);
		exit(1);
	}
	if (read(fd, buf, 128) != 0)
	{
		count = atoi(buf);
	}
	else
	{
		count = -1;
	}
}

void check_out_of_number(int assignment_record)
{
	count_get(file_count_path);
	if (count < assignment_record)
	{
		printf("No such record! \n");
		exit(1);
	}
}

void check_devicefile(char *filename) // to check the state of device file
{
	struct stat buf;
	if (stat(filename, &buf) != 0)
	{
		device_file_create(file_mode[0], file_work_level[0]);
	}
}

void device_file_create(char mode, char level)
{
	if (mode == '1')
	{
		switch (level)
		{
		case '1':
			if (system("mknod /dev/controlinfo_white_1 c 124 0") == -1)
			{
				printf("Cann't create the devive file ! \n");
				printf("Please check and try again! \n");
				exit(1);
			}
			else
			{
				chmod("/dev/controlinfo_white_1", 0666);
			}
			break;
		case '2':
			if (system("mknod /dev/controlinfo_white_2 c 124 0") == -1)
			{
				printf("Cann't create the devive file ! \n");
				printf("Please check and try again! \n");
				exit(1);
			}
			else
			{
				chmod("/dev/controlinfo_white_2", 0666);
			}
			break;
		case '3':
			if (system("mknod /dev/controlinfo_white_3 c 124 0") == -1)
			{
				printf("Cann't create the devive file ! \n");
				printf("Please check and try again! \n");
				exit(1);
			}
			else
			{
				chmod("/dev/controlinfo_white_3", 0666);
			}
			break;
		case '4':
			if (system("mknod /dev/controlinfo_white_4 c 124 0") == -1)
			{
				printf("Cann't create the devive file ! \n");
				printf("Please check and try again! \n");
				exit(1);
			}
			else
			{
				chmod("/dev/controlinfo_white_4", 0666);
			}
			break;
		case '5':
			if (system("mknod /dev/controlinfo_white_5 c 124 0") == -1)
			{
				printf("Cann't create the devive file ! \n");
				printf("Please check and try again! \n");
				exit(1);
			}
			else
			{
				chmod("/dev/controlinfo_white_5", 0666);
			}
			break;
		default:
			printf("Invalid work_level! \n");
			exit(1);
		}
	}
	else
	{
		switch (level)
		{
		case '1':
			if (system("mknod /dev/controlinfo_black_1 c 124 0") == -1)
			{
				printf("Cann't create the devive file ! \n");
				printf("Please check and try again! \n");
				exit(1);
			}
			else
			{
				chmod("/dev/controlinfo_black_1", 0666);
			}
			break;
		case '2':
			if (system("mknod /dev/controlinfo_black_2 c 124 0") == -1)
			{
				printf("Cann't create the devive file ! \n");
				printf("Please check and try again! \n");
				exit(1);
			}
			else
			{
				chmod("/dev/controlinfo_black_2", 0666);
			}
			break;
		case '3':
			if (system("mknod /dev/controlinfo_black_3 c 124 0") == -1)
			{
				printf("Cann't create the devive file ! \n");
				printf("Please check and try again! \n");
				exit(1);
			}
			else
			{
				chmod("/dev/controlinfo_black_3", 0666);
			}
			break;
		case '4':
			if (system("mknod /dev/controlinfo_black_4 c 124 0") == -1)
			{
				printf("Cann't create the devive file ! \n");
				printf("Please check and try again! \n");
				exit(1);
			}
			else
			{
				chmod("/dev/controlinfo_black_4", 0666);
			}
			break;
		case '5':
			if (system("mknod /dev/controlinfo_black_5 c 124 0") == -1)
			{
				printf("Cann't create the devive file ! \n");
				printf("Please check and try again! \n");
				exit(1);
			}
			else
			{
				chmod("/dev/controlinfo_black_5", 0666);
			}
			break;
		default:
			printf("Invalid work_level! \n");
			exit(1);
		}
	}
}

void choose(char *filename, int assignment_record, char p[]) // to get certain record from filename
{
	char buf[READING_SIZE];
	int fd;
	fd = open(filename, O_RDWR | S_IRUSR | S_IWUSR);
	if (fd < 0)
	{
		printf("can't open %s \n", filename);
		exit(1);
	}
	read(fd, buf, READING_SIZE);
	char *head = buf;
	int i;
	for (i = 0; i < assignment_record; i++)
	{
		head = strchr(head, '\n');
		if (head == NULL)
		{
			break;
		}
		head++;
	}
	char *tail = strchr(head, '\n');
	int len = strlen(head) - strlen(tail);
	char s[1024];
	strncpy(s, head, len + 1);
	s[len] = '\0';
	strcpy(p, s);
}

void message_saved(int savefd, struct control_message message)
{
	write(savefd, message.controlled_protocol, strlen(message.controlled_protocol));
	write(savefd, " ", 1);
	write(savefd, message.controlled_saddr, strlen(message.controlled_saddr));
	write(savefd, " ", 1);
	write(savefd, message.controlled_daddr, strlen(message.controlled_daddr));
	write(savefd, " ", 1);
	write(savefd, message.controlled_srcport, strlen(message.controlled_srcport));
	write(savefd, " ", 1);
	write(savefd, message.controlled_dstport, strlen(message.controlled_dstport));
	write(savefd, "\n", 1);
}

void device_info_saved(int fd, char controlinfo[])
{
	write(fd, controlinfo, 4);
	write(fd, " ", 1);
	write(fd, controlinfo + 4, 4);
	write(fd, " ", 1);
	write(fd, controlinfo + 8, 4);
	write(fd, " ", 1);
	write(fd, controlinfo + 12, 4);
	write(fd, " ", 1);
	write(fd, controlinfo + 16, 4);
	write(fd, "\n", 1);
}

int getpara(int argc, char *argv[], struct control_message *message) // Parsing command line
{
	int optret;
	unsigned short tmpport;
	optret = getopt(argc, argv, "pxymn");
	while (optret != -1)
	{
		//			printf(" first in getpara: %s\n",argv[optind]);
		switch (optret)
		{
		case 'p':
			strcpy(message->controlled_protocol, argv[optind]);
			if (strncmp(argv[optind], "ping", 4) == 0)
			{
				controlled_protocol = 1;
			}
			else if (strncmp(argv[optind], "tcp", 3) == 0)
			{
				controlled_protocol = 6;
			}
			else if (strncmp(argv[optind], "udp", 3) == 0)
			{
				controlled_protocol = 17;
			}
			else
			{
				printf("Unkonwn protocol! please check and try again! \n");
				exit(1);
			}
			break;
		case 'x': // get source ipaddr
			strcpy(message->controlled_saddr, argv[optind]);
			if (inet_aton(argv[optind], (struct in_addr *)&controlled_saddr) == 0)
			{
				printf("Invalid source ip address! please check and try again! \n ");
				exit(1);
			}
			break;
		case 'y': // get destination ipaddr
			strcpy(message->controlled_daddr, argv[optind]);
			if (inet_aton(argv[optind], (struct in_addr *)&controlled_daddr) == 0)
			{
				printf("Invalid destination ip address! please check and try again! \n ");
				exit(1);
			}
			break;
		case 'm': // get source port
			strcpy(message->controlled_srcport, argv[optind]);
			tmpport = atoi(argv[optind]);
			if (tmpport == 0)
			{
				printf("Invalid source port! please check and try again! \n ");
				exit(1);
			}
			controlled_srcport = htons(tmpport);
			break;
		case 'n': // get destination ipaddr
			strcpy(message->controlled_dstport, argv[optind]);
			tmpport = atoi(argv[optind]);
			if (tmpport == 0)
			{
				printf("Invalid destination port! please check and try again! \n ");
				exit(1);
			}
			controlled_dstport = htons(tmpport);
			break;
		default:
			printf("Invalid parameters! \n ");
			display_usage(argv[0]);
			exit(1);
			;
		}
		optret = getopt(argc, argv, "pxymnh");
	}
}

void display_usage(char *commandname)
{
	printf("here are the functions and corresponding parameters: \n");
	printf("Usage of add funcion: %s -p protocol -x saddr -y daddr -m srcport -n dstport \n", commandname);
	printf("Usage of list funcion: %s -ls\n", commandname);
	printf("Usage of delete function: %s -d\n", commandname);
	printf("Usage of clear function: %s -dl \n", commandname);
	printf("Usage of help function: %s -h \n", commandname);
	printf("Usage of change mode funtion: %s -c  \n", commandname);
	printf("Usage of change work_level funtion: %s -k \n", commandname);
	printf("Usage of time stamp funtion: %s -t \n", commandname);
}

void surprise()
{
	printf("the list of the programmers: \n");
	printf("haoxin wang \n");
	printf("hanwen zhang \n");
	printf("haochen xu \n");
	printf("junjie liu \n");
	printf("yining zhang \n");
	printf("please give us a high score! we have tried our best! o(╥﹏╥)o\n");
	printf("     *    	      		     *     			     *    	      		     *     \n");
	printf("   *   *   	   		   *   *   			   *   *   	   		   *   *   \n");
	printf(" *       * 			 *       * 			 *       * 			 *       * \n");
	printf("   *   *   			   *   *   			   *   *   			   *   *   \n");
	printf("     *     			     *     			     *     			     *     \n");
}

void init()
{
	// printf("file_mode = %s\n", file_mode);
	Create_Mode_File();
	// printf("file_mode = %s\n", file_mode);
	time_file_init();

	// printf("file_mode_path = %s\n", FILE_MODE_PATH);

	int fd = open(FILE_MODE_PATH, O_RDWR | O_CREAT, 0666);
	if (fd < 0)
	{
		printf("can't open %s \n", FILE_MODE_PATH);
		exit(1);
	}
	char buf[128];
	if (read(fd, buf, 128) != 0)
	{
		strcpy(file_mode, buf);
	}
	else
	{
		strcpy(file_mode, "0"); // default mode is BLACK
		write(fd, file_mode, 1);
	}
	close(fd);

	fd = open(FILE_WORK_LEVEL_PATH, O_RDWR | O_CREAT, 0666);
	if (fd < 0)
	{
		printf("can't open %s \n", FILE_WORK_LEVEL_PATH);
		exit(1);
	}
	if (read(fd, buf, 128) != 0)
	{
		strcpy(file_work_level, buf);
	}
	else
	{
		strcpy(file_work_level, "1"); // default work_level is 1
		write(fd, file_work_level, 1);
	}

	init_path(file_mode, file_work_level);
}

void time_file_init()
{
	time_file_create(FILE_PATH_BLACK_1);
	time_file_create(FILE_PATH_WHITE_1);
	time_file_create(FILE_PATH_BLACK_5);
	time_file_create(FILE_PATH_WHITE_5);
}

void time_file_create(char *file_time_path)
{
	int fd;
	char buf[128];
	fd = open(file_time_path, O_RDWR | O_CREAT, 0666);
	if (fd < 0)
	{
		printf("can't open %s \n", file_time_path);
		exit(1);
	}
	if (read(fd, buf, 128) == 0)
	{
		write(fd, "00:00:00\n", 9);
		write(fd, "23:59:59\n", 9);
	}
	close(fd);
}

void time_function()
{
	printf("set the time stamp: \n");
	printf("only level 1 and level 5 can set the time stamp \n");
	if (level_check(file_work_level) == 0)
	{
		printf("the work_level is %s now!\n", file_work_level);
		printf("sure to set the time stamp?  (y/n)\n");
		char option;
		scanf("%c", &option);
		if (option == 'y')
		{
			scanf("%c", &option);
			struct time_message start_time_message;
			struct time_message end_time_message;
			printf("please input the start time stamp: \n");
			time_stamp_set(&start_time_message);
			printf("please input the end time stamp: \n");
			time_stamp_set(&end_time_message);
			/*
			if (time_stamp_check(start_time_message, end_time_message) == 0)
			{
				exit(1);
			}
			*/
			// time_add_device_file(start_time_message, end_time_message);
			time_add_file(start_time_message, end_time_message);
			printf("the time stamp is set successfully! \n");
		}
		else
		{
			printf("cancel the set \n");
			exit(1);
		}
	}
	else
	{
		printf("the work_level is %c, not 1 or 5, can't set the time stamp \n", file_work_level[0]);
		exit(1);
	}
}

void time_add_file(struct time_message start_time_message, struct time_message end_time_message)
{
	int fd;
	remove(file_path);
	fd = open(file_path, O_RDWR | O_CREAT, 0666);
	if (fd < 0)
	{
		printf("can't open %s \n", file_path);
		exit(1);
	}
	write(fd, start_time_message.hour, strlen(start_time_message.hour));
	write(fd, ":", 1);
	// printf("start_time_message.hour: %s \n", start_time_message.hour);
	write(fd, start_time_message.minute, strlen(start_time_message.minute));
	write(fd, ":", 1);
	// printf("start_time_message.minute: %s \n", start_time_message.minute);
	write(fd, start_time_message.second, strlen(start_time_message.second));
	// printf("start_time_message.second: %s \n", start_time_message.second);
	write(fd, "\n", 1);

	write(fd, end_time_message.hour, strlen(end_time_message.hour));
	write(fd, ":", 1);

	write(fd, end_time_message.minute, strlen(end_time_message.minute));
	write(fd, ":", 1);
	write(fd, end_time_message.second, strlen(end_time_message.second));
	write(fd, "\n", 1);
	close(fd);
}

void time_add_device_file(struct time_message start_time_message, struct time_message end_time_message)
{
	int result = unlink(device_file_path);
	check_devicefile(device_file_path);
	int fd;
	fd = open(device_file_path, O_RDWR);
	if (fd < 0)
	{
		printf("can't open %s \n", device_file_path);
		exit(1);
	}
	lseek(fd, 0, SEEK_SET);
	write(fd, start_time_message.hour, strlen(start_time_message.hour));
	write(fd, ":", 1);
	write(fd, start_time_message.minute, strlen(start_time_message.minute));
	write(fd, ":", 1);
	write(fd, start_time_message.second, strlen(start_time_message.second));
	write(fd, "\n", 1);
	write(fd, end_time_message.hour, strlen(end_time_message.hour));
	write(fd, ":", 1);
	write(fd, end_time_message.minute, strlen(end_time_message.minute));
	write(fd, ":", 1);
	write(fd, end_time_message.second, strlen(end_time_message.second));
	write(fd, "\n", 1);
	close(fd);
}

int time_stamp_check(struct time_message start_time_message, struct time_message end_time_message)
{
	int start_hour = atoi(start_time_message.hour);
	int start_minute = atoi(start_time_message.minute);
	int start_second = atoi(start_time_message.second);
	int end_hour = atoi(end_time_message.hour);
	int end_minute = atoi(end_time_message.minute);
	int end_second = atoi(end_time_message.second);
	if ((start_hour > end_hour) || ((start_hour == end_hour) && (start_minute > end_minute)) || ((start_hour == end_hour) && (start_minute == end_minute) && (start_second > end_second)))
	{
		printf("Invalid time stamp! \n");
		printf("the start time should be earlier than the end time \n");
		printf("please check and try again! \n");
		return 0;
	}
	else
	{
		return 1;
	}
}

void time_stamp_set(struct time_message *time_message)
{
	char hour[128];
	char minute[128];
	char second[128];
	printf("hour: 0-23\n");
	time_input_get("0", "23", hour);
	time_transfer(hour);
	printf("minute: 0-59\n");
	time_input_get("0", "59", minute);
	time_transfer(minute);
	printf("second: 0-59\n");
	time_input_get("0", "59", second);
	time_transfer(second);
	strcpy(time_message->hour, hour);
	strcpy(time_message->minute, minute);
	strcpy(time_message->second, second);
}

void time_transfer(char time[])
{
	int tmp = atoi(time);
	if (tmp < 10)
	{
		char buf[3];
		buf[0] = '0';
		sprintf(buf + 1, "%d", tmp);
		buf[2] = '\0';
		strcpy(time, buf);
	}
}

void time_input_get(char low[], char high[], char time[])
{
	char buf[128] = "-1";
	int input_time = 0;
	scanf("%s", buf);
	char option;
	scanf("%c", &option);
	while (time_check(low, high, buf) == 0 && input_time < 10)
	{
		scanf("%s", buf);
		scanf("%c", &option);
		input_time++;
	}
	if (input_time > 10)
	{
		printf("Invalid input! \n");
		printf("please check and try again! \n");
		exit(1);
	}
	strcpy(time, buf);
}

void mode_level_cover_mode()
{
	int fd;
	switch (file_work_level[0])
	{
	case '1':
		strcpy(file_mode_path, FILE_MODE_PATH_1);
		break;
	case '2':
		strcpy(file_mode_path, FILE_MODE_PATH_2);
		break;
	case '3':
		strcpy(file_mode_path, FILE_MODE_PATH_3);
		break;
	case '4':
		strcpy(file_mode_path, FILE_MODE_PATH_4);
		break;
	case '5':
		strcpy(file_mode_path, FILE_MODE_PATH_5);
		break;
	default:
		printf("unpredictable fault happens! \n");
		exit(1);
	}

	char buf[128];
	fd = open(file_mode_path, O_RDWR);
	if (fd < 0)
	{
		printf("can't open %s \n", file_mode_path);
		exit(1);
	}
	read(fd, buf, 1);
	file_mode[0] = buf[0];
	close(fd);

	fd = open(FILE_MODE_PATH, O_RDWR | O_CREAT, 0666);
	if (fd < 0)
	{
		printf("can't open %s \n", FILE_MODE_PATH);
		exit(1);
	}
	lseek(fd, 0, SEEK_SET);
	write(fd, file_mode, 1);
	close(fd);
}

int time_check(char low[], char high[], char time[])
{
	int min = atoi(low);
	int max = atoi(high);
	int tmp = atoi(time);
	if ((tmp >= min) && (tmp <= max))
	{
		return 1;
	}
	else
	{
		printf("Invalid time input! \n");
		printf("the time should be between %s and %s \n", low, high);
		printf("please check and try again! \n");
		return 0;
	}
}

int level_check(char work_level[])
{
	int level = atoi(work_level);
	if ((level >= 2) && (level <= 4))
	{
		return 1;
	}
	else
		return 0;
}

void init_path(char *file_mode, char *file_work_level)
{
	char option = file_mode[0];
	char level = file_work_level[0];
	if (option == '0')
	{
		switch (level)
		{
		case '1':
			strcpy(file_path, FILE_PATH_BLACK_1);
			strcpy(file_count_path, FILE_COUNT_PATH_BLACK_1);
			strcpy(device_file_path, DEVICE_FILE_PATH_BLACK_1);
			break;
		case '2':
			strcpy(file_path, FILE_PATH_BLACK_2);
			strcpy(file_count_path, FILE_COUNT_PATH_BLACK_2);
			strcpy(device_file_path, DEVICE_FILE_PATH_BLACK_2);
			break;
		case '3':
			strcpy(file_path, FILE_PATH_BLACK_3);
			strcpy(file_count_path, FILE_COUNT_PATH_BLACK_3);
			strcpy(device_file_path, DEVICE_FILE_PATH_BLACK_3);
			break;
		case '4':
			strcpy(file_path, FILE_PATH_BLACK_4);
			strcpy(file_count_path, FILE_COUNT_PATH_BLACK_4);
			strcpy(device_file_path, DEVICE_FILE_PATH_BLACK_4);
			break;
		case '5':
			strcpy(file_path, FILE_PATH_BLACK_5);
			strcpy(file_count_path, FILE_COUNT_PATH_BLACK_5);
			strcpy(device_file_path, DEVICE_FILE_PATH_BLACK_5);
			break;
		default:
			printf("Invalid work_level! \n");
			exit(1);
		}
	}
	else
	{
		switch (level)
		{
		case '1':
			strcpy(file_path, FILE_PATH_WHITE_1);
			strcpy(file_count_path, FILE_COUNT_PATH_WHITE_1);
			strcpy(device_file_path, DEVICE_FILE_PATH_WHITE_1);
			break;
		case '2':
			strcpy(file_path, FILE_PATH_WHITE_2);
			strcpy(file_count_path, FILE_COUNT_PATH_WHITE_2);
			strcpy(device_file_path, DEVICE_FILE_PATH_WHITE_2);
			break;
		case '3':
			strcpy(file_path, FILE_PATH_WHITE_3);
			strcpy(file_count_path, FILE_COUNT_PATH_WHITE_3);
			strcpy(device_file_path, DEVICE_FILE_PATH_WHITE_3);
			break;
		case '4':
			strcpy(file_path, FILE_PATH_WHITE_4);
			strcpy(file_count_path, FILE_COUNT_PATH_WHITE_4);
			strcpy(device_file_path, DEVICE_FILE_PATH_WHITE_4);
			break;
		case '5':
			strcpy(file_path, FILE_PATH_WHITE_5);
			strcpy(file_count_path, FILE_COUNT_PATH_WHITE_5);
			strcpy(device_file_path, DEVICE_FILE_PATH_WHITE_5);
			break;
		default:
			printf("Invalid work_level! \n");
			exit(1);
		}
	}
}

void level_and_mode_show(char mode, char level)
{
	char list[16];
	char work[128];
	if (mode == '0')
	{
		strcpy(list, "BLACK");
	}
	else
	{
		strcpy(list, "WHITE");
	}
	switch (level)
	{
	case '1':
		strcpy(work, "1 NF_INET_PRE_ROUTING");
		break;
	case '2':
		strcpy(work, "2 NF_INET_LOCAL_IN");
		break;
	case '3':
		strcpy(work, "3 NF_INET_FORWARD");
		break;
	case '4':
		strcpy(work, "4 NF_INET_LOCAL_OUT");
		break;
	case '5':
		strcpy(work, "5 NF_INET_POST_ROUTING");
		break;
	default:
		printf("Invalid work_level! \n");
		exit(1);
	}

	printf("the mode is %s now. \n", list);
	printf("the work_level is %s now.\n", work);
}

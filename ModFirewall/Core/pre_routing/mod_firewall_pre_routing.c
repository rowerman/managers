//#define __KERNEL__
//#define MODULE
#define __KERNEL_SYSCALLS__

#include <linux/unistd.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/udp.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/uaccess.h>
#include <asm/uaccess.h>
#include <linux/sched.h>
#include <asm/processor.h>
#include <linux/string.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <linux/module.h>
#include <linux/in.h>
#include <linux/time.h>
#define MATCH	1
#define NMATCH	0
#define PASS    1
#define NPASS   0
#define change_file "mode_1.txt"
#define rule_file_1 "file_black_1.txt"
#define rule_file_2 "file_white_1.txt"
#define MAX_BUFFER_SIZE 1024
#define READ_SIZE 4096

int enable_flag = 1;
char buf[READ_SIZE];
bool flag = 0;
struct nf_hook_ops myhook;
static struct file *fp;
struct sk_buff *tmpskb;
struct iphdr *piphdr;
char controlled_time[10] = {'0'};

//0 is black, 1 is white
int Get_signal(void)
{
    struct file *file;
    mm_segment_t old_fs;
    int ret;

    // 打开文件
    file = filp_open(change_file, O_RDONLY, 0);
    if (IS_ERR(file)) {
        printk(KERN_ERR "!!! hook_1 ljj_test Failed to open file : mode_1.txt\n");
        return PTR_ERR(file);
    }

    // 切换到内核态的文件系统访问权限
    old_fs = get_fs();
    set_fs(KERNEL_DS);

    // 读取文件内容
    ret = vfs_read(file, buf, 4096, &file->f_pos);
    if (ret < 0) {
        printk(KERN_ERR "!!! hook_1 ljj_test Failed to read file: mode_1.txt\n");

        filp_close(file, NULL);
        set_fs(old_fs);
    }

    // 切换回用户态的文件系统访问权限
    set_fs(old_fs);

    // 打印读取到的文件内容
    printk(KERN_INFO "!!! hook_1 ljj_test File mode_1.txt content: %s\n", buf);

    // 关闭文件
    filp_close(file, NULL);
    if(buf[0] == '0')
        return 0;
    else 
        return 1;
}


void pre_process(char buf[])
{
    struct file *file;
    mm_segment_t old_fs;
    int ret = 0;        //将字符串转换为int型是否成功的标识
    // 打开文件
    int flag=Get_signal();
    if(flag == 0)
    	file = filp_open(rule_file_1, O_RDONLY, 0);
    else
	    file = filp_open(rule_file_2, O_RDONLY, 0);
    if (IS_ERR(file)) {
        printk(KERN_ERR "!!! hook_1 ljj_test Failed to open file file_white(or black)_1.txt\n");
        return PTR_ERR(file);
    }

    // 切换到内核态的文件系统访问权限
    old_fs = get_fs();
    set_fs(KERNEL_DS);

    // 读取文件内容
    ret = vfs_read(file, buf, 4096, &file->f_pos);
    if (ret < 0) {
        printk(KERN_ERR "!!! hook_1 Failed to read file\n");
        filp_close(file, NULL);
        set_fs(old_fs);
    }
    char tmp[9];
    tmp[0] = buf[0];
    tmp[1] = buf[1];
    tmp[2] = buf[3];
    tmp[3] = buf[4];
    tmp[4] = buf[9];
    tmp[5] = buf[10];
    tmp[6] = buf[12];
    tmp[7] = buf[13];
    tmp[8] = '\0';
    strcpy(controlled_time, tmp);

    // 切换回用户态的文件系统访问权限
    set_fs(old_fs);
    // 打印读取到的文件内容
    // 关闭文件
    filp_close(file, NULL);
}

// 判断是否在内网网段之中
// 参数：skb - 指向网络数据包的指针
// 返回值：数据包的目的地址是否在内网网段之中，true 表示在，false 表示不在
static bool is_in_internal_network(struct sk_buff *skb)
{
    struct iphdr *iph = ip_hdr(skb);
    __be32 ip_s = iph->saddr; // 获取数据包的源IP地址
    __be32 ip_d = iph->daddr; // 获取数据包的目的IP地址
    if (
        ((ip_s & htonl(0xff000000)) == htonl(0x7f000000)) && 
        ((ip_d & htonl(0xff000000)) == htonl(0x7f000000))
        ){
        // 如果IP地址是环回地址，则不在内网网段之中
        return false;
    }

    if (
        ((ip_s & htonl(0xff000000)) == htonl(0x0a000000)) &&
        ((ip_d & htonl(0xff000000)) == htonl(0x0a000000))       
        ){
        // 如果IP地址在 10.0.0.0/8 网段之中，则在内网网段之中
        return true;
    }

    if (
        ((ip_s & htonl(0xffff0000)) == htonl(0xc0a80000)) &&
        ((ip_d & htonl(0xffff0000)) == htonl(0xc0a80000))      
        ){
        // 如果IP地址在 192.168.0.0/16 网段之中，则在内网网段之中
        return true;
    }

    if (
        ((ip_s & htonl(0xfff00000)) == htonl(0xac100000)) &&
        ((ip_d & htonl(0xfff00000)) == htonl(0xac100000))       
        ){
        // 如果IP地址在 172.16.0.0/12 网段之中，则在内网网段之中
        return true;
    }
    return false;
}

//类似库函数strftime()，将tm结构体转化为字符串
static char *time_to_str(struct tm *tm)
{
    char *str;
    int len;

    len = snprintf(NULL, 0, "%02d%02d", tm->tm_hour, tm->tm_min) + 1;
    str = kmalloc(len + 1, GFP_KERNEL);
    if (!str) {
        return NULL;
    }

    snprintf(str, len + 1, "%02d%02d", (tm->tm_hour + 8) % 24, tm->tm_min);
    return str;
}

//黑名单模式，检验时间，非工作时间禁止外网访问内网
int time_check_black(unsigned int saddr){
    struct iphdr *iph = ip_hdr(tmpskb);
    struct tm tm = {};
    char *time_str = NULL;
    ktime_t t = ktime_get_real_seconds();
    time64_to_tm(t, 0, &tm);
    if (time_str = time_to_str(&tm)) {
    	printk("!!! hook_1 ljj_test time_str: %s",time_str);
        printk("!!! hook_1 ljj_test controlled_time: %s",controlled_time);
        printk("!!! hook_1 ljj_test buf: %s",controlled_time);
        //printk("ljj_test subnet: %d", subnet_str_to_nip("112.80.248.76"));
        if( controlled_time[0] == '0' && controlled_time[1] == '0' &&
            controlled_time[2] == '0' && controlled_time[3] == '0' &&
            controlled_time[4] == '0' && controlled_time[5] == '0' &&
            controlled_time[6] == '0' && controlled_time[7] == '0'){
            if(time_str != NULL) kfree(time_str);
            printk("!!! hook_1 ljj_test info: the packet %u -> %u is accepted",iph->saddr,iph->daddr);
            return NF_ACCEPT;
        }
        else if(strncmp(controlled_time, controlled_time + 4, 4) <= 0 && strncmp(controlled_time, time_str, 4) <= 0 && strncmp(controlled_time + 4, time_str, 4) >=0 ){
            printk("!!! hook_1 ljj_test info: the packet is in the controlled_time range");
            if(time_str != NULL) kfree(time_str);
            // 判断 IP 地址是否在内网地址范围内
            if(is_in_internal_network(tmpskb)){
                printk("!!! hook_1 ljj_test info: the packet %u -> %u is accepted",iph->saddr,iph->daddr);
                return NF_ACCEPT;
            }

            else {
                printk("!!! hook_1 ljj_test info: the packet %u -> %u is dropped",iph->saddr,iph->daddr);
                return NF_DROP;
            }
        }
        else if(
            strncmp(controlled_time, controlled_time + 4, 4) >= 0 && 
            ((strncmp(controlled_time, time_str, 4) <= 0 && strncmp(time_str, "2359", 4) <=0 ) ||
            (strncmp(controlled_time + 4, time_str, 4) >= 0 && strncmp(time_str, "0000", 4) >=0))
        ){
            printk("ljj_test info: the packet is in the controlled_time range");
            if(time_str != NULL) kfree(time_str);
            // 判断 IP 地址是否在内网地址范围内
            if(is_in_internal_network(tmpskb)){
                printk("!!! hook_1 ljj_test info: the packet %u -> %u is accepted",iph->saddr,iph->daddr);
                return NF_ACCEPT;
            }

            else {
                printk("!!! hook_1 ljj_test info: the packet %u -> %u is dropped",iph->saddr,iph->daddr);
                return NF_DROP;
            }
        }

        else{
            if(time_str != NULL) kfree(time_str);
            printk("!!! hook_1 ljj_test info: the packet %u -> %u is accepted",iph->saddr,iph->daddr);
            return NF_ACCEPT;
        }
    }
    printk("!!! hook_1 ljj_test info: the packet %u -> %u is accepted",iph->saddr,iph->daddr);
    return NF_ACCEPT;

}

//检验时间，非工作时间禁止外网访问内网
int time_check_white(unsigned int saddr){
    struct iphdr *iph = ip_hdr(tmpskb);
    struct tm tm = {};
    char *time_str = NULL;
    ktime_t t = ktime_get_real_seconds();
    time64_to_tm(t, 0, &tm);
    if (time_str = time_to_str(&tm)) {
        // 在使用 time_str 之前，需要确保它不为 NULL
    	printk("!!! hook_1 ljj_test time_str: %s",time_str);
        printk("!!! hook_1 ljj_test controlled_time: %s",controlled_time);
        printk("!!! hook_1 ljj_test buf: %s",controlled_time);
        if( controlled_time[0] == '0'){
            if(time_str != NULL) kfree(time_str);
            printk("!!! hook_1 ljj_test info: the packet %u -> %u is accepted",iph->saddr,iph->daddr);
            return NF_ACCEPT;
        }
        else if(! strncmp(controlled_time, controlled_time + 4, 4) <= 0 && strncmp(controlled_time, time_str, 4) <= 0 && strncmp(controlled_time + 4, time_str, 4) >=0 ){
            printk("!!! hook_1 ljj_test info: the packet is in the controlled_time range");
            if(time_str != NULL) kfree(time_str);
            // 判断 IP 地址是否在内网地址范围内
            if(is_in_internal_network(tmpskb)){
                printk("!!! hook_1 ljj_test info: the packet %u -> %u is accepted",iph->saddr,iph->daddr);
                return NF_ACCEPT;
            }

            else {
                printk("!!! hook_1 ljj_test info: the packet %u -> %u is dropped",iph->saddr,iph->daddr);
                return NF_DROP;
            }
        }
        else if( !
            (strncmp(controlled_time, controlled_time + 4, 4) >= 0 && 
            ((strncmp(controlled_time, time_str, 4) <= 0 && strncmp(time_str, "2359", 4) <=0 ) ||
            (strncmp(controlled_time + 4, time_str, 4) >= 0 && strncmp(time_str, "0000", 4) >=0)))
        ){
            printk("!!! hook_1 ljj_test info: the packet is in the controlled_time range");
            if(time_str != NULL) kfree(time_str);
            // 判断 IP 地址是否在内网地址范围内
            if(is_in_internal_network(tmpskb)){
                printk("!!! hook_1 ljj_test info: the packet %u -> %u is accepted",iph->saddr,iph->daddr);
                return NF_ACCEPT;
            }

            else {
                printk("!!! hook_1 ljj_test info: the packet %u -> %u is dropped",iph->saddr,iph->daddr);
                return NF_DROP;
            }
        }

        else{
            if(time_str != NULL) kfree(time_str);
            printk("!!! hook_1 ljj_test info: the packet %u -> %u is accepted",iph->saddr,iph->daddr);
            return NF_ACCEPT;
        }
    }
    printk("!!! hook_1 ljj_test info: the packet %u -> %u is accepted",iph->saddr,iph->daddr);
    return NF_ACCEPT;

}


unsigned int hook_func(void * priv,struct sk_buff *skb,const struct nf_hook_state * state){

   	tmpskb = skb;
	piphdr = ip_hdr(tmpskb);

    if(flag==0)
    {
        return (time_check_black(piphdr->saddr));
    }

    if(flag==1)
    {
        return (time_check_white(piphdr->saddr));
    }

    else
    {
        printk("!!! hook_1 white_or_black_flag error! \n");
        return NF_DROP;
    }

}

static int __init initmodule(void)
{
	int ret;
    flag = Get_signal();
    pre_process(buf);
    printk("!!! hook_1 Init Module\n");
    myhook.hook=hook_func;
    myhook.hooknum=NF_INET_PRE_ROUTING;
    myhook.pf=PF_INET;
    myhook.priority=NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net,&myhook);
    return 0;
}

static void __exit cleanupmodule(void)
{
	nf_unregister_net_hook(&init_net,&myhook);
    printk("!!! hook_1 CleanUp\n");
}

module_init(initmodule);
module_exit(cleanupmodule);
MODULE_LICENSE("GPL");
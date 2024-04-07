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

#define MATCH	1
#define NMATCH	0
#define PASS    1
#define NPASS   0
#define change_file "mode_4.txt"
#define rule_file_1 "file_black_4.txt"
#define rule_file_2 "file_white_4.txt"
#define MAX_BUFFER_SIZE 1024

#define is_digit(c) ((c) >= '0' && (c) <= '9')

int enable_flag = 1;
//int white_or_black_flag=1;

#define READ_SIZE 4096

char pre_pointer[READ_SIZE];
char *pre_pointer_move = pre_pointer;
unsigned int control_protocal[100] = {0};
unsigned int control_saddr[100] = {0};
unsigned int control_daddr[100] = {0};
unsigned short control_sport[100]= {0};
unsigned short control_dport[100]= {0};

int num_of_rules=0;  //记录规则总数

int Signal;

struct nf_hook_ops myhook;

static struct file *fp;


struct sk_buff *tmpskb;
struct iphdr *piphdr;


int in4_pton(const char *src, int srclen, u8 *dst, int delim)
{
    if (srclen < 0)
    	srclen = strlen(src);
    const char *src_end = src + srclen;
    u8 *pdst = dst;
    u8 *p = pdst;
    u8 sum;
    unsigned int n;
    int len = 0;


    while (src < src_end) {
        /* Extract a number from the string */
        sum = 0;
        while (src < src_end && is_digit(*src)) {
            sum = sum * 10 + (*src - '0');
            ++src;
        }
        ++len;

        if (sum > 0xff)
            return -1;
        *p = sum;
	p++;

        if (p == pdst + 4)
            break;

        if (*src != delim)
            return -1;
        ++src;
    }

    if (len == 0 || len > 4)
        return -1;
    return p - pdst;
}

int port_convert(const char* src,unsigned short *p)
{
	char *tmp = src;
	int len = strlen(src);
	printk("len : %d",len);
	int i = 0;
	unsigned short num = 0;
	while(i<len)
	{
		num = num * 10 + (*tmp) - '0';
		i++;
		tmp++;
	}
	*p = num;
	if(num > 0)
		return 1;
	else 
		return -1;
}


int Get_signal(void )
{
    struct file *file;
    mm_segment_t old_fs;
    char buf[10] = {'\0'};
    int ret;

        // 打开文件
    file = filp_open(change_file, O_RDONLY, 0);
    if (IS_ERR(file)) {
	printk("fail fail fail!!!!");
        printk(KERN_ERR "Failed to open file_Get_signal!\n");
	long err = PTR_ERR(file);
	printk("error_num: %ld",err);
        return PTR_ERR(file);
    }

    // 切换到内核态的文件系统访问权限
    old_fs = get_fs();
    set_fs(KERNEL_DS);

    // 读取文件内容
    ret = vfs_read(file, buf, sizeof(buf), &file->f_pos);
    if (ret < 0) {
        printk(KERN_ERR "Failed to read file\n");

        filp_close(file, NULL);
        set_fs(old_fs);
    }

        // 切换回用户态的文件系统访问权限
    set_fs(old_fs);

    // 打印读取到的文件内容
    printk(KERN_INFO "File content:\n%s\n", buf);

    // 关闭文件
    filp_close(file, NULL);
    printk("mode: %s",buf);
    if(buf[0] == '0')
        return 0;
    else 
        return 1;
}



void pre_process(char pre_pointer[])
{
    struct file *file;
    mm_segment_t old_fs;
    int ret;
    //int foot_point=0;    //buf数组下角标
    int part_length = 0;   //一条规则内部每一部分的长度
    int order = 5;       
    /*当前应该处理规则的哪一部分，1代表协议类型，2代表源IP，3代表目的IP，4代表源端口，5代表目的端口
*/
    char *post_pointer = pre_pointer;
    char tem[20] = {'\0'};
    char *tmp=tem;

    long err;
    int ip_ret = 0;
    int port_ret = 0;

    u8 ip_addr[4] = {0};
    unsigned int ip_int = 0;
    unsigned short port_before;   //大小端转换前的端口号

    int flag;

        // 打开文件
    /*file = filp_open(change_file, O_RDONLY, 0);
    if (IS_ERR(file)) {
        printk(KERN_ERR "Failed to open file\n");
        err =  PTR_ERR(file);
        printk("open mode file error:%ld" ,err);
        return;
    }*/
    flag = Signal;
    if(flag == 0)    
        file = filp_open(rule_file_1, O_RDONLY, 0);
    else
        file = filp_open(rule_file_2, O_RDONLY, 0);
    if (IS_ERR(file)) {
	long err = PTR_ERR(file);
	printk("error_num: %ld",err);
        printk(KERN_ERR "Failed to open file_Get_law!_line209! \n");
        return ;
    }

    // 切换到内核态的文件系统访问权限
    old_fs = get_fs();
    set_fs(KERNEL_DS);

    // 读取文件内容
    ret = vfs_read(file, pre_pointer, READ_SIZE, &file->f_pos);
    if (ret < 0) {
        printk(KERN_ERR "Failed to read file\n");
        filp_close(file, NULL);
        set_fs(old_fs);
	return;
    }
    printk("file length: %d \n",ret);
    printk("file content: %s \n",pre_pointer);
    // 切换回用户态的文件系统访问权限
    set_fs(old_fs);

    // 打印读取到的文件内容
    //printk(KERN_INFO "File content:\n%s\n", buf);

    // 关闭文件
    filp_close(file, NULL);
    

    //while(*post_pointer != '\0')
    int i=0;
    while(i<ret)
    {
	i++;
        if(*post_pointer == '\n'|| i == ret)   //读取目的端口号
        {
            post_pointer++;
            order = 5;
            strncpy(tmp,pre_pointer_move,part_length);
	    printk("length: %d",part_length);
	    printk("dport: %s",tmp);
            port_ret = port_convert(tmp,&port_before);
	    printk("dport_before:%hu",port_before);

            if(port_ret < 0)
            {
                printk("port conversion failed! \n");
            }
            control_dport[num_of_rules] = cpu_to_be16(port_before); //大小端转换
            printk("input dport:%hu \n",control_dport[num_of_rules]);
            part_length = 0;
            num_of_rules++;
            pre_pointer_move = post_pointer;
	    memset(tem,'\0',20);
        }

        else if(*post_pointer == ' ')
        {
            if(order == 5)
            {
                order = 1;
                post_pointer++;
                strncpy(tmp,pre_pointer_move,part_length);
		printk("length: %d",part_length);
	        printk("tmp: %s",tmp);
                switch (tmp[0])
                {
                case 'p':
                    control_protocal[num_of_rules] = 1;
		            printk("input protocol: %d \n",control_protocal[num_of_rules]);
                    break;
                case 't':
                    control_protocal[num_of_rules] = 6;
                    printk("input protocol: %d \n",control_protocal[num_of_rules]);
                    break;
                case 'u':
                    control_protocal[num_of_rules] = 17;
                    printk("input protocol: %d \n",control_protocal[num_of_rules]);
                    break;
                }
                part_length = 0;
                pre_pointer_move = post_pointer; 
		memset(tem,'\0',20);             
            }

            else if(order == 1)
            {
                order = 2;
                post_pointer++;
                strncpy(tmp,pre_pointer_move,part_length);
		printk("length: %d",part_length);
		//printk("the length of tmp: %d",strlen(tmp));
		//tmp = "192.168.128.128";
                ip_ret = in4_pton(tmp, strlen(tmp), ip_addr,'.');
		//printk("ip_addr: %u.%u.%u.%u \n",ip_addr[0],ip_addr[1],ip_addr[2],ip_addr[3]);
                if(ip_ret <= 0)
                {
                    printk("ip conversion error! \n");
		    //return;
                }
                //ip_int = (ip_addr[0] << 24) | (ip_addr[1] << 16) | (ip_addr[2] << 8) | ip_addr[3];
                ip_int = (ip_addr[3] << 24) | (ip_addr[2] << 16) | (ip_addr[1] << 8) | ip_addr[0];
                printk("input saddr: %u \n ",ip_int);

                control_saddr[num_of_rules] = ip_int;
                part_length = 0;
                pre_pointer_move = post_pointer;
		memset(tem,'\0',20);
            }

            else if(order == 2)
            {
                order = 3;
                post_pointer++;
                strncpy(tmp,pre_pointer_move,part_length);
		printk("length: %d",part_length);
                ip_ret = in4_pton(tmp,strlen(tmp), ip_addr, '.');
                if(ip_ret <= 0)
                {
                    printk("ip conversion error! \n");
                    //return;
                }
                //ip_int = (ip_addr[0] << 24) | (ip_addr[1] << 16) | (ip_addr[2] << 8) | ip_addr[3];
                ip_int = (ip_addr[3] << 24) | (ip_addr[2] << 16) | (ip_addr[1] << 8) | ip_addr[0];
                printk("input daddr: %u \n ",ip_int);

                control_daddr[num_of_rules] = ip_int;
                part_length = 0;
                pre_pointer_move = post_pointer;
		memset(tem,'\0',20);
            }

            else if(order == 3)
            {
                post_pointer++;
                order = 4;
                strncpy(tmp,pre_pointer_move,part_length);
		printk("length: %d",part_length);
		printk("sport: %s",tmp);
                port_ret = port_convert(tmp,&port_before);    //字符串变为unsigned int
		printk("sport_before:%hu",port_before);
                if(port_ret < 0)
                {
                    printk("port conversion failed! \n");
                }
                control_sport[num_of_rules] = cpu_to_be16(port_before); //大小端转换
                printk("input sport:%hu \n",control_sport[num_of_rules]);
                part_length = 0;
                pre_pointer_move = post_pointer;
		memset(tem,'\0',20);
            }
        }
        else
        {
	    //printk("current char: %d",*post_pointer);
	   // printk("head char: %d",*pre_pointer_move);
	   // printk("part_length: %d",part_length);
            post_pointer++;
	    part_length++;
        }
    }
}


/*int local_out_port_check_black(unsigned short dstport)
{
    int i;
    for(i=0;i<num_of_rules;i++)
    {
        if(control_dport[i]==0)
        {
            printk("local_out_port_check_black droped because no port was offered");
        }
        else if(control_dport[i] == dstport)
            {
                printk("local_out_port_check_black droped because the port was matched");
                return MATCH;
            }
            else
            {
                printk("local_out_port_check accepted because the port was not matched");
            }
    }
    return NMATCH;
}*/

int local_out_ip_check_black(unsigned int daddr,int num_of_rules)
{
    int i;
    int droped_ip[100] = {0};
    printk("get black dest ip: %u",daddr);
    printk("stored black desr ip: %u",control_daddr[0]);
    for(i=0;i<num_of_rules;i++)
    {
        if(control_daddr[i] == 0)
        {
            printk("local_out_port_check_black accpeded because no ipaddr was offered");
        }
        else if(control_daddr[i] == daddr)
            {
                printk("local_out_port_check_black droped because the ipaddr was matched");
		droped_ip[i] = 1;
            }
            else 
            {
                printk("local_out_port_check accepted because the ipaddr was not matched");
            }
    }

    for(i=0;i<num_of_rules;i++)
    {
	if(droped_ip[i] == 1);
	   return MATCH;
    }

    return NMATCH;
}

int local_out_ip_check_white(unsigned int daddr,int num_of_rules)
{
    int i;
    int droped_ip[100] = {0};
    printk("get white dest ip: %u",daddr);
    printk("stored white desr ip: %u",control_daddr[0]);
    for(i=0;i<num_of_rules;i++)
    {
        if(control_daddr[i] !=0)
            if(control_daddr[i] == daddr)
            {
                printk("local_out_port_check_white accepted because the ipaddr was matched");
		droped_ip[i] = 1;
            }
            else 
            {
                printk("local_out_port_check_white accepted because the ipaddr was not matched");
            }
        else 
        {
            printk("local_out_port_check_white droped because no ipaddr was offered");
        }
    }
    
    for(i=0;i<num_of_rules;i++)
    {
	if(droped_ip[i] == 1);
	   return PASS;
    }
    return NPASS;
}




/*int ipaddr_check(unsigned int saddr, unsigned int daddr){
	if ((controlled_saddr == 0 ) && ( controlled_daddr == 0 ))
		return MATCH;
	if ((controlled_saddr != 0 ) && ( controlled_daddr == 0 ))
	{
		if (controlled_saddr == saddr) // ڰ      У if (controlled_saddr == saddr||con)
			return MATCH;
		else
			return NMATCH;
	}
	if ((controlled_saddr == 0 ) && ( controlled_daddr != 0 ))
	{
		if (controlled_daddr == daddr)
			return MATCH;
		else
			return NMATCH;
	}
	if ((controlled_saddr != 0 ) && ( controlled_daddr != 0 ))
	{
		if ((controlled_saddr == saddr) && (controlled_daddr == daddr))
			return MATCH;
		else
			return NMATCH;
	}
	return NMATCH;
}*/



/*int port_check_white(unsigned short srcport, unsigned short dstport)
{
    if ((controlled_srcport != 0 ) && ( controlled_dstport != 0 ))      //  Ч             뽫Դ  Ŀ 궼       
    {
        if(((controlled_srcport == srcport) && (controlled_dstport == dstport))||((controlled_srcport == dstport) && (controlled_dstport == srcport)))
            return PASS;
        else
            return NPASS;
    }
    else
    {
        printk("The port_check return NPASS due to incomplete order! flag=1 white \n");
        return NPASS;
    }

}*/

/*int port_check_white_simplified(unsigned short srcport, unsigned short dstport)
{
    return PASS;
}*/


/*int ipaddr_check_white(unsigned int saddr, unsigned int daddr)
{
    if ((controlled_saddr != 0 ) && ( controlled_daddr != 0 ))      //  Ч             뽫Դ  Ŀ 궼       
    {
        if(((controlled_saddr == saddr) && (controlled_daddr == daddr))||((controlled_saddr == daddr) && (controlled_daddr == saddr)))
            return PASS;
        else
            return NPASS;
    }
    else
    {
        printk("The ipaddr_check return NPASS due to incomplete order! flag=1 white \n");
        return NPASS;
    }

}*/


/*int ipaddr_check_white_simplified(unsigned int saddr, unsigned int daddr)
{
    return ipaddr_check_white(saddr,daddr);
}*/

int local_out_check_black(unsigned int daddr,unsigned short dstport,int num_of_rules)
{
    int droped_ip[100] = {0};
    int droped_port[100] = {0};

    int i;
    printk("get black dest ip: %u",daddr);
    printk("stored black dest ip: %u",control_daddr[0]);
    printk("get black dest port: %hu ",dstport);
    printk("stored black dest port: %hu",control_dport[0]);

    //端口检验
    for(i=0;i<num_of_rules;i++)
    {
        if(control_dport[i]==0)  //黑名单下，端口为0应默认放行
        {
            printk("local_out_port_check_black accepted because no port was offered");
        }
        else if(control_dport[i] == dstport)
            {
                printk("local_out_port_check_black droped because the port was matched");
                droped_port[i] = 1;
            }
            else
            {
                printk("local_out_port_check accepted because the port was not matched");
            }

        if(control_daddr[i] == 0)
        {
            printk("local_out_ip_check_black accepted because no ip was offered");
        }
        else if(control_daddr[i] == daddr)
            {
                printk("local_out_ip_check_black droped because the ip was matched");
                droped_ip[i] = 1;
            }
            else
            {
                printk("local_out_port_check accepted because the ip was not matched");
            }
    }

    for(i=0;i<num_of_rules;i++)
    {
        if(droped_ip[i] == 1 && droped_port[i] == 1)
	    {
	    printk("the package was droped!!!!!!!");
            return MATCH;
	    }
    }
    printk("the package was accepted!!!!");
    return NMATCH;
}

int local_out_check_white(unsigned int daddr,int num_of_rules)
{
    int droped_ip[100] = {0};   //0代表PASS，1代表NPASS

    int i;
    printk("get white dest ip: %u",daddr);

    for(i=0;i<num_of_rules;i++)
    {
        if(control_daddr[i]==0)  //白名单下，端口为0应默认丢弃
        {
            printk("local_out_port_check_white dropped because no port was offered");
            droped_ip[i] = 1;
        }
        else if(control_daddr[i] == daddr)
            {
                printk("local_out_address_check_white accepted because the port was matched");
            }
            else
            {
                printk("local_out_port_white dropped because the port was not matched");
                droped_ip[i] = 1;
            }

    }

    for(i=0;i<num_of_rules;i++)
    {
        if(droped_ip[i] == 0)
            return PASS;
    }
    return NPASS;
}

int icmp_check(void)
{
   struct icmphdr *picmphdr;
   picmphdr = (struct icmphdr *)(tmpskb->data +(piphdr->ihl*4));

    if(!Signal)   //black module
    {
        if (picmphdr->type == 0)
        {
            if (local_out_ip_check_black(piphdr->saddr,num_of_rules) == MATCH)
            {
                printk("black module, an ICMP packet is denied! \n");
                return NF_DROP;
            }
        }
        if (picmphdr->type == 8){
            if (local_out_ip_check_black(piphdr->daddr,num_of_rules) == MATCH)
            {
                printk("black module, an ICMP packet is denied! \n");
                return NF_DROP;
            }
        }
        return NF_ACCEPT;
    }

    else if(Signal)
    {
        if (picmphdr->type == 0)
        {
            if ( local_out_ip_check_white(piphdr->saddr,num_of_rules) == NPASS)
            {
                printk("white module, an ICMP packet is denied! \n");
                return NF_DROP;
            }
        }
        if (picmphdr->type == 8){
            if ( local_out_ip_check_white(piphdr->daddr,num_of_rules) == NPASS)
            {
                printk("white module, an ICMP packet is denied! \n");
                return NF_DROP;
            }
        }
        return NF_ACCEPT;
    }

    else
    {
        printk("white_or_black_flag error! \n");
        return -1;
    }

}

int tcp_check(void){
	struct tcphdr *ptcphdr;
//   printk("<0>This is an tcp packet.\n");
   ptcphdr = (struct tcphdr *)(tmpskb->data +(piphdr->ihl*4));


   if(!Signal)
   {
	if(local_out_check_black(piphdr->daddr,ptcphdr->dest,num_of_rules))
        {
            printk("black module, a TCP packet is denied! \n");
            return NF_DROP;
        }
        else
            return NF_ACCEPT;
   }


   else if(Signal)
   {
       if (local_out_check_white(piphdr->daddr,num_of_rules) == PASS)
       {
           printk("white module, a TCP packet is accepted! \n");
           return NF_ACCEPT;
       }
       else
       {
           printk("white module, a TCP packet is denied! \n");
           return NF_DROP;
       }
   }

    else
    {
        printk("white_or_black_flag error! \n");
        return -1;
    }
}

int udp_check(void){
	struct udphdr *pudphdr;
//   printk("<0>This is an udp packet.\n");
   pudphdr = (struct udphdr *)(tmpskb->data +(piphdr->ihl*4));


   if(!Signal)
    {
	if(local_out_check_black(piphdr->daddr,pudphdr->dest,num_of_rules))
        {
            printk("black module, a UDP packet is denied! \n");
            return NF_DROP;
        }
        else
            return NF_ACCEPT;
    }


    else if(Signal)
    {
       if (local_out_check_white(piphdr->daddr,num_of_rules) == PASS)
        {
            printk("white module, a UDP packet is accepted! \n");
            return NF_ACCEPT;
        }
        else
        {
            printk("white module, a UDP packet is denied! \n");
            return NF_DROP;
        }
    }

    else
    {
        printk("white_or_black_flag error! \n");
        return -1;
    }
}

/*unsigned int hook_func(unsigned int hooknum,struct sk_buff **skb,const struct net_device *in,const struct net_device *out,int (*okfn)(struct sk_buff *))
*/
unsigned int hook_func(void * priv,struct sk_buff *skb,const struct nf_hook_state * state){

	/*if (enable_flag == 0)
		return NF_ACCEPT;*/  
   	tmpskb = skb;
	piphdr = ip_hdr(tmpskb);
	int i;

        for(i=0;i<num_of_rules;i++)
        {
        if(piphdr->protocol != control_protocal[i])
            return NF_ACCEPT;                       
        if (piphdr->protocol  == 1)  //ICMP packet
            return icmp_check();
        else if (piphdr->protocol  == 6) //TCP packet
            return tcp_check();
        else if (piphdr->protocol  == 17) //UDP packet
            return udp_check();
        }
	return NF_ACCEPT;
}

/*static ssize_t write_controlinfo(struct file * fd, const char __user *buf, size_t len, loff_t *ppos)
{
	char controlinfo[128];
	char *pchar;

	pchar = controlinfo;

	if (len == 0){
		enable_flag = 0;
		return len;
	}

	if (copy_from_user(controlinfo, buf, len) != 0){
		printk("Can't get the control rule! \n");
		printk("Something may be wrong, please check it! \n");
		return 0;
	}
	controlled_protocol = *(( int *) pchar);
	pchar = pchar + 4;
	controlled_saddr = *(( int *) pchar);
	pchar = pchar + 4;
	controlled_daddr = *(( int *) pchar);
	pchar = pchar + 4;
	controlled_srcport = *(( int *) pchar);
	pchar = pchar + 4;
	controlled_dstport = *(( int *) pchar);

	/*enable_flag = 1;
	printk("input info: p = %d, x = %d y = %d m = %d n = %d \n", controlled_protocol,controlled_saddr,controlled_daddr,controlled_srcport,controlled_dstport);*/
	/*return len;
}*/


/*struct file_operations fops = {
	.owner=THIS_MODULE,
	.write=write_controlinfo,
};*/


static int __init initmodule(void)
{
    if(Get_signal())
	Signal = 1;
    else
	Signal = 0; 
    pre_process(pre_pointer);
    printk("Init Module\n");
    myhook.hook=hook_func;
    myhook.hooknum=NF_INET_LOCAL_OUT;
    myhook.pf=PF_INET;
    myhook.priority=NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net,&myhook);

    //加上读取mode文件再注册设备文件的逻辑
        //ret = register_chrdev(127, "dev/controlinfo_black_4", &fops); 
		
        //ret = register_chrdev(127, "dev/controlinfo_white_4", &fops);
    //if (ret != 0) printk("Can't register device file! \n");

    return 0;
}

static void __exit cleanupmodule(void)
{
	nf_unregister_net_hook(&init_net,&myhook);
    printk("CleanUp\n");
}

module_init(initmodule);
module_exit(cleanupmodule);
MODULE_LICENSE("GPL");

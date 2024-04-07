import sys
import time
import snmp_cmds
from pysnmp.hlapi import *
from pysnmp.entity import engine, config
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity.rfc3413 import ntfrcv

TIMEOUT = 100

trap_info = {"1.3.6.1.2.1.1.3.0": "",
			 "1.3.6.1.6.3.1.1.4.1.0": "",
			 "1.3.6.1.6.3.18.1.3.0": "",
			 "1.3.6.1.6.3.18.1.4.0": "",
			 "1.3.6.1.6.3.1.1.4.3.0": ""}


def GetByOid(des_ip, oid):
	try:
		res = snmp_cmds.snmpwalk(des_ip, oid, 'public', 161, TIMEOUT)
		return [varBind for varBind in res]
	except:
		return "connect error"


# res = GetByOid("192.168.11.128", ".1.3.6.1.2.1.1.6")
# print(res[0][0])
# print(res[0][1])


def SetByOid(des_ip, oid, value, type):
	try:
		types = {"integer": 'i',
				 "unsigned_integer": 'u',
				 "time_ticks": 't',
				 "ip_address": 'a',
				 "object_identifier": 'o',
				 "string": 's',
				 "hex_string": 'x',
				 "decimal_string": 'd',
				 "bit_string": 'b'}
		type_index = types[type]
		res = snmp_cmds.snmpset(des_ip, oid, type_index, value, 'public', 161, TIMEOUT)
		return res
	except:
		return "NoChangable!"



def sendTrap(des_ip, oid, oid_extra, value):
	try:
		# sendNotification函数用来发送SNMP消息，包括trap和inform
		errorIndication, errorStatus, errorIndex, varBinds = next(
			sendNotification(
				SnmpEngine(),
				CommunityData('public'),
				UdpTransportTarget((des_ip, 162)),
				ContextData(),
				'trap',
				NotificationType(
					ObjectIdentity(oid)
				).addVarBinds(
					(oid_extra, OctetString(value))
				)
			)
		)
		
		if errorIndication:
			print('Notification not sent: %s' % errorIndication)
			return errorStatus, errorIndex
	except:
		return "send error"

# res = sendTrap("192.168.11.128",".1.3.6.1.2.1.1.5.0",".1.3.6.1.2.1.1.5.0",666)
# print(res)

class TrapListener:
	def __init__(self, external_function):
		self.trap_info = {
            "1.3.6.1.2.1.1.3.0": "",		# 超时时间
            "1.3.6.1.6.3.1.1.4.1.0": "",	# trapOid
            "1.3.6.1.6.3.18.1.3.0": "",		# IP
            "1.3.6.1.6.3.18.1.4.0": "",		# community
            "1.3.6.1.6.3.1.1.4.3.0": ""		# trapType
        }
		self.snmpEngine = SnmpEngine()
		self.external_function = external_function

	def cbFun(self, snmpEngine, stateReference, contextEngineId, contextName, varBinds, cbCtx):
		for name, val in varBinds:
			self.trap_info[name.prettyPrint()] = val.prettyPrint()
		self.external_function(self.trap_info)
		# .0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000.
		
	def listenTrap(self):
		config.addTransport(
			self.snmpEngine,
			udp.domainName,
			udp.UdpTransport().openServerMode(('0.0.0.0', 162))
		)
		config.addV1System(self.snmpEngine, 'my-area', 'public')
		ntfrcv.NotificationReceiver(self.snmpEngine, self.cbFun)
		self.snmpEngine.transportDispatcher.jobStarted(1)
		try:
			self.snmpEngine.transportDispatcher.runDispatcher()
		except:
			self.snmpEngine.transportDispatcher.closeDispatcher()
			raise
	
	def getTrapInfo(self):
		return self.trap_info

def monitor_cpu(des_ip):
	try:
		res = snmp_cmds.snmpwalk(des_ip, '.1.3.6.1.4.1.2021.11.11.0', 'public', 161, TIMEOUT)
		return 100 - int(res[0][1])
	except:
		return "connect error"

def monitor_RAM(des_ip):
	# 获取内存使用量
	res1 = GetByOid(des_ip, '.1.3.6.1.4.1.2021.4.6.0')
	if isinstance(res1, str):
		return "get memory error"
	# 获取内存总量
	res2 = GetByOid(des_ip, '.1.3.6.1.4.1.2021.4.5.0')
	if isinstance(res2, str):
		return "get memory error"
	
	# 计算内存利用率
	if isinstance(res1, str) or isinstance(res2, str):
		return "calculate error"
	else:
		res1_value = float(res1[0][1].replace(' kB', ''))
		res2_value = float(res2[0][1].replace(' kB', ''))
		return res1_value / res2_value
	
res = monitor_RAM("192.168.11.128")
print(res)

def monitor_disk(des_ip):
	# 获取所有分区的总容量
	total_space = 0
	res1 = GetByOid(des_ip, '.1.3.6.1.2.1.25.2.3.1.5')
	if isinstance(res1, str):
		return "connect error"
	else:
		for varBind in res1:
			total_space += float(varBind[1].replace(' kB', ''))
	
	# 获取所有分区的总使用量
	total_used = 0
	res2 = GetByOid(des_ip, '.1.3.6.1.2.1.25.2.3.1.6')
	if isinstance(res2, str):
		return "connect error"
	else:
		for varBind in res2:
			total_used += float(varBind[1].replace(' kB', ''))
	
	# 计算磁盘使用率
	if isinstance(res1, str) or isinstance(res2, str):
		return "calculate error"
	else:
		return total_used / total_space
	
res = monitor_disk("192.168.11.128")
print(res)


def monitor_MAC(des_ip):
	# MAC地址
	res = GetByOid(des_ip, '.1.3.6.1.2.1.2.2.1.6')
	if isinstance(res, str):
		return "connect error"
	else:
		return res


def get_bytes(ip, oid):
	try:
		results = snmp_cmds.snmpwalk(ip, oid, 'public', 161, 2)
		total_bytes = sum(int(result[1]) for result in results)
		return total_bytes
	except:
		return "Connection error"


def monitor_net(des_ip):
	# 获取初始的发送和接收字节数
	initial_received_bytes = get_bytes(des_ip, '.1.3.6.1.2.1.2.2.1.10')
	initial_sent_bytes = get_bytes(des_ip, '.1.3.6.1.2.1.2.2.1.16')
	
	# 等待一段时间（例如5分钟）
	time.sleep(2)
	
	# 获取5分钟后的发送和接收字节数
	final_received_bytes = get_bytes(des_ip, '.1.3.6.1.2.1.2.2.1.10')
	final_sent_bytes = get_bytes(des_ip, '.1.3.6.1.2.1.2.2.1.16')
	
	# 计算网络流量
	if isinstance(initial_received_bytes, str) or isinstance(final_received_bytes, str):
		return "Error calculating received traffic"
	else:
		received_traffic = final_received_bytes - initial_received_bytes
	
	if isinstance(initial_sent_bytes, str) or isinstance(final_sent_bytes, str):
		return "Error calculating sent traffic"
	else:
		sent_traffic = final_sent_bytes - initial_sent_bytes
	
	if not isinstance(received_traffic, str) and not isinstance(sent_traffic, str):
		total_traffic = received_traffic + sent_traffic
	
	return received_traffic, sent_traffic, total_traffic

# r1,r2,r3 = monitor_net("192.168.11.128")
# print(r1)
# print(r2)
# print(r3)

def warn_cpu(des_ip, warn_level):
	warn_level = int(warn_level)
	res = monitor_cpu(des_ip)
	if int(res) > warn_level:
		return False
	time.sleep(1)
	return True


def warn_memory(des_ip, warn_level):
	warn_level = int(warn_level)

	res = monitor_RAM(des_ip)
	if res > warn_level:
		return False
	time.sleep(1)
	return True


def warn_disk(des_ip, warn_level):
	warn_level = int(warn_level)

	res = monitor_disk(des_ip)
	if res > warn_level:
		return False
	time.sleep(1)
	return True

def start_monitor_state(des_ip):
	while 1:
		try:
			cpu_state = monitor_cpu(des_ip)
			RAM_state = monitor_RAM(des_ip)
			disk_state = monitor_disk(des_ip)
			download_state, upload_state, total_state = monitor_net(des_ip)
			state_packet = {"cpu_state":cpu_state, "RAM_state":RAM_state, "disk_state":disk_state,
							"download_state":download_state, "upload_state":upload_state, "total_state":total_state}
			send_state_packet(state_packet)
		except:
			raise ValueError("ip wrong!")
		
		time.sleep(3)

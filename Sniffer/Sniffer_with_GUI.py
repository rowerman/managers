import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTableWidget, QVBoxLayout, QWidget,
    QPushButton, QHBoxLayout, QTableWidgetItem, QDialog, QButtonGroup,
    QRadioButton, QLabel, QHeaderView, QTextEdit, QMessageBox, QLineEdit, QFileDialog
)
from PyQt5.QtGui import QColor
from PyQt5.QtCore import pyqtSignal, pyqtSlot, QObject, Qt
from scapy.all import *
from threading import Thread, Lock
from datetime import datetime

# 全局变量来控制嗅探线程
sniffer_thread = None
sniffing = False
iface = "ens33"  # 默认接口
frags = {}  # 用于存储分片数据的全局字典
frag_lock = Lock()  # 创建一个线程锁

# 定义协议颜色映射
protocol_colors = {
    'IP': 'lightgrey',
    'IPv6': 'lightyellow',  # 新增IPv6的颜色
    'TCP': 'lightblue',
    'UDP': 'lightgreen',
    'ICMP': 'lightcoral',
    'ARP': 'wheat',
    'Fragmented': 'plum',  # IP分片的数据包颜色
    'Defragmented': 'violet',  # IP分片重组后的数据包颜色
    'Other': 'white'  # 其它协议或信息
}

class PacketInfoEmitter(QObject):
    packet_info_signal = pyqtSignal(str, str, str, str, str, str, Packet)
    packet_info_signal_zero = pyqtSignal(str, str, str, str, str, str)

class FilterWindow(QDialog):
    def __init__(self, parent=None):
        super(FilterWindow, self).__init__(parent)
        self.setWindowTitle('Filter Packets')
        self.selected_protocol = None
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()
        self.button_group = QButtonGroup(self)
        # Create a radio button for each protocol including IPv6
        for protocol in ['IP', 'IPv6', 'ARP', 'ICMP', 'TCP', 'UDP']:  # 新增IPv6
            button = QRadioButton(protocol)
            self.button_group.addButton(button)
            layout.addWidget(button)
        # Add a button to apply the filter
        self.filter_button = QPushButton('Apply Filter')
        self.filter_button.clicked.connect(self.apply_filter)
        layout.addWidget(self.filter_button)
        self.setLayout(layout)
    
    def apply_filter(self):
        selected_button = self.button_group.checkedButton()
        if selected_button:
            self.selected_protocol = selected_button.text()
            self.accept()  # Closes the dialog and sets result to QDialog.Accepted

    def get_selected_protocol(self):
        return self.selected_protocol

class InterfaceSelectionWindow(QDialog):
    def __init__(self, parent=None):
        super(InterfaceSelectionWindow, self).__init__(parent)
        self.setWindowTitle('Select Network Interface')
        self.selected_interface = None
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()
        self.button_group = QButtonGroup(self)
        # Create a radio button for each interface
        for interface in ['ens33', 'lo']:
            button = QRadioButton(interface)
            self.button_group.addButton(button)
            layout.addWidget(button)
        # Add a button to apply the selection
        self.select_button = QPushButton('Select Interface')
        self.select_button.clicked.connect(self.apply_selection)
        layout.addWidget(self.select_button)
        self.setLayout(layout)

    def apply_selection(self):
        selected_button = self.button_group.checkedButton()
        if selected_button:
            self.selected_interface = selected_button.text()
            self.accept()  # Closes the dialog and sets result to QDialog.Accepted

    def get_selected_interface(self):
        return self.selected_interface

class SnifferGUI(QMainWindow):
    
    current_filter_protocol = None  
    
    def __init__(self, packet_info_emitter):
        super().__init__()
        self.packet_info_emitter = packet_info_emitter
        self.initUI()
        self.packet_info_emitter.packet_info_signal.connect(self.update_packet_display)
        self.sniffer_thread = None
        self.packets = []  # 用于存储捕获的数据包列表
    
    def initUI(self):
        
        self.tableWidget = QTableWidget()
        self.tableWidget.setColumnCount(5)  # 设置列数为5
        self.tableWidget.setHorizontalHeaderLabels(['Time', 'Source', 'Destination', 'Protocol', 'Info'])  # 设置列标题
        self.tableWidget.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tableWidget.setEditTriggers(QTableWidget.NoEditTriggers)  # 设置表格不可编辑
        self.tableWidget.setSelectionBehavior(QTableWidget.SelectRows)  # 设置整行选中的行为

        # 创建按钮并设置布局
        self.startButton = QPushButton('Start Sniffing')
        self.stopButton = QPushButton('Stop Sniffing')
        self.filterButton = QPushButton('Filter Packets')  # 新增过滤按钮
        self.interfaceButton = QPushButton('Select Interface')  # 新增网卡选择按钮

        self.stopButton.setEnabled(False)  # 初始时停止按钮不可用
        self.startButton.clicked.connect(self.start_sniffing)
        self.stopButton.clicked.connect(self.stop_sniffing)
        self.filterButton.clicked.connect(self.open_filter_window)  # 连接过滤按钮的点击事件
        self.interfaceButton.clicked.connect(self.open_interface_window)  # 连接网卡选择按钮的点击事件

        buttonLayout = QHBoxLayout()
        buttonLayout.addWidget(self.startButton)
        buttonLayout.addWidget(self.stopButton)
        buttonLayout.addWidget(self.filterButton)
        buttonLayout.addWidget(self.interfaceButton)  # 将网卡选择按钮添加到布局中

        # 新增一个输出栏，用于显示详细的数据包信息
        self.outputTextEdit = QTextEdit()
        self.outputTextEdit.setReadOnly(True)  # 设置为只读，不允许编辑

        centralWidget = QWidget()
        self.setCentralWidget(centralWidget)
        layout = QVBoxLayout()
        layout.addLayout(buttonLayout)
        layout.addWidget(self.tableWidget)  # 添加QTableWidget到布局中
        layout.addWidget(self.outputTextEdit)  # 添加输出栏到布局中
        centralWidget.setLayout(layout)

        self.setGeometry(100, 100, 1000, 800)  # 窗口大小调整为更大
        self.setWindowTitle('Packet Sniffer')
        self.tableWidget.clicked.connect(self.on_table_item_selection_changed)  # 连接表格选择改变事件
        self.show()


        # 新增搜索文本框和按钮
        self.srcIPSearchLineEdit = QLineEdit()
        self.srcIPSearchButton = QPushButton('Search by Source IP')
        self.dstIPSearchLineEdit = QLineEdit()
        self.dstIPSearchButton = QPushButton('Search by Destination IP')

        # 新增导出按钮
        self.exportButton = QPushButton('Export Packets')

        # 连接搜索按钮的点击事件
        self.srcIPSearchButton.clicked.connect(self.search_by_source_ip)
        self.dstIPSearchButton.clicked.connect(self.search_by_destination_ip)

        # 连接导出按钮的点击事件
        self.exportButton.clicked.connect(self.export_packets)

        # 搜索和导出按钮布局
        searchExportLayout = QHBoxLayout()
        searchExportLayout.addWidget(QLabel('Source IP:'))
        searchExportLayout.addWidget(self.srcIPSearchLineEdit)
        searchExportLayout.addWidget(self.srcIPSearchButton)
        searchExportLayout.addWidget(QLabel('Destination IP:'))
        searchExportLayout.addWidget(self.dstIPSearchLineEdit)
        searchExportLayout.addWidget(self.dstIPSearchButton)
        searchExportLayout.addWidget(self.exportButton)

        # 创建按钮并设置布局
        # 省略原有的按钮创建代码...

        # 将搜索和导出布局添加到主布局中
        layout.addLayout(searchExportLayout)


    def search_by_source_ip(self):
        src_ip = self.srcIPSearchLineEdit.text().strip()
        self.filter_packets(lambda packet: IP in packet and packet[IP].src == src_ip)

    def search_by_destination_ip(self):
        dst_ip = self.dstIPSearchLineEdit.text().strip()
        self.filter_packets(lambda packet: IP in packet and packet[IP].dst == dst_ip)

    def filter_packets(self, filter_func):
        # 用于根据提供的过滤函数更新表格
        self.tableWidget.setRowCount(0)
        for packet in self.packets:
            if filter_func(packet):
                # 这里添加数据到表格...
                pass

    def export_packets(self):
        # 获取用户指定的文件名
        filename, _ = QFileDialog.getSaveFileName(self, 'Save Packets', '', 'PCAP Files (*.pcap);;All Files (*)')
        if filename:
            # 将数据包写入到指定的文件中
            wrpcap(filename, self.packets)
            QMessageBox.information(self, 'Export Successful', f'Packets have been exported to {filename}.')

    def open_interface_window(self):
        interface_window = InterfaceSelectionWindow(self)
        if interface_window.exec_():
            selected_interface = interface_window.get_selected_interface()
            if selected_interface:
                global iface
                iface = selected_interface
                QMessageBox.information(self, "Interface Selected", f"Selected interface: {iface}")

    def on_table_item_selection_changed(self):
        selected_items = self.tableWidget.selectedItems()
        if selected_items:
            row_index = selected_items[0].row()
            if row_index < len(self.packets):
                packet = self.packets[row_index]
                self.outputTextEdit.setPlainText(packet.show(dump=True))  # 显示选中的数据包详细信息

    def open_filter_window(self):
        filter_window = FilterWindow(self)
        if filter_window.exec_():
            selected_protocol = filter_window.get_selected_protocol()
            self.apply_filter(selected_protocol)

    def apply_filter(self, protocol):
        # 清除现有的表格行
        self.tableWidget.setRowCount(0)
        # 设置当前过滤协议，用于更新显示时的判断
        self.current_filter_protocol = protocol
        
    @pyqtSlot(str, str, str, str, str, str, Packet)
    def update_packet_display(self, time, src, dst, protocol, info, color_name, packet):
        # 如果没有设置过滤协议，或当前项目符合过滤条件，则添加到表格
        if self.current_filter_protocol is None or self.current_filter_protocol == protocol:
            row_position = self.tableWidget.rowCount()
            self.tableWidget.insertRow(row_position)
            self.tableWidget.setItem(row_position, 0, QTableWidgetItem(time))
            self.tableWidget.setItem(row_position, 1, QTableWidgetItem(src))
            self.tableWidget.setItem(row_position, 2, QTableWidgetItem(dst))
            self.tableWidget.setItem(row_position, 3, QTableWidgetItem(protocol))
            self.tableWidget.setItem(row_position, 4, QTableWidgetItem(info))
            # 根据协议类型设置行颜色
            for i in range(self.tableWidget.columnCount()):
                self.tableWidget.item(row_position, i).setBackground(QColor(protocol_colors.get(color_name, 'white')))
            # 保存捕获的数据包
            self.packets.append(packet)
        # 否则，如果设置了过滤协议但是不匹配，则不添加到表格

    def on_table_item_selection_changed(self):
        selected_items = self.tableWidget.selectedItems()
        if selected_items:
            row_index = selected_items[0].row()
            if row_index < len(self.packets):
                packet = self.packets[row_index]
                # 使用packet.show2()方法来显示详细信息
                packet_details = packet.show2(dump=True)
                self.outputTextEdit.setPlainText(packet_details)
                
    def start_sniffing(self):
        
        global sniffer_thread, sniffing
        if not sniffing:
            sniffing = True
            self.startButton.setEnabled(False)
            self.stopButton.setEnabled(True)
            sniffer_thread = Thread(target=self.sniff_packets)
            sniffer_thread.daemon = True
            sniffer_thread.start()

    def stop_sniffing(self):
      
        global sniffing
        sniffing = False
        self.startButton.setEnabled(True)
        self.stopButton.setEnabled(False)
        # 如果嗅探线程存在，则等待其结束
        if self.sniffer_thread is not None:
            self.sniffer_thread.join()
            self.sniffer_thread = None
            

    def sniff_packets(self):
        global sniffing, iface
        while sniffing:
            # 修改嗅探器过滤器以同时接受IPv4和IPv6报文
            sniff(iface=iface, prn=lambda pkt: packet_callback(pkt, self.packet_info_emitter), filter="ip or arp or ip6", store=0, count=10)
        self.packet_info_emitter.packet_info_signal_zero.emit("Sniffing stopped.", '', '', '', '', 'white')


def packet_callback(packet, packet_info_emitter):
    # 获取数据包的时间戳
    packet_time = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S')
    src, dst, summary, color, protocol = '', '', '', 'Other', 'Other'

    # 处理IPv6数据包
    if IPv6 in packet:
        src = packet[IPv6].src
        dst = packet[IPv6].dst
        protocol = 'IPv6'
        color = 'IPv6'
        packet_info_emitter.packet_info_signal.emit(packet_time, src, dst, protocol, summary, color, packet)

       
        summary = packet[IPv6].summary()

        packet_info_emitter.packet_info_signal.emit(packet_time, src, dst, protocol, summary, color, packet)
    # 处理IPv4数据包
    elif IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        protocol = 'IP'
        color = 'IP'
        summary = packet[IP].summary()
        packet_info_emitter.packet_info_signal.emit(packet_time, src, dst, protocol, summary, color, packet)
        
        # 检查是否是IP分片
        if (packet[IP].flags & 0x1) or (packet[IP].frag > 0):
            protocol = 'Fragmented'
            color = 'Fragmented'
            summary = f"Fragmented IP part, offset {packet[IP].frag}"
            packet_info_emitter.packet_info_signal.emit(packet_time, src, dst, protocol, summary, color, packet)
            defragment(packet, packet_info_emitter)
        
        if TCP in packet:
            protocol = 'TCP'
            color = 'TCP'
            summary = packet[TCP].summary()
        elif UDP in packet:
            protocol = 'UDP'
            color = 'UDP'
            summary = packet[UDP].summary()
        elif ICMP in packet:
            protocol = 'ICMP'
            color = 'ICMP'
            summary = packet[ICMP].summary()

        packet_info_emitter.packet_info_signal.emit(packet_time, src, dst, protocol, summary, color, packet)
    # 处理ARP数据包
    elif ARP in packet:
        src = packet[ARP].psrc
        dst = packet[ARP].pdst
        protocol = 'ARP'
        color = 'ARP'
        summary = packet.summary()
        packet_info_emitter.packet_info_signal.emit(packet_time, src, dst, protocol, summary, color, packet)

def defragment(packet, packet_info_emitter):
    global frags, frag_lock
    if IP in packet and (packet[IP].frag > 0 or packet[IP].flags & 0x1):
        packet_time = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S')
        src = packet[IP].src
        dst = packet[IP].dst
        
        with frag_lock:
            pkt_id = (packet[IP].src, packet[IP].dst, packet[IP].id)
            if pkt_id not in frags:
                frags[pkt_id] = {packet[IP].frag: bytes(packet[IP].payload)}
            else:
                frags[pkt_id][packet[IP].frag] = bytes(packet[IP].payload)

            # Check if we have all fragments
            chunks = sorted(frags[pkt_id].items())
            last_offset = None
            complete = True
            for offset, _ in chunks:
                if last_offset is not None and offset != last_offset + 8:
                    complete = False
                    break
                last_offset = offset

            if complete and (packet[IP].flags & 0x1) == 0:
                payload = b''.join(data for _, data in chunks)
                new_packet = IP(src=packet[IP].src, dst=packet[IP].dst) / payload
                new_packet[IP].flags = 0
                new_packet[IP].frag = 0
                new_packet[IP].len = len(payload) + len(new_packet[IP])
                defrag_info = f"Defragmented packet from {new_packet[IP].src} to {new_packet[IP].dst}"
                packet_info_emitter.packet_info_signal.emit(packet_time, new_packet[IP].src, new_packet[IP].dst, 'Defragmented', defrag_info, 'Defragmented')
                del frags[pkt_id]

def main():
    app = QApplication(sys.argv)
    packet_info_emitter = PacketInfoEmitter()
    gui = SnifferGUI(packet_info_emitter)
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()

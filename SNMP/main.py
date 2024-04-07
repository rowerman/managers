import copy
import sys
import threading
import time

import IPy
from PyQt5.QtWidgets import QApplication, QMainWindow, QMessageBox, QVBoxLayout, QGroupBox, QHeaderView, QTableWidgetItem
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.backends.backend_qt5agg import NavigationToolbar2QT as NavigationToolbar
from matplotlib.figure import Figure
from pyqt5_plugins.examplebuttonplugin import QtGui

from GUI import Gui
import funcs

class MonitorThread(QThread):
    data_updated = pyqtSignal()

    def __init__(self, window, des_ip):
        super().__init__()
        self.window = window
        self.des_ip = des_ip
        self.should_stop = False  # 添加一个标志来表示线程是否应该停止

    def run(self):
        cpu = []
        RAM = []
        disk = []
        upload = []
        download = []

        while not self.should_stop:
            res = funcs.monitor_cpu(self.des_ip)
            cpu.append(res)
            self.window.ui.label_25.setText(str(res) + "%")

            res = funcs.monitor_RAM(self.des_ip)
            RAM.append(res)
            res_per = "{:.2%}".format(res)
            self.window.ui.label_26.setText(str(res_per))

            res = funcs.monitor_disk(self.des_ip)
            disk.append(res)
            res_per = "{:.2%}".format(res)
            self.window.ui.label_27.setText(str(res_per))

            res_download, res_upload, total = funcs.monitor_net(self.des_ip)
            res_download = float(res_download)/2000
            download.append(res)
            res_upload = float(res_upload)/2000
            upload.append(res)
            if res_upload > 1000:
                self.window.ui.label_30.setText(str(res_upload/1000)+"MB/s")
            else:
                self.window.ui.label_30.setText(str(res_upload) + "KB/s")
            if res_download > 1000:
                self.window.ui.label_31.setText(str(res_download/1000)+"MB/s")
            else:
                self.window.ui.label_31.setText(str(res_download) + "KB/s")
                
            self.window.update_matplotlib_figure(self.window.ui.groupBox_4, cpu)
            self.window.update_matplotlib_figure(self.window.ui.groupBox_5, RAM)
            self.window.update_matplotlib_figure(self.window.ui.groupBox_6, disk)
            self.window.update_matplotlib_figure(self.window.ui.groupBox_7, upload)
            self.window.update_matplotlib_figure(self.window.ui.groupBox_8, download)

            self.data_updated.emit()

            time.sleep(3)
            
    def stop(self):  # 添加一个方法来设置这个标志
        self.should_stop = True
        
class WarnCpu(QThread):
    cpu_overload = pyqtSignal()  # 定义一个信号

    def __init__(self, window, des_ip, level):
        super().__init__()
        self.window = window
        self.des_ip = des_ip
        self.level = level
        self.stop = False

    def run(self):
        while not self.stop:
            if funcs.warn_cpu(self.des_ip, self.level) == False:
                self.cpu_overload.emit()  # 发出信号
                time.sleep(3)
            else:
                continue

    def stop(self):
        self.stop = True



class WarnRAM(QThread):
    RAM_overload = pyqtSignal()
    
    def __init__(self, window, des_ip, level):
        super().__init__()
        self.window = window
        self.des_ip = des_ip
        self.level = level
        self.stop = False
    
    def run(self):
        while not self.stop:
            if funcs.warn_memory(self.des_ip, self.level) == False:
                self.RAM_overload.emit()  # 发出信号
                time.sleep(3)
            else:
                continue
    
    def stop(self):
        self.stop = True

    

class MyMainWindow(QMainWindow):
    def __init__(self, parent=None):
        super(MyMainWindow, self).__init__(parent)
        self.ui = Gui.Ui_MainWindow()
        self.ui.setupUi(self)
        self.trap_packets = []
        self.ui.tableWidget.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.ui.lineEdit_4.setReadOnly(True)
        self.ui.label_8.setText("No work~")
        
        self.ui.label_35.setScaledContents(True)  # 设置scaledContents属性为True
        pixmap = QtGui.QPixmap('./pics/logo.png')
        pixmap = pixmap.scaled(self.ui.label_35.width(), self.ui.label_35.height(), Qt.KeepAspectRatio)
        self.ui.label_35.setPixmap(pixmap)
        
        self.ui.pushButton.clicked.connect(lambda : self.ui.stackedWidget.setCurrentIndex(0))
        self.ui.pushButton_2.clicked.connect(lambda: self.ui.stackedWidget.setCurrentIndex(1))
        self.ui.pushButton_3.clicked.connect(lambda : self.ui.stackedWidget.setCurrentIndex(2))
        self.ui.pushButton_4.clicked.connect(lambda : self.ui.stackedWidget.setCurrentIndex(3))
        self.ui.pushButton_5.clicked.connect(lambda : self.ui.stackedWidget.setCurrentIndex(4))
        
        self.groupBoxes = [self.ui.groupBox_4, self.ui.groupBox_5, self.ui.groupBox_6, self.ui.groupBox_7,
                           self.ui.groupBox_8]
        
        # 将OID查询与槽函数绑定
        self.ui.pushButton_8.clicked.connect(lambda: self.GetByOid(self.ui.lineEdit_6, self.ui.lineEdit_7, self.ui.textEdit))
        # 将SET与槽函数绑定
        self.ui.pushButton_9.clicked.connect(lambda: self.SetByOid(self.ui.lineEdit_8, self.ui.lineEdit_9, self.ui.lineEdit,
                                                                   self.ui.lineEdit_4,self.ui.comboBox))
        # 将监听与槽函数绑定
        self.ui.pushButton_10.clicked.connect(lambda: self.listenTrap())
        # 展示trap包信息
        self.ui.tableWidget.itemClicked.connect(lambda item: self.showTrapInfo(item))
        # 发送trap包
        self.ui.pushButton_11.clicked.connect(lambda: self.sendTrap(self.ui.lineEdit_10, self.ui.lineEdit_11, self.ui.lineEdit_2,
                                                                    self.ui.lineEdit_3))
        # 开始监控
        self.ui.pushButton_12.clicked.connect(lambda: self.monitor(self.ui.lineEdit_12))
        # 设置阈值
        self.ui.pushButton_6.clicked.connect(lambda: self.warnCpu(self.ui.comboBox_2, self.ui.lineEdit_12))
        self.ui.pushButton_7.clicked.connect(lambda: self.warnRAM(self.ui.comboBox_3, self.ui.lineEdit_12))
    
    def closeEvent(self, event):
        if hasattr(self, 'monitor_thread') and self.monitor_thread.isRunning():
            self.monitor_thread.stop()
            self.monitor_thread.wait()
        if hasattr(self,'thread_cpu') and self.thread_cpu.isRunning():
            self.thread_cpu.stop()
            self.thread_cpu.wait()
        if hasattr(self,'thread_ram') and self.thread_ram.isRunning():
            self.thread_ram.stop()
            self.thread_ram.wait()
        
        super().closeEvent(event)
        
    def update_matplotlib_figure(self, groupBox, data):
        # 获取matplotlib图像的第一个子图
        ax = groupBox.layout().itemAt(0).widget().figure.axes[0]
        
        # 更新线条的数据
        x_data = range(len(data))
        ax.lines[0].set_data(x_data, data)
        
        # 更新坐标轴的范围
        ax.relim()
        ax.autoscale_view()
        
        # 重绘图像
        ax.figure.canvas.draw()
    
    def update_ui(self):
        QApplication.processEvents()
    
    def monitor(self,LineEdit):
        des_ip = LineEdit.text()
        if des_ip == "" or self.checkip(des_ip) == False:
            QMessageBox.information(self, "提示", "请输入正确的IP地址")
            return
        
        for groupBox in self.groupBoxes:
            self.create_matplotlib_figure(groupBox)
        
        self.monitor_thread = MonitorThread(self, des_ip)
        self.monitor_thread.data_updated.connect(self.update_ui)
        self.monitor_thread.start()
    
    def create_matplotlib_figure(self, groupBox):
        # 创建一个matplotlib图像
        figure = Figure()
        canvas = FigureCanvas(figure)
        
        # 创建一个matplotlib导航工具栏，并添加到QGroupBox中
        toolbar = NavigationToolbar(canvas, groupBox)
        
        # 使用QVBoxLayout布局，并将matplotlib图像和工具栏添加到布局中
        layout = QVBoxLayout()
        layout.addWidget(canvas)
        groupBox.setLayout(layout)
        
        # 在matplotlib图像上绘制一个空的线条
        ax = figure.add_subplot(111)
        ax.get_xaxis().set_ticklabels([])
        ax.get_yaxis().set_visible(False)  # 隐藏y轴
        ax.plot([])
    
    def checkip(self,address):
        try:
            version = IPy.IP(address).version()
            if version == 4 or version == 6:
                return True
            else:
                return False
        except Exception as e:
            return False
        
    def GetByOid(self, LineEdit_1, LineEdit_2, TextEdit):
        des_ip = LineEdit_1.text()
        oid = LineEdit_2.text()
        if self.checkip(des_ip) != True:
            QMessageBox.information(self, '提示', '请输入正确的IP地址!')
            return
        
        res = funcs.GetByOid(des_ip,oid)
        if res == "connect error":
            QMessageBox.information(self, '提示', '连接错误!')
            return
        
        TextEdit.setText("oid:{} \ncontent:{}".format(res[0][0],res[0][1]))
        
    def SetByOid(self, LineEdit_1, LineEdit_2, LineEdit_3, LineEdit_4, ComboBox):
        des_ip = LineEdit_1.text()
        oid = LineEdit_2.text()
        if self.checkip(des_ip) != True:
            QMessageBox.information(self, '提示', '请输入正确的IP地址!')
            return
        
        value = LineEdit_3.text()
        type = ComboBox.currentText()
        
        res = funcs.SetByOid(des_ip,oid,value,type)
        if res == "NoChangable!":
            QMessageBox.information(self, '提示', 'oid对应的属性不可以修改!')
            return
        else:
            LineEdit_4.setText(res)
    
    def showTrapInfo(self,item):
        row_num = item.row()
        packet = self.trap_packets[row_num]
        packet_list = list(packet.items())
        packet_values = packet_list[5:]
        packet_values = dict(packet_values)
        
        self.ui.textEdit_7.setText("过期时间：{} \ntrap消息对应的oid：{} \ntrap包的源IP:{} \ntrap包的源社区:{} \ntrap包类型:{} \n数据:{}".format(
            packet["1.3.6.1.2.1.1.3.0"],
            packet["1.3.6.1.6.3.1.1.4.1.0"],
            packet["1.3.6.1.6.3.18.1.3.0"],
            packet["1.3.6.1.6.3.18.1.4.0"],
            packet["1.3.6.1.6.3.1.1.4.3.0"],
            packet_values
        ))
        
    def InsertTrap(self, trap_info):
        # uptime = trap_info["1.3.6.1.2.1.1.3.0"]
        # trap_id = trap_info["1.3.6.1.6.3.1.1.4.1.0"]
        # ip = trap_info["1.3.6.1.6.3.18.1.3.0"]
        # community = trap_info["1.3.6.1.6.3.18.1.4.0"]
        # trap_type = trap_info["1.3.6.1.6.3.1.1.4.3.0"]
        new_trap = copy.deepcopy(trap_info)
        self.trap_packets.append(new_trap)
        ip = self.trap_packets[-1]["1.3.6.1.6.3.18.1.3.0"]
        community = self.trap_packets[-1]["1.3.6.1.6.3.18.1.4.0"]

        row_num = self.ui.tableWidget.rowCount()
        self.ui.tableWidget.insertRow(row_num)
        
        self.ui.tableWidget.setItem(row_num, 0, QTableWidgetItem(ip))
        self.ui.tableWidget.setItem(row_num, 1, QTableWidgetItem(community))
        
    
    def listenTrap(self):
        self.ui.label_8.setText("listening...")
        traplistener = funcs.TrapListener(self.InsertTrap)
        thread_listen = threading.Thread(target=traplistener.listenTrap)
        thread_listen.daemon = True
        thread_listen.start()
        
    def sendTrap(self,LineEdit_1, LineEdit_2, LineEdit_3, LineEdit_4):
        des_ip = LineEdit_1.text()
        oid = LineEdit_2.text()
        if self.checkip(des_ip) != True:
            QMessageBox.information(self, '提示', '请输入正确的IP地址!')
            return
        extra_oid = LineEdit_3.text()
        extra_value = LineEdit_4.text()
        
        res_status = funcs.sendTrap(des_ip, oid, extra_oid, extra_value)
        
        if res_status == None:
            QMessageBox.information(self, '提示', '发送失败!')
            return
        self.ui.lineEdit_5.setText(res_status)
    
    def warnCpu(self, ComboBox, LineEdit):
        des_ip = LineEdit.text()
        level = ComboBox.currentText()
        
        self.thread_cpu = WarnCpu(self, des_ip, level)
        self.thread_cpu.cpu_overload.connect(self.show_CPUwarning)  # 连接信号到槽
        self.thread_cpu.start()
    
    def show_CPUwarning(self):
        QMessageBox.information(self, "警告", "CPU使用率超过设定的阈值！")
        
    def warnRAM(self,ComboBox,LineEdit):
        des_ip = LineEdit.text()
        level = ComboBox.currentText()
        
        self.thread_ram = WarnRAM(self,des_ip,level)
        self.thread_ram.RAM_overload.connect(self.show_RAMwarning)  # 连接信号到槽
        self.thread_ram.start()
        
    def show_RAMwarning(self):
        QMessageBox.information(self, "警告", "内存使用率超过设定的阈值！")
        

if __name__ == '__main__':
    app = QApplication(sys.argv)  # 创建应用程序对象
    
    MainWindow = MyMainWindow()  # 创建主窗口
    MainWindow.show()  # 显示主窗口
    sys.exit(app.exec_())  # 在主线程中退出
import sys
from PyQt5 import QtCore, QtGui, QtWidgets
import os, msgpack, winreg
from security import KeyExport, LocalSecurity
from channels import Client
from response import RespCode

TITLE = 'Verified Transmit'

code_map = {
    RespCode.RCS_OK: '操作成功完成。',
    RespCode.RCS_OK_BUT_UNAUTHORIZED: '操作成功，但此计算机未授权。',
    RespCode.RCE_FAILED: '操作失败。服务器没有提供详细信息。',
    RespCode.RCE_UNAUTHORIZED: '此计算机未被授权进行此操作。',
    RespCode.RCE_REGISTER_TWICE: '此计算机已经进行过注册操作。',
    RespCode.RCE_INTEGRITY_FAIL: '网络传输过程中文件完整性受损。',
    RespCode.RCE_SIGNATURE_MISMATCH: '服务器计算的数字签名与客户端不一致，可能由文件受损导致。',
    RespCode.RCE_WRONG_PASSWORD: '提供的密码与服务器生成的不符。',
    RespCode.RCE_INVALID_FSPATH: '无效的文件系统路径请求。',
    RespCode.RCE_NO_SUCH_COMMAND: '请求的操作在服务器上未被定义，或已被禁用。',
    RespCode.RCE_ACCESS_DENIED: '对目标项的访问被拒绝。这可能是启动服务器的用户不具有访问该目录的权限。'
}

desktop = None

def get_desktop() -> str:
    global desktop
    if not desktop:
        if sys.platform == 'win32':
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders')
            desktop = winreg.QueryValueEx(key, "Desktop")[0]
            winreg.CloseKey(key)
        else:
            desktop = os.path.expanduser('~/desktop')
    return desktop

def as_hex(i):
    return '0x' + hex(i)[2:].upper().zfill(4)

def format_code(code):
    return '%s (%s)\n%s' % (as_hex(code.value), code.name, code_map[code])

def format_size(size):
    if size < 1024:
        return f'{size} B'
    elif size < 1024*1024:
        return f'{size/1024:.2f} KB'
    elif size < 1024*1024*1024:
        return f'{size/1024/1024:.2f} MB'
    else:
        return f'{size/1024/1024/1024:.2f} GB'

def wrap(s, width=50):
    lines = []
    while s:
        lines.append(s[:width])
        s = s[width:]
    return '\n'.join(lines)

class Ui_MainWindow(object):
    def __init__(self):
        self._hasLocalPEM = os.path.isfile('local.pem')
        self._client = None
        self._dir = []
        self.FILE_ICON = QtGui.QIcon('file-icon.png')
        self.FOLDER_ICON = QtGui.QIcon('folder-icon.png')
        self.APP_ICON = QtGui.QIcon('icon.png')
        self.waiting = []
        self.fthread = None
    def setupUi(self, MainWindow):
        self.win = MainWindow
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(800, 575)
        MainWindow.setFixedSize(800, 575)
        MainWindow.setWindowIcon(self.APP_ICON)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(MainWindow.sizePolicy().hasHeightForWidth())
        MainWindow.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei UI")
        MainWindow.setFont(font)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.targetTree = QtWidgets.QListWidget(self.centralwidget)
        self.targetTree.setGeometry(QtCore.QRect(10, 37, 340, 501))
        self.targetTree.setObjectName("targetTree")
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(10, 1, 341, 31))
        self.label.setObjectName("label")
        self.fileList = QtWidgets.QTableWidget(self.centralwidget)
        self.fileList.setGeometry(QtCore.QRect(360, 37, 431, 361))
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.fileList.sizePolicy().hasHeightForWidth())
        self.fileList.setSizePolicy(sizePolicy)
        self.fileList.setObjectName("fileList")
        self.fileList.setColumnCount(0)
        self.fileList.setRowCount(0)
        self.label_2 = QtWidgets.QLabel(self.centralwidget)
        self.label_2.setGeometry(QtCore.QRect(362, 1, 341, 31))
        self.label_2.setObjectName("label_2")
        self.buttonSelect = QtWidgets.QPushButton(self.centralwidget)
        self.buttonSelect.setGeometry(QtCore.QRect(360, 407, 131, 31))
        self.buttonSelect.setObjectName("buttonSelect")
        self.buttonRemove = QtWidgets.QPushButton(self.centralwidget)
        self.buttonRemove.setGeometry(QtCore.QRect(510, 407, 131, 31))
        self.buttonRemove.setObjectName("buttonRemove")
        self.buttonClear = QtWidgets.QPushButton(self.centralwidget)
        self.buttonClear.setGeometry(QtCore.QRect(660, 407, 131, 31))
        self.buttonClear.setObjectName("buttonClear")
        self.progress = QtWidgets.QProgressBar(self.centralwidget)
        self.progress.setEnabled(True)
        self.progress.setGeometry(QtCore.QRect(360, 509, 431, 31))
        self.progress.setMaximum(10000)
        self.progress.setProperty("value", 0)
        self.progress.setTextVisible(False)
        self.progress.setObjectName("progress")
        self.buttonUpload = QtWidgets.QPushButton(self.centralwidget)
        self.buttonUpload.setGeometry(QtCore.QRect(360, 457, 431, 41))
        self.buttonUpload.setObjectName("buttonUpload")
        self.line = QtWidgets.QFrame(self.centralwidget)
        self.line.setGeometry(QtCore.QRect(360, 437, 431, 21))
        self.line.setFrameShape(QtWidgets.QFrame.HLine)
        self.line.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line.setObjectName("line")
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 800, 26))
        self.menubar.setObjectName("menubar")
        self.menuFile = QtWidgets.QMenu(self.menubar)
        self.menuFile.setObjectName("menuFile")
        self.menuSecurity = QtWidgets.QMenu(self.menubar)
        self.menuSecurity.setObjectName("menuSecurity")
        self.menuConnection = QtWidgets.QMenu(self.menubar)
        self.menuConnection.setObjectName("menuConnection")
        MainWindow.setMenuBar(self.menubar)
        self.actionSelect = QtWidgets.QAction(MainWindow)
        self.actionSelect.setObjectName("actionSelect")
        self.actionRemove = QtWidgets.QAction(MainWindow)
        self.actionRemove.setObjectName("actionRemove")
        self.actionClear = QtWidgets.QAction(MainWindow)
        self.actionClear.setObjectName("actionClear")
        self.actionExit = QtWidgets.QAction(MainWindow)
        self.actionExit.setObjectName("actionExit")
        self.actionGenerate = QtWidgets.QAction(MainWindow)
        self.actionGenerate.setObjectName("actionGenerate")
        self.actionRegister = QtWidgets.QAction(MainWindow)
        self.actionRegister.setObjectName("actionRegister")
        self.actionKeyInfo = QtWidgets.QAction(MainWindow)
        self.actionKeyInfo.setObjectName("actionKeyInfo")
        self.actionConnect = QtWidgets.QAction(MainWindow)
        self.actionConnect.setObjectName("actionConnect")
        self.actionConnectionInfo = QtWidgets.QAction(MainWindow)
        self.actionConnectionInfo.setObjectName("actionConnectionInfo")
        self.menuFile.addAction(self.actionSelect)
        self.menuFile.addAction(self.actionRemove)
        self.menuFile.addAction(self.actionClear)
        self.menuFile.addSeparator()
        self.menuFile.addAction(self.actionExit)
        self.menuSecurity.addAction(self.actionGenerate)
        self.menuSecurity.addAction(self.actionRegister)
        self.menuSecurity.addSeparator()
        self.menuSecurity.addAction(self.actionKeyInfo)
        self.menuConnection.addAction(self.actionConnect)
        self.menuConnection.addAction(self.actionConnectionInfo)
        self.menubar.addAction(self.menuFile.menuAction())
        self.menubar.addAction(self.menuSecurity.menuAction())
        self.menubar.addAction(self.menuConnection.menuAction())

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

        self.centralwidget.setEnabled(False)
        self.actionSelect.setEnabled(False)
        self.actionRemove.setEnabled(False)
        self.actionClear.setEnabled(False)
        self.actionGenerate.setEnabled(not self._hasLocalPEM)
        self.actionKeyInfo.setEnabled(self._hasLocalPEM)
        self.actionConnectionInfo.setEnabled(False)
        self.actionRegister.setEnabled(False)
        self.actionExit.triggered.connect(self.exitProgram)
        self.actionGenerate.triggered.connect(self.generateKey)
        self.actionKeyInfo.triggered.connect(self.keyInfo)
        self.actionConnect.triggered.connect(self.connectionDialog)
        self.actionConnectionInfo.triggered.connect(self.connectionInfo)
        self.targetTree.itemDoubleClicked.connect(self.switchDir)
        self.actionRegister.triggered.connect(self.registerKey)
        self.fileList.setSelectionMode(QtWidgets.QAbstractItemView.MultiSelection)
        self.fileList.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.actionSelect.triggered.connect(self.buttonSelect.click)
        self.buttonSelect.clicked.connect(self.selectFile)
        self.actionClear.triggered.connect(self.buttonClear.click)
        self.buttonClear.clicked.connect(self.clearList)
        self.actionRemove.triggered.connect(self.buttonRemove.click)
        self.buttonRemove.clicked.connect(self.removeFiles)

        self.fileList.setColumnCount(2)
        self.fileList.setHorizontalHeaderLabels(['文件名', '大小'])
        self.fileList.verticalHeader().setVisible(False)
        self.fileList.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.fileList.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.fileList.itemSelectionChanged.connect(self.fileListSelect)
        self.buttonUpload.clicked.connect(self.uploadFiles)
    def uploadFiles(self):
        indexes = self.fileList.selectedIndexes()
        indexList = []
        todo = []
        for index in indexes:
            index = index.row()
            if index in indexList: continue
            indexList.append(index)
            todo.append(self.waiting[index][0])
        targetdir = os.path.sep.join(self._dir)
        self.centralwidget.setEnabled(False)
        self.ud = ud = UploadDialog(self._client, todo, self._dir, self.win)
        ud.show()
        ud.accepted.connect(self.uploadFinished)
    def uploadFinished(self):
        success, failed = self.ud.ui.getResults()
        todo = []
        for f, size in self.waiting:
            if f in success:
                todo.append((f, size))
        for item in todo:
            self.waiting.remove(item)
        self.updateFileList()
        msg = '上传结果:\n\n'
        msg += '尝试上传了 %i 个文件\n' % (len(success) + len(failed))
        if success:
            msg += '以下文件成功上传至服务器:\n' 
            msg += '\n'.join(map(lambda f: os.path.split(f)[1], success))
            msg += '\n\n'
        else:
            msg += '全部上传失败。\n\n'
        if failed:
            for f, code in failed:
                msg += '%s 上传失败。原因:\n' % os.path.split(f)[1]
                msg += format_code(code)
                msg += '\n'
        else:
            msg += '全部上传成功。'
        msg = msg.strip()
        QtWidgets.QMessageBox.information(self.win, TITLE, msg)
        self.centralwidget.setEnabled(True)
    def selectFile(self):
        files = QtWidgets.QFileDialog.getOpenFileNames(self.win, '选择上传文件', get_desktop(), '全部文件 (*.*)')[0]
        if not files:
            return
        for f in files:
            f = os.path.normpath(f)
            size = os.path.getsize(f)
            if (f, size) not in self.waiting:
                self.waiting.append((f, size))
        self.updateFileList()
    def updateFileList(self):
        self.fileList.clearContents()
        self.fileList.setRowCount(len(self.waiting))
        for i, (f, size) in enumerate(self.waiting):
            fn = os.path.split(f)[1]
            self.fileList.setItem(i, 0, QtWidgets.QTableWidgetItem(fn))
            self.fileList.setItem(i, 1, QtWidgets.QTableWidgetItem(format_size(size)))
        can = bool(self.waiting)
        self.buttonClear.setEnabled(can)
        self.actionClear.setEnabled(can)
    def clearList(self):
        self.waiting.clear()
        self.updateFileList()
    def fileListSelect(self):
        can = bool(self.fileList.selectedIndexes())
        self.buttonRemove.setEnabled(can)
        self.actionRemove.setEnabled(can)
        self.buttonUpload.setEnabled(can)
    def removeFiles(self):
        indexes = self.fileList.selectedIndexes()
        indexList = []
        todo = []
        for index in indexes:
            index = index.row()
            if index in indexList: continue
            indexList.append(index)
            todo.append(self.waiting[index])
        for item in todo:
            self.waiting.remove(item)
        self.updateFileList()
    def exitProgram(self):
        self.win.close()
    def registerKey(self):
        resp = self._client.startRegister()
        if resp.error():
            QtWidgets.QMessageBox.critical(self.win, TITLE, '密钥注册失败。\n\n原因：\n%s' % format_code(resp.code()))
            return
        password, ret = QtWidgets.QInputDialog.getText(self.win, '密钥注册', '输入服务器控制台上显示的密码：', QtWidgets.QLineEdit.Password)
        if not ret:
            password = b''
        else:
            password = password.encode()
        resp = self._client.endRegister(password)
        if resp.success():
            QtWidgets.QMessageBox.information(self.win, TITLE, '密钥注册成功。\n\n此计算机已成为受信任的来源。')
            self.actionRegister.setEnabled(False)
        else:
            QtWidgets.QMessageBox.critical(self.win, TITLE, '密钥注册失败。\n\n原因：\n%s' % format_code(resp.code()))
    def keyInfo(self):
        export = KeyExport.load('local.pem')
        msg = 'RSA 密钥信息:\n\n'
        msg += 'RSA 指数: %i\n'
        msg += 'RSA 模数: %s\n'
        msg += '密钥 SHA-256 摘要标识符: %s\n'
        msg += '公钥 SHA-256 摘要标识符: %s'
        msg = msg % (export.key().e, wrap(str(export.key().n)), export.identifier(), export.publicKey().identifier())
        QtWidgets.QMessageBox.information(self.win, TITLE, msg)
    def generateKey(self):
        LocalSecurity.generate().save('local.pem')
        QtWidgets.QMessageBox.information(self.win, TITLE, '已生成本地密钥文件。')
        self._hasLocalPEM = True
        self.actionGenerate.setEnabled(False)
        self.actionKeyInfo.setEnabled(True)
    def connectionDialog(self):
        self._cd = cd = ConnectionDialog(self.win)
        cd.accepted.connect(self.connected)
        cd.show()
    def connected(self):
        self.actionConnect.setEnabled(False)
        self._client = self._cd.getClient()
        self.centralwidget.setEnabled(True)
        if not self._client.authorized():
            QtWidgets.QMessageBox.warning(self.win, TITLE, '本计算机还未进行公钥注册，无法上传文件。\n请前往菜单"安全 > 公钥认证"进行认证。')
        self.actionSelect.setEnabled(True)
        self.buttonRemove.setEnabled(False)
        self.buttonClear.setEnabled(False)
        self.buttonUpload.setEnabled(False)
        self.actionConnectionInfo.setEnabled(True)
        self.actionRegister.setEnabled(not self._client.authorized())
        self.updateFileSystem()
    def connectionInfo(self):
        args = list(self._client.address())
        args.append('是' if self._client.authorized() else '否')
        msg = '连接信息:\n\n'
        msg += '服务器地址: %s\n'
        msg += '服务器端口: %i\n'
        msg += '本机公钥是否已注册: %s'
        msg = msg % tuple(args)
        QtWidgets.QMessageBox.information(self.win, TITLE, msg)
    def updateFileSystem(self, path=''):
        cache = self._dir.copy()
        if path == '..':
            self._dir.pop()
        elif path:
            self._dir.append(path)
        resp = self._client.fileSystem(self._dir)
        if resp.error():
            self._dir = cache
            QtWidgets.QMessageBox.critical(self.win, TITLE, '切换目录失败。\n\n原因:\n%s' % format_code(resp.code()))
            return
        data = msgpack.unpackb(resp.description())
        self.files = data['files']
        self.dirs = data['dirs']
        root = data['base']
        self.targetTree.clear()
        if not root:
            self.targetTree.addItem(QtWidgets.QListWidgetItem(self.FOLDER_ICON, '..'))
        for d in self.dirs:
            self.targetTree.addItem(QtWidgets.QListWidgetItem(self.FOLDER_ICON, d))
        for f in self.files:
            self.targetTree.addItem(QtWidgets.QListWidgetItem(self.FILE_ICON, f))
    def switchDir(self):
        item = self.targetTree.selectedItems()[0].text()
        if item in self.dirs or item == '..':
            self.updateFileSystem(item)
        else:
            full = self._dir + [item,]
            self.fetchFile(full)
    def fetchFile(self, item):
        if self.fthread:
            QtWidgets.QMessageBox.information(self.win, TITLE, '请等待当前文件下载完成。')
            return
        ext = os.path.splitext(item[-1])[1]
        extname = ext[1:].upper()
        path = QtWidgets.QFileDialog.getSaveFileName(self.win, '下载文件', get_desktop(), '%s 文件 (*%s)' % (extname, ext))[0]
        if not path: return
        self.fthread = DownloadThread(self._client, path, item)
        self.fthread.callback.connect(self.fetchProgress)
        self.fthread.finished.connect(self.fetchFinished)
        self.fthread.start()
    def fetchProgress(self, count, total):
        self.progress.setValue(10000 * count / total)
    def fetchFinished(self):
        self.progress.setValue(0)
        resp = self.fthread.getResponse()
        self.fthread = None
        msg = '下载结果:\n\n'
        if resp.success():
            msg += '下载文件成功。'
        else:
            msg += '下载失败，原因:\n'
            msg += format_code(resp.code())
        QtWidgets.QMessageBox.information(self.win, TITLE, msg)
    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "Verified Transmit"))
        self.label.setText(_translate("MainWindow", "服务器计算机文件系统"))
        self.label_2.setText(_translate("MainWindow", "本地文件列表"))
        self.buttonSelect.setText(_translate("MainWindow", "添加文件..."))
        self.buttonRemove.setText(_translate("MainWindow", "移除选中"))
        self.buttonClear.setText(_translate("MainWindow", "清空列表"))
        self.buttonUpload.setText(_translate("MainWindow", "上传文件"))
        self.menuFile.setTitle(_translate("MainWindow", "文件 (&F)"))
        self.menuSecurity.setTitle(_translate("MainWindow", "安全 (&S)"))
        self.menuConnection.setTitle(_translate("MainWindow", "连接 (&C)"))
        self.actionSelect.setText(_translate("MainWindow", "添加文件... (&S)"))
        self.actionRemove.setText(_translate("MainWindow", "移除选中 (&R)"))
        self.actionClear.setText(_translate("MainWindow", "清空列表 (&C)"))
        self.actionExit.setText(_translate("MainWindow", "退出 (&X)"))
        self.actionGenerate.setText(_translate("MainWindow", "生成密钥对 (&G)"))
        self.actionRegister.setText(_translate("MainWindow", "公钥注册 (&K)"))
        self.actionKeyInfo.setText(_translate("MainWindow", "密钥信息... (&I)"))
        self.actionConnect.setText(_translate("MainWindow", "连接至... (&T)"))
        self.actionConnectionInfo.setText(_translate("MainWindow", "连接信息... (&H)"))
    def __del__(self):
        if self._client:
            self._client.close()

class Ui_ConnectionDialog(object):
    def setupUi(self, ConnectionDialog):
        self._dialog = ConnectionDialog
        ConnectionDialog.setObjectName("ConnectionDialog")
        ConnectionDialog.resize(400, 300)
        ConnectionDialog.setFixedSize(400, 300)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(ConnectionDialog.sizePolicy().hasHeightForWidth())
        ConnectionDialog.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei UI")
        ConnectionDialog.setFont(font)
        ConnectionDialog.setModal(True)
        self.buttonBox = QtWidgets.QDialogButtonBox(ConnectionDialog)
        self.buttonBox.setGeometry(QtCore.QRect(20, 250, 361, 32))
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.Cancel|QtWidgets.QDialogButtonBox.Ok)
        self.buttonBox.setCenterButtons(True)
        self.buttonBox.setObjectName("buttonBox")
        self.label = QtWidgets.QLabel(ConnectionDialog)
        self.label.setGeometry(QtCore.QRect(20, 20, 351, 31))
        self.label.setObjectName("label")
        self.lineEdit = QtWidgets.QLineEdit(ConnectionDialog)
        self.lineEdit.setGeometry(QtCore.QRect(20, 60, 361, 31))
        self.lineEdit.setObjectName("lineEdit")
        self.label_2 = QtWidgets.QLabel(ConnectionDialog)
        self.label_2.setGeometry(QtCore.QRect(20, 100, 351, 31))
        self.label_2.setObjectName("label_2")
        self.spinBox = QtWidgets.QSpinBox(ConnectionDialog)
        self.spinBox.setGeometry(QtCore.QRect(20, 140, 361, 31))
        self.spinBox.setMinimum(0)
        self.spinBox.setMaximum(99999)
        self.spinBox.setObjectName("spinBox")
        self.progress = QtWidgets.QProgressBar(ConnectionDialog)
        self.progress.setGeometry(QtCore.QRect(20, 200, 361, 31))
        self.progress.setProperty("value", 0)
        self.progress.setTextVisible(False)
        self.progress.setObjectName("progress")

        self.retranslateUi(ConnectionDialog)
        self.buttonBox.accepted.connect(self.tryConnect)
        self.buttonBox.rejected.connect(ConnectionDialog.reject)
        QtCore.QMetaObject.connectSlotsByName(ConnectionDialog)

    def retranslateUi(self, ConnectionDialog):
        _translate = QtCore.QCoreApplication.translate
        ConnectionDialog.setWindowTitle(_translate("ConnectionDialog", "连接至服务器"))
        self.label.setText(_translate("ConnectionDialog", "服务器地址 (eg. 192.168.0.1)："))
        self.label_2.setText(_translate("ConnectionDialog", "服务器端口 (eg. 5000)："))
    def tryConnect(self):
        host = self.lineEdit.text()
        port = self.spinBox.value()
        try:
            c = Client(host, port)
            self.progress.setValue(50)
            c.connect()
            self.progress.setValue(100)
        except Exception:
            QtWidgets.QMessageBox.critical(self._dialog, TITLE, '连接至 %s:%i 失败。' % (host, port))
            self.progress.setValue(0)
        else:
            self._dialog._client = c
            self._dialog.close()
            self._dialog.accept()

class Ui_UploadDialog(object):
    def __init__(self, client: Client, files, targetdir, parent: 'MainWindow'=None):
        self._client = client
        self._files = files
        self._dir = targetdir
        self._total = len(files)
        self._success = []
        self._failed = []
        self._parent = parent
    def setupUi(self, UploadDialog):
        self._dialog = UploadDialog
        UploadDialog.setObjectName("UploadDialog")
        UploadDialog.resize(510, 140)
        font = QtGui.QFont()
        font.setFamily("Microsoft YaHei UI")
        UploadDialog.setFont(font)
        self.label = QtWidgets.QLabel(UploadDialog)
        self.label.setGeometry(QtCore.QRect(20, 20, 471, 21))
        self.label.setObjectName("label")
        self.progressBar = QtWidgets.QProgressBar(UploadDialog)
        self.progressBar.setGeometry(QtCore.QRect(10, 50, 491, 31))
        self.progressBar.setMaximum(10000)
        self.progressBar.setProperty("value", 0)
        self.progressBar.setObjectName("progressBar")
        self.buttonStart = QtWidgets.QPushButton(UploadDialog)
        self.buttonStart.setGeometry(QtCore.QRect(200, 90, 121, 35))
        self.buttonStart.setObjectName("buttonStart")

        self.retranslateUi(UploadDialog)
        QtCore.QMetaObject.connectSlotsByName(UploadDialog)
        
        self.buttonStart.clicked.connect(self.startUpload)
    def startUpload(self):
        msg = '将上传以下文件：\n'
        for f in self._files:
            msg += os.path.split(f)[1]
            msg += '\n'
        msg += '至服务器的以下目录：\n%s\n' % (os.path.join(*self._dir) if self._dir else 'ROOT')
        msg += '确定吗？'
        if QtWidgets.QMessageBox.warning(self._dialog, '上传文件', msg, QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No) != QtWidgets.QMessageBox.Yes:
            return
        self.thread = thread = UploadThread(self._client, self._files, self._dir)
        thread.finished.connect(self.finished)
        thread.callback.connect(self.progressCallback)
        thread.uploaded.connect(self.singleUploaded)
        thread.start()
        self.buttonStart.setEnabled(False)
    def progressCallback(self, current, count, total, retrying):
        current = os.path.split(current)[1]
        if retrying:
            self.label.setText('状态: 正在重试 %s 的第 %i / %i 个块' % (current, count, total))
        else:
            self.label.setText('状态: 正在上传 %s 的第 %i / %i 个块' % (current, count, total))
        self.progressBar.setValue(int(10000 * count / total))
    def singleUploaded(self, current, code):
        code = RespCode(code)
        if code == RespCode.RCS_OK:
            self._success.append(current)
        else:
            self._failed.append((current, code))
        if self._parent:
            self._parent.ui.progress.setValue(int(10000 * (len(self._success) + len(self._failed)) / self._total))
    def getResults(self):
        return self._success, self._failed
    def retranslateUi(self, UploadDialog):
        _translate = QtCore.QCoreApplication.translate
        UploadDialog.setWindowTitle(_translate("UploadDialog", "上传文件"))
        self.label.setText(_translate("UploadDialog", "状态: 就绪"))
        self.buttonStart.setText(_translate("UploadDialog", "开始"))
    def finished(self):
        if self._parent:
            self._parent.ui.progress.setValue(0)
        self._dialog.close()
        self._dialog.accept()


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

class ConnectionDialog(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.ui = Ui_ConnectionDialog()
        self.ui.setupUi(self)
        self._client = None
    def getClient(self) -> Client:
        return self._client

class UploadDialog(QtWidgets.QDialog):
    def __init__(self, client: Client, files, targetdir, parent=None):
        super().__init__(parent)
        self.ui = Ui_UploadDialog(client, files, targetdir, parent)
        self.ui.setupUi(self)
    def getResults(self):
        return self.ui.getResults()

class UploadThread(QtCore.QThread):
    callback = QtCore.pyqtSignal(str, int, int, bool)
    uploaded = QtCore.pyqtSignal(str, int)
    finished = QtCore.pyqtSignal()
    def __init__(self, client: Client, files, targetdir):
        super().__init__()
        self.files = files
        self.client = client
        self.dir = targetdir
    def run(self):
        for f in self.files:
            target = self.dir + [os.path.split(f)[1],]
            self.current = f
            resp = self.client.upload(f, target, self._callback)
            self.uploaded.emit(f, resp.code().value)
        self.finished.emit()
    def _callback(self, count, total, retrying):
        self.callback.emit(self.current, count, total, retrying)

class DownloadThread(QtCore.QThread):
    callback = QtCore.pyqtSignal(int, int)
    finished = QtCore.pyqtSignal()
    def __init__(self, client: Client, local, remote):
        super().__init__()
        self.local = local
        self.remote = remote
        self.client = client
    def run(self):
        self.resp = self.client.fetch(self.local, self.remote, self._callback)
        self.finished.emit()
    def getResponse(self):
        return self.resp
    def _callback(self, count, total):
        self.callback.emit(count, total)

if __name__ == '__main__':
    app = QtWidgets.QApplication([])
    win = MainWindow()
    win.show()
    app.exec_()
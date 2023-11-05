#include "stdafx.h"
#include "Sniffer.h"
#include "SnifferDlg.h"
#include "afxdialogex.h"
#include "pcap.h"
#include "protocol.h"
#include "analysis.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

DWORD WINAPI CapThread(LPVOID lpParameter);

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    

protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()





CSnifferDlg::CSnifferDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_SNIFFER_DIALOG, pParent)
{
	HIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CSnifferDlg::DoDataExchange(CDataExchange* pDX) {
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_COMBO1, CBNetCard);
	DDX_Control(pDX, IDC_COMBO2, CBFilterRule);
	DDX_Control(pDX, IDC_LIST1, LCtrl);
	DDX_Control(pDX, IDC_TREE1, TCtrl);
	DDX_Control(pDX, IDC_EDIT1, Edit);
	DDX_Control(pDX, IDC_BUTTON1, BTNStart);
	DDX_Control(pDX, IDC_BUTTON2, BTNStop);
	DDX_Control(pDX, IDC_BUTTON3, BTNSave);
	DDX_Control(pDX, IDC_BUTTON4, BTNRead);
	DDX_Control(pDX, IDC_EDIT2, EARP);
	DDX_Control(pDX, IDC_EDIT3, eIPv4);
	DDX_Control(pDX, IDC_EDIT4, eIPv6);
	DDX_Control(pDX, IDC_EDIT5, eICMPv4);
	DDX_Control(pDX, IDC_EDIT6, eICMPv6);
	DDX_Control(pDX, IDC_EDIT7, eUDP);
	DDX_Control(pDX, IDC_EDIT8, eTCP);
	DDX_Control(pDX, IDC_EDIT9, eHTTP);
	DDX_Control(pDX, IDC_EDIT10, eOther);
	DDX_Control(pDX, IDC_EDIT11, eSum);
}

BEGIN_MESSAGE_MAP(CSnifferDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &CSnifferDlg::ClickStart)//start
	ON_BN_CLICKED(IDC_BUTTON2, &CSnifferDlg::ClickEnd)//end
	ON_BN_CLICKED(IDC_BUTTON3, &CSnifferDlg::ClickSave)//save
	ON_BN_CLICKED(IDC_BUTTON4, &CSnifferDlg::ClickRead)//read
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST1, &CSnifferDlg::UpdateList)
	ON_NOTIFY(NM_CUSTOMDRAW, IDC_LIST1, &CSnifferDlg::ChangeColor)
END_MESSAGE_MAP()

BOOL CSnifferDlg::OnInitDialog() {
	CDialogEx::OnInitDialog();
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);
	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL NameValid;
		CString AboutMenu;
		NameValid = AboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(NameValid);
		if (!AboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, AboutMenu);
		}
	}
	SetIcon(HIcon, TRUE);			
	SetIcon(HIcon, FALSE);		
	LCtrl.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	LCtrl.InsertColumn(0, "编号", 2, 50);
	LCtrl.InsertColumn(1, "时间", 2, 200);
	LCtrl.InsertColumn(2, "长度", 2, 100);
	LCtrl.InsertColumn(3, "源MAC地址", 2, 200);
	LCtrl.InsertColumn(4, "目的MAC地址", 2, 200);
	LCtrl.InsertColumn(5, "协议", 2, 100);
	LCtrl.InsertColumn(6, "源IP地址", 2, 150);
	LCtrl.InsertColumn(7, "目的IP地址", 2, 150);
	CBNetCard.AddString("请选择网卡接口");
	CBFilterRule.AddString("请选择过滤规则");
	if (InitCap() < 0) 
		return FALSE;
	for (dev = allDevs; dev; dev = dev->next) 
		if (dev->description)
			CBNetCard.AddString(dev->description);
	CBFilterRule.AddString("TCP");
	CBFilterRule.AddString("UDP");
	CBFilterRule.AddString("IP");
	CBFilterRule.AddString("ICMP");
	CBFilterRule.AddString("ARP");
	CBNetCard.SetCurSel(0);
	CBFilterRule.SetCurSel(0);
	return TRUE; 
}


void CSnifferDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

void CSnifferDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); 
		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);
		int xIcon = GetSystemMetrics(SM_CXICON);
		int yIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - xIcon + 1) / 2;
		int y = (rect.Height() - yIcon + 1) / 2;
		dc.DrawIcon(x, y, HIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

HCURSOR CSnifferDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(HIcon);
}


int CSnifferDlg::InitCap() {                               
	devCount = 0;
	if (pcap_findalldevs(&allDevs, errorBufffer) == -1)
		return -1;
	for (dev = allDevs; dev; dev = dev->next)
		devCount++;
	return 0;
}

int CSnifferDlg::StartCap() {                              
	//STEP1
	int NetCardIndex = this->CBNetCard.GetCurSel();
	int FilterIndex = this->CBFilterRule.GetCurSel();
	if (NetCardIndex == 0 || NetCardIndex == CB_ERR) {
		MessageBox("请选择网卡接口!");
		return -1;
	}
	if (FilterIndex == CB_ERR) {
		MessageBox("过滤器选择错误");
		return -1;
	}

	//STEP2
	dev = allDevs;
	for (int i = 0; i < FilterIndex - 1; i++)
		dev = dev->next;

	//STEP3
	Handle_checken = pcap_open_live(dev->name, 65536, 1, 1000, errorBufffer);
	if (Handle_checken == NULL) {
		MessageBox("错误：无法打开接口：" + CString(dev->description));
		pcap_freealldevs(allDevs);
		return -1;
	}

	//STEP4
	if (pcap_datalink(Handle_checken) != DLT_EN10MB) {
		MessageBox("错误：非以太网的网络");
		pcap_freealldevs(allDevs);
		return -1;
	}

	//STEP5
	u_int netmask;
	if (dev->addresses != NULL)
		netmask = ((struct sockaddr_in *)(dev->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		netmask = 0xffffff;

	//STEP6
	struct bpf_program fcode;
	if (FilterIndex == 0) {
		char filter[] = "";
		if (pcap_compile(Handle_checken, &fcode, filter, 1, netmask) < 0) {
			MessageBox("错误：无法编译过滤器");
			pcap_freealldevs(allDevs);
			return -1;
		}
	}
	else {
		CString str;
		this->CBFilterRule.GetLBText(FilterIndex, str);
		int len = str.GetLength() + 1;
		char *filter = (char*)malloc(len);
		for (int i = 0; i < len; i++)
			filter[i] = str.GetAt(i);
		if (pcap_compile(Handle_checken, &fcode, filter, 1, netmask) < 0) {
			MessageBox("错误：无法编译过滤器");
			pcap_freealldevs(allDevs);
			return -1;
		}
	}

	//STEP7
	if (pcap_setfilter(Handle_checken, &fcode) < 0) {
		MessageBox("设置过滤器错误");
		pcap_freealldevs(allDevs);
		return -1;
	}

	//STEP8
	struct tm *localTime;
	time_t SecondSince1970;
	time(&SecondSince1970);
	localTime = localtime(&SecondSince1970);
	char realTime[30];
	strftime(realTime, sizeof(realTime), "%Y%m%d %H%M%S", localTime);

	//STEP9
	CFileFind file;
	if (!file.FindFile("Data"))
		CreateDirectory("Data", NULL);
	memset(Path, 0, sizeof(Path));
	memset(Name, 0, sizeof(Name));
	strcpy(Path, "Data\\");
	strcat(Name, realTime);
	strcat(Name, ".lix");
	strcat(Path, Name);
	dumpFile = pcap_dump_open(Handle_checken, Path);
	if (dumpFile == NULL){
		MessageBox("文件创建错误！");
		return -1;
	}

	//STEP10
	LPDWORD threadCap = NULL;
	ThreadHandle = CreateThread(NULL, 0, CapThread, this, 0, threadCap);
	if (ThreadHandle == NULL)	{
		CString str;
		str.Format("创建线程错误，代码为：%d.", GetLastError());
		MessageBox(str);
		return -1;
	}
	return 1;
}

/**THREAD**/

int CSnifferDlg::UpdatePacket() {		// UpdatePacket
	CString str;
	str.Format("%d", this->packetCount.num_arp);
	this->EARP.SetWindowText(str);

	str.Format("%d", this->packetCount.num_ip4);
	this->eIPv4.SetWindowText(str);

	str.Format("%d", this->packetCount.num_ip6);
	this->eIPv6.SetWindowText(str);

	str.Format("%d", this->packetCount.num_icmp4);
	this->eICMPv4.SetWindowText(str);

	str.Format("%d", this->packetCount.num_icmp6);
	this->eICMPv6.SetWindowText(str);

	str.Format("%d", this->packetCount.num_udp);
	this->eUDP.SetWindowText(str);

	str.Format("%d", this->packetCount.num_tcp);
	this->eTCP.SetWindowText(str);

	str.Format("%d", this->packetCount.num_http);
	this->eHTTP.SetWindowText(str);

	str.Format("%d", this->packetCount.num_other);
	this->eOther.SetWindowText(str);

	str.Format("%d", this->packetCount.num_sum);
	this->eSum.SetWindowText(str);

	return 1;
}

int CSnifferDlg::UpdateList(struct pcap_pkthdr *data_header, struct data_packet *data, const u_char *pkt_data) {		//UpdateList
	//Save
	u_char *data_packet_list;
	data_packet_list = (u_char*)malloc(data_header->len);
	memcpy(data_packet_list, pkt_data, data_header->len);

	this->LocalDataList.AddTail(data);
	this->NetDataList.AddTail(data_packet_list);

	//Len
	data->len = data_header->len;
	//Time
	time_t local_tv_sec = data_header->ts.tv_sec;
	struct tm *ltime = localtime(&local_tv_sec);
	data->time[0] = ltime->tm_year + 1900;
	data->time[1] = ltime->tm_mon + 1;
	data->time[2] = ltime->tm_mday;
	data->time[3] = ltime->tm_hour;
	data->time[4] = ltime->tm_min;
	data->time[5] = ltime->tm_sec;

	CString buffer;
	buffer.Format("%d", this->packetNum);
	int nextItem = this->LCtrl.InsertItem(this->packetNum, buffer);

	//Time
	CString timestr;
	timestr.Format("%d/%d/%d  %d:%d:%d", data->time[0],
		data->time[1], data->time[2], data->time[3], data->time[4], data->time[5]);
	this->LCtrl.SetItemText(nextItem, 1, timestr);

	//Len
	buffer.Empty();
	buffer.Format("%d", data->len);
	this->LCtrl.SetItemText(nextItem, 2, buffer);

	//Source MAC
	buffer.Empty();
	buffer.Format("%02X-%02X-%02X-%02X-%02X-%02X", data->ethh->src[0], data->ethh->src[1],
		data->ethh->src[2], data->ethh->src[3], data->ethh->src[4], data->ethh->src[5]);
	this->LCtrl.SetItemText(nextItem, 3, buffer);

	//Dest MAC
	buffer.Empty();
	buffer.Format("%02X-%02X-%02X-%02X-%02X-%02X", data->ethh->dest[0], data->ethh->dest[1],
		data->ethh->dest[2], data->ethh->dest[3], data->ethh->dest[4], data->ethh->dest[5]);
	this->LCtrl.SetItemText(nextItem, 4, buffer);

	//Protocol
	this->LCtrl.SetItemText(nextItem, 5, CString(data->type));

	//Source IP
	buffer.Empty();
	if (data->ethh->type == PROTO_ARP) {
		buffer.Format("%d.%d.%d.%d", data->arph->src_ip[0],
			data->arph->src_ip[1], data->arph->src_ip[2], data->arph->src_ip[3]);
	}
	else if (data->ethh->type == PROTO_IPV4) {
		struct  in_addr in;
		in.S_un.S_addr = data->ip4h->src_addr;
		buffer = CString(inet_ntoa(in));
	}
	else if (data->ethh->type == PROTO_IPV6) {
		for (int i = 0; i < 8; i++) {
			if (i <= 6)
				buffer.AppendFormat("%02x:", data->ip6h->src_addr[i]);
			else
				buffer.AppendFormat("%02x", data->ip6h->src_addr[i]);
		}
	}
	this->LCtrl.SetItemText(nextItem, 6, buffer);

	//Dest IP
	buffer.Empty();
	if (data->ethh->type == PROTO_ARP) {
		buffer.Format("%d.%d.%d.%d", data->arph->dest_ip[0],
			data->arph->dest_ip[1], data->arph->dest_ip[2], data->arph->dest_ip[3]);
	}
	else if (data->ethh->type == PROTO_IPV4) {
		struct in_addr in;
		in.S_un.S_addr = data->ip4h->dest_addr;
		buffer = CString(inet_ntoa(in));
	}
	else if (data->ethh->type == PROTO_IPV6) {
		for (int i = 0; i < 8; i++) {
			if (i <= 6)
				buffer.AppendFormat("%02x:", data->ip6h->dest_addr[i]);
			else
				buffer.AppendFormat("%02x", data->ip6h->dest_addr[i]);
		}
	}
	this->LCtrl.SetItemText(nextItem, 7, buffer);
	this->packetNum++;		//Count
	return 1;
}

DWORD WINAPI CapThread(LPVOID lpParameter) {
	CSnifferDlg *pthis = (CSnifferDlg*)lpParameter;
	if (pthis->ThreadHandle == NULL) {
		MessageBox(NULL, "线程句柄错误", "提示", MB_OK);
		return -1;
	}
	int flag;
	struct pcap_pkthdr *data_header;
	const u_char *pkt_data = NULL;
	while ((flag = pcap_next_ex(pthis->Handle_checken, &data_header, &pkt_data)) >= 0) {
		if (flag == 0)
			continue;
		struct data_packet *data = (struct data_packet*)malloc(sizeof(struct data_packet));
		memset(data, 0, sizeof(struct data_packet));
		if (data == NULL) {
			MessageBox(NULL, "无法接收新的数据包", "Error", MB_OK);
			return -1;
		}
		if (analyse_data_frame(pkt_data, data, &(pthis->packetCount)) < 0)
			continue;
		if (pthis->dumpFile != NULL)
			pcap_dump((unsigned char*)pthis->dumpFile, data_header, pkt_data);
		pthis->UpdatePacket();
		pthis->UpdateList(data_header, data, pkt_data);
	}
	return 1;
}

  /***GUI***/

int CSnifferDlg::SaveFile() {		//SaveFile
	CFileFind find;
	if (find.FindFile(CString(Path)) == NULL){
		MessageBox("UnkownError");
		return -1;
	}
	char szFilter[] = "lix文件(*.lix)|*.lix||";
	CFileDialog openDlg(FALSE, ".lix", 0, 0, szFilter);
	openDlg.m_ofn.lpstrInitialDir = "D:\\";
	if (openDlg.DoModal() == IDOK)
		CopyFile(CString(Path), openDlg.GetPathName(), TRUE);
	return 1;
}

int CSnifferDlg::ReadFile(CString path) {		//ReadFile
	int len = path.GetLength() + 1;
	char* charPath = (char *)malloc(len);
	memset(charPath, 0, len);
	if (charPath == NULL)
		return -1;
	for (int i = 0; i < len; i++)
		charPath[i] = (char)path.GetAt(i);
	pcap_t *fp;		//OpenFile
	if ((fp = pcap_open_offline(charPath, errorBufffer)) == NULL) {
		MessageBox("打开文件错误" + CString(errorBufffer));
		return -1;
	}
	struct pcap_pkthdr *data_header;
	const u_char *pkt_data = NULL;
	while (pcap_next_ex(fp, &data_header, &pkt_data) >= 0) {
		struct data_packet *data = (struct data_packet*)malloc(sizeof(struct data_packet));
		memset(data, 0, sizeof(struct data_packet));
		if (data == NULL) {
			MessageBox("无法接收新的数据包");
			return  -1;
		}
		if (analyse_data_frame(pkt_data, data, &(this->packetCount)) < 0)
			continue;

		this->UpdatePacket();
		this->UpdateList(data_header, data, pkt_data);
	}
	pcap_close(fp);
	return 1;
}

int CSnifferDlg::UpdateEdit(int index) {		//UpdateEdit
	POSITION localPos = this->LocalDataList.FindIndex(index);
	POSITION netPos = this->NetDataList.FindIndex(index);
	struct data_packet* localData = (struct data_packet*)(this->LocalDataList.GetAt(localPos));
	u_char * netData = (u_char*)(this->NetDataList.GetAt(netPos));
	CString buffer;
	this->FormatPacket(netData, localData->len, &buffer);
	this->Edit.SetWindowText(buffer);
	return 1;
}

void CSnifferDlg::FormatPacket(const u_char* packet, int packet_size, CString *buffer) {		//FormatPacket
	for (int i = 0; i < packet_size; i += 16) {      //HEX
		buffer->AppendFormat("%04x:  ", (u_int)i);
		int row = (packet_size - i) > 16 ? 16 : (packet_size - i);
		for (int j = 0; j < row; j++)
			buffer->AppendFormat("%02x  ", (u_int)packet[i + j]);
		if (row < 16)
			for (int j = row; j < 16; j++)
				buffer->AppendFormat("            ");
		for (int j = 0; j < row; j++) {		//CHAR
			u_char ch = packet[i + j];
			ch = isprint(ch) ? ch : '.';
			buffer->AppendFormat("%c", ch);
		}
		buffer->Append("\r\n");
		if (row < 16)
			return;
	}
}

int CSnifferDlg::UpdateTree(int index) {
	this->TCtrl.DeleteAllItems();
	POSITION localPos = this->LocalDataList.FindIndex(index);
	struct data_packet* localData = (struct data_packet*)(this->LocalDataList.GetAt(localPos));
	CString str;
	str.Format("第%d个数据包", index + 1);
	HTREEITEM root = this->TCtrl.GetRootItem();
	HTREEITEM data = this->TCtrl.InsertItem(str, root);
	return 1;
}

void CSnifferDlg::ClickStart() {
	if (this->LocalDataList.IsEmpty() == FALSE)
		if (MessageBox("确认不保存数据？", "警告", MB_YESNO) == IDNO)
			this->SaveFile();
	this->packetNum = 1; 
	this->LocalDataList.RemoveAll(); 
	this->NetDataList.RemoveAll();
	memset(&(this->packetCount), 0, sizeof(struct packet_count));
	this->UpdatePacket();
	if (this->StartCap() < 0)
		return;
	this->LCtrl.DeleteAllItems();
	this->TCtrl.DeleteAllItems();
	this->Edit.SetWindowText("");
	this->BTNStart.EnableWindow(FALSE);
	this->BTNStop.EnableWindow(TRUE);
	this->BTNSave.EnableWindow(FALSE);
}

void CSnifferDlg::ClickEnd() {
	if (this->ThreadHandle == NULL)
		return;
	if (TerminateThread(this->ThreadHandle, -1) == 0) {
		MessageBox("线程关闭错误，请稍后重试");
		return;
	}
	this->ThreadHandle = NULL;
	this->BTNStart.EnableWindow(TRUE);
	this->BTNStop.EnableWindow(FALSE);
	this->BTNSave.EnableWindow(TRUE);
}

void CSnifferDlg::ClickSave() {
	if (this->SaveFile() < 0)
		return;
}

void CSnifferDlg::ClickRead() {
	this->LCtrl.DeleteAllItems();
	this->packetNum = 1;
	this->LocalDataList.RemoveAll();
	this->NetDataList.RemoveAll();
	memset(&(this->packetCount), 0, sizeof(struct packet_count));
	char szFilter[] = "lix文件(*.lix)|*.lix||";
	CFileDialog FileDlg(TRUE, ".lix", 0, 0, szFilter);
	FileDlg.m_ofn.lpstrInitialDir = "D:\\";
	if (FileDlg.DoModal() == IDOK) {
		int ret = this->ReadFile(FileDlg.GetPathName());
		if (ret < 0)
			return;
	}
}

void CSnifferDlg::UpdateList(NMHDR *pNMHDR, LRESULT *pResult) {
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	POSITION pos = LCtrl.GetFirstSelectedItemPosition();
	int index = LCtrl.GetNextSelectedItem(pos); 
	if (index != -1) {
		this->UpdateEdit(index);
		this->UpdateTree(index);
	}
	*pResult = 0;
}

void CSnifferDlg::ChangeColor(NMHDR *pNMHDR, LRESULT *pResult) {
	LPNMLVCUSTOMDRAW pNMCD = (LPNMLVCUSTOMDRAW)pNMHDR;
	*pResult = 0;
	if (CDDS_PREPAINT == pNMCD->nmcd.dwDrawStage)
		*pResult = CDRF_NOTIFYITEMDRAW;
	else if(CDDS_ITEMPREPAINT == pNMCD->nmcd.dwDrawStage) {
		POSITION pos = this->LocalDataList.FindIndex(pNMCD->nmcd.dwItemSpec);
		struct data_packet * localData = (struct data_packet *)this->LocalDataList.GetAt(pos);
		char buffer[10];
		memset(buffer, 0, sizeof(buffer));
		strcpy(buffer, localData->type);
		COLORREF crText;
		if (!strcmp(buffer, "ARP"))
			crText = RGB(222, 234, 226);
		if (!strcmp(buffer, "IPv4"))
			crText = RGB(254, 180, 194);
		if (!strcmp(buffer, "IPv6"))
			crText = RGB(113, 220, 254);
		if(!strcmp(buffer, "UDP"))
			crText = RGB(197, 194, 251);
		if(!strcmp(buffer, "TCP"))
			crText = RGB(218, 214, 240);
		if(!strcmp(buffer, "ICMPv4"))
			crText = RGB(61, 155, 209);
		if(!strcmp(buffer, "ICMPv6"))
			crText = RGB(200, 245, 80);
		if (!strcmp(buffer, "HTTP"))
			crText = RGB(222, 221, 166);
		pNMCD->clrTextBk = crText;
		*pResult = CDRF_DODEFAULT;
	}
}
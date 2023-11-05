

#pragma once
#include "pcap.h"
#include "protocol.h"


class CSnifferDlg : public CDialogEx
{
public:
	CSnifferDlg(CWnd* pParent = nullptr);	

	int InitCap();
	int StartCap();

	int devCount;
	char errorBufffer[PCAP_ERRBUF_SIZE];
	pcap_if_t *allDevs;
	pcap_if_t *dev;
	pcap_t *Handle_checken;

	char Path[1024];
	char Name[1024];
	pcap_dumper_t *dumpFile;

	HANDLE ThreadHandle;
	struct packet_count packetCount;
	int packetNum;
	CPtrList LocalDataList;
	CPtrList NetDataList;

	int UpdatePacket();
	int UpdateList(struct pcap_pkthdr *data_header, struct data_packet *data, const u_char *pkt_data);
	int SaveFile();
	int ReadFile(CString path);
	int UpdateEdit(int index);
	void FormatPacket(const u_char* packet, int packet_size, CString *bufffer);
	int UpdateTree(int index);

#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_SNIFFER_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	


protected:
	HICON HIcon;

	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CComboBox CBNetCard;
	CComboBox CBFilterRule;
	CListCtrl LCtrl;
	CTreeCtrl TCtrl;
	CEdit Edit;
	CButton BTNStart;
	CButton BTNStop;
	CButton BTNSave;
	CButton BTNRead;
	CEdit EARP;
	CEdit eIPv4;
	CEdit eIPv6;
	CEdit eICMPv4;
	CEdit eICMPv6;
	CEdit eUDP;
	CEdit eTCP;
	CEdit eHTTP;
	CEdit eOther;
	CEdit eSum;
	
	afx_msg void ClickStart();
	afx_msg void ClickEnd();
	afx_msg void ClickSave();
	afx_msg void ClickRead();
	afx_msg void UpdateList(NMHDR *pNMHDR, LRESULT *pResult);//列表更新
	afx_msg void ChangeColor(NMHDR *pNMHDR, LRESULT *pResult);//列表项颜色变换
};

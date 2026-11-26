#include "mainwindow.hpp"
#include "netscope/parser.hpp"
#include "netscope/filter.hpp"
#include "netscope/pcap.hpp"
#include <QAction>
#include <QActionGroup>
#include <QSettings>
#include <QKeySequence>
#include <QFile>
#include <QTextStream>
#include <QDateTime>
#include <QStyle>
#include <QFileDialog>
#include <QFileInfo>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QFrame>
#include <QProgressBar>
#include <QScrollArea>
#include <QGroupBox>
#include <QToolBar>
#include <QSignalBlocker>
#include <QBrush>
#include <QColor>
#include <QLabel>
#include <QLineEdit>
#include <QMenuBar>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QSplitter>
#include <QStatusBar>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableView>
#include <QItemSelectionModel>
#include <QMetaObject>
#include <QPointer>
#include <QThread>
#include <QTreeWidget>
#include <QVBoxLayout>
#include <QWidget>
#include <algorithm>
#include <iomanip>
#include <limits>
#include <map>
#include <sstream>
#include <stdexcept>

namespace {
QString qstr(const std::string& s) { return QString::fromStdString(s); }
void put(QTableWidget* table,int row,int col,const QString& value) {
 auto* item=new QTableWidgetItem(value);
 item->setFlags(item->flags() & ~Qt::ItemIsEditable);
 table->setItem(row,col,item);
}
void setupTable(QTableWidget* table,const QStringList& headers) {
 table->setColumnCount(headers.size());
 table->setHorizontalHeaderLabels(headers);
 table->setSelectionBehavior(QAbstractItemView::SelectRows);
 table->setSelectionMode(QAbstractItemView::SingleSelection);
 table->setEditTriggers(QAbstractItemView::NoEditTriggers);
 table->setAlternatingRowColors(true);
 table->horizontalHeader()->setStretchLastSection(true);
 table->verticalHeader()->hide();
}
}
MainWindow::MainWindow(QWidget* parent):QMainWindow(parent) {
 setWindowTitle("NetScope v1.0 — Network Traffic Analyzer");
 resize(1200,800);
 auto* fileMenu=menuBar()->addMenu("&File");
 auto* open=fileMenu->addAction("&Open PCAP...");
 openAction_=open;
 open->setShortcut(QKeySequence::Open);
 connect(open,&QAction::triggered,this,[this]{openCapture();});
 fileMenu->addSeparator();
 auto* quit=fileMenu->addAction("E&xit");
 connect(quit,&QAction::triggered,this,&QWidget::close);
 auto* viewMenu=menuBar()->addMenu("&View");
 auto* themeMenu=viewMenu->addMenu("&Appearance");
 auto* themeGroup=new QActionGroup(this);
 lightThemeAction_=themeMenu->addAction("Light theme");
 darkThemeAction_=themeMenu->addAction("Dark theme");
 for(auto* action : {lightThemeAction_,darkThemeAction_}) {action->setCheckable(true);themeGroup->addAction(action);}
 connect(lightThemeAction_,&QAction::triggered,this,[this]{applyTheme(false);});
 connect(darkThemeAction_,&QAction::triggered,this,[this]{applyTheme(true);});
 auto* helpMenu=menuBar()->addMenu("&Help");
 auto* aboutAction=helpMenu->addAction("&About NetScope...");
 connect(aboutAction,&QAction::triggered,this,[this]{
  QMessageBox::about(this,"About NetScope", "NetScope v1.0\nOffline Network Traffic Analyzer\n\nC++20 + Qt 6\nIndexed PCAP access, bounded raw-byte cache, flow and conversation analytics.\n\nOpen-source portfolio project. Offline captures only.");
 });
 auto* toolbar=addToolBar("Capture");
 toolbar->setMovable(false);
 toolbar->addAction(open);
 open->setIcon(style()->standardIcon(QStyle::SP_DialogOpenButton));
 auto* exportPacketAction=fileMenu->addAction("Export &Packets CSV...");
 auto* exportFlowAction=fileMenu->addAction("Export &Flows CSV...");
 auto* exportConversationAction=fileMenu->addAction("Export &Conversations CSV...");
 exportPacketAction->setToolTip("Export visible packet metadata as CSV");
 toolbar->addSeparator();
 toolbar->addAction(exportPacketAction);
 toolbar->addAction(exportFlowAction);
 toolbar->addAction(exportConversationAction);
 connect(exportPacketAction,&QAction::triggered,this,[this]{exportPackets();});
 connect(exportFlowAction,&QAction::triggered,this,[this]{exportFlows();});
 connect(exportConversationAction,&QAction::triggered,this,[this]{exportConversations();});
 auto* root=new QWidget(this);
 auto* layout=new QVBoxLayout(root);
 auto* heading=new QLabel("NetScope   /   Offline Network Traffic Analysis",root);
 heading->setObjectName("pageHeading");
 layout->addWidget(heading);
 filter_=new QLineEdit(root);
 filter_->setPlaceholderText("Filter: tcp  |  udp.port == 53  |  ip.src == 192.168.1.10  |  frame.number == 1");
 layout->addWidget(filter_);
 filterStatus_=new QLabel("Filter: all packets",root);
 filterStatus_->setObjectName("filterStatus");
 layout->addWidget(filterStatus_);
 connect(filter_,&QLineEdit::textChanged,this,[this]{refreshFilter();});
 tabs_=new QTabWidget(root);
 auto* packetPage=new QWidget(tabs_);
 auto* packetLayout=new QVBoxLayout(packetPage);
 auto* split=new QSplitter(Qt::Vertical,packetPage);
 mainSplitter_=split;
 split->setChildrenCollapsible(false);
 packetTable_=new QTableView(split);
 packetModel_=new PacketModel(this);
 packetProxy_=new PacketProxy(this);
 packetProxy_->setSourceModel(packetModel_);
 packetTable_->setModel(packetProxy_);
 packetTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
 packetTable_->setSelectionMode(QAbstractItemView::SingleSelection);
 packetTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
 packetTable_->setAlternatingRowColors(true);
 packetTable_->setSortingEnabled(true);
 packetTable_->verticalHeader()->hide();
 packetTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
 split->addWidget(packetTable_);
 auto* lower=new QSplitter(Qt::Horizontal,split);
 details_=new QTreeWidget(lower);
 details_->setHeaderLabel("Decoded packet fields");
 hex_=new QPlainTextEdit(lower);
 hex_->setReadOnly(true);
 hex_->setPlaceholderText("Select a packet to view its bytes");
 hex_->setObjectName("hexViewer");
 lower->addWidget(details_);
 lower->addWidget(hex_);
 lower->setSizes({450,650});
 lower->setChildrenCollapsible(false);
 split->addWidget(lower);
 split->setStretchFactor(0,3);
 split->setStretchFactor(1,2);
 split->setSizes({390,340});
 packetLayout->addWidget(split);
 tabs_->addTab(packetPage,"Packets");
 flowTable_=new QTableWidget(tabs_);
 setupTable(flowTable_,{"Source IP","Src Port","Destination IP","Dst Port","Protocol","Packets","Bytes"});
 flowTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
 flowTable_->setSortingEnabled(true);
 tabs_->addTab(flowTable_,"Flows");
 conversationTable_=new QTableWidget(tabs_);
 setupTable(conversationTable_,{"Endpoint A","Endpoint B","Protocol","A → B pkts","B → A pkts","Total bytes","Duration (s)","Avg bps","TCP state"});
 conversationTable_->setSortingEnabled(true);
 conversationTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
 tabs_->addTab(conversationTable_,"Conversations");
 auto* summaryPage=new QWidget(tabs_);
 auto* summaryLayout=new QVBoxLayout(summaryPage);
 summaryLayout->setSpacing(12);
 summary_=new QLabel("Open a PCAP file to see traffic statistics.",summaryPage);
 summary_->setTextInteractionFlags(Qt::TextSelectableByMouse);
 summary_->setObjectName("summaryCard");
 summaryLayout->addWidget(summary_);
 auto* chartRow=new QHBoxLayout();
 auto* protocolGroup=new QGroupBox("Protocol distribution",summaryPage);
 protocolBars_=new QVBoxLayout(protocolGroup);
 auto* talkerGroup=new QGroupBox("Top source IPs",summaryPage);
 talkerBars_=new QVBoxLayout(talkerGroup);
 chartRow->addWidget(protocolGroup,1);
 chartRow->addWidget(talkerGroup,1);
 summaryLayout->addLayout(chartRow);
 auto* timelineGroup=new QGroupBox("Traffic over time (1-second buckets)",summaryPage);
 auto* timeLayout=new QVBoxLayout(timelineGroup);
 timelineTable_=new QTableWidget(timelineGroup);
 setupTable(timelineTable_,{"Timestamp (UTC)","Packets","Bytes","Relative traffic"});
 timelineTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
 timeLayout->addWidget(timelineTable_);
 summaryLayout->addWidget(timelineGroup,1);
 tabs_->addTab(summaryPage,"Dashboard");
 layout->addWidget(tabs_);
 setCentralWidget(root);
 status_=new QLabel("Ready — File > Open PCAP (Ctrl+O)",this);
 statusBar()->addWidget(status_);
 loadProgress_=new QProgressBar(this);
 loadProgress_->setRange(0,0);
 loadProgress_->setFixedWidth(160);
 loadProgress_->hide();
 statusBar()->addPermanentWidget(loadProgress_);
 connect(packetTable_->selectionModel(),&QItemSelectionModel::selectionChanged,this,[this]{showPacketDetails();});
 restorePreferences();
}
void MainWindow::openCapture() {
 const auto path=QFileDialog::getOpenFileName(this,"Open Ethernet PCAP",{},"PCAP captures (*.pcap *.cap);;All files (*)");
 if(!path.isEmpty()) loadCapture(path);
}
MainWindow::~MainWindow() {
 QSettings("NetScope Project","NetScope").setValue("window/size",size());
 if(cancelLoad_) cancelLoad_->store(true);
 if(loadThread_) {loadThread_->wait(); delete loadThread_; loadThread_=nullptr;}
}
void MainWindow::loadCapture(const QString& filename) {
 if(loadThread_) return;
 struct LoadResult {
  std::vector<CapturedPacket> packets;
  std::unique_ptr<netscope::IndexedPcap> indexed;
  netscope::FlowTracker tracker;
  netscope::ConversationTracker conversations;
  netscope::TrafficTimeline timeline;
  QString error;
  bool cancelled=false;
  bool capped=false;
 };
 auto result=std::make_shared<LoadResult>();
 cancelLoad_=std::make_shared<std::atomic_bool>(false);
 auto cancelled=cancelLoad_;
 const auto path=filename.toStdString();
 openAction_->setEnabled(false);
 loadProgress_->show();
 status_->setText("Loading capture in background: "+filename);
 loadThread_=QThread::create([result,cancelled,path]{
  try {
   result->indexed=std::make_unique<netscope::IndexedPcap>(path);
   const auto& entries=result->indexed->entries();
   result->packets.reserve(entries.size());
   // Sequential scan avoids reopening the PCAP once for every packet.
   // Raw bytes are discarded after decoding; only metadata is retained.
   size_t i=0;
   netscope::read_pcap_records(path,[&](const netscope::PcapRecord& record){
    if(cancelled->load()) throw std::runtime_error("Load cancelled");
    if(i>=entries.size() || entries[i].captured_length!=record.bytes.size() ||
       entries[i].timestamp_us!=record.timestamp_us)
     throw std::runtime_error("PCAP changed while loading");
    result->timeline.observe(record.timestamp_us,static_cast<uint32_t>(record.bytes.size()));
    CapturedPacket item;
    item.captured_length=static_cast<uint32_t>(record.bytes.size());
    item.timestamp_us=record.timestamp_us;
    if(auto decoded=netscope::decode_ethernet(record.bytes)) {
     item.decoded=true;
     item.packet=*decoded;
     result->tracker.observe(*decoded);
     result->conversations.observe(*decoded,record.timestamp_us);
    }
    result->packets.push_back(std::move(item));
    ++i;
   });
   if(i!=entries.size()) throw std::runtime_error("PCAP changed while loading");
  } catch(const std::exception& e) {
   if(cancelled->load()) result->cancelled=true;
   else if(!result->capped) result->error=QString::fromUtf8(e.what());
  }
 });
 connect(loadThread_,&QThread::finished,this,[this,result,filename]{
  // The thread has finished writing result; GUI state changes only here.
  loadProgress_->hide();
  openAction_->setEnabled(true);
  if(!result->error.isEmpty()) {
   QMessageBox::critical(this,"Unable to open PCAP",result->error);
   status_->setText("Capture load failed");
  } else if(!result->cancelled) {
   packetModel_->setPackets(nullptr);
   packets_=std::move(result->packets);
   indexed_=std::move(result->indexed);
   cache_.clear();
   tracker_=std::move(result->tracker);
   conversations_=std::move(result->conversations);
   timeline_=std::move(result->timeline);
   currentFile_=filename;
   setWindowTitle("NetScope v1.0 — "+QFileInfo(filename).fileName());
   filter_->clear();
   packetModel_->setPackets(&packets_);
   refreshFilter();
   refreshFlows();
   refreshConversations();
   refreshSummary();
   refreshTimeline();
   status_->setText(QString("Indexed %1 frames, %2 flows%4 — %3")
    .arg(static_cast<qulonglong>(packets_.size()))
    .arg(static_cast<qulonglong>(tracker_.flow_count())).arg(filename)
    .arg(result->capped ? " (100,000 packet GUI safety limit)" : ""));
   tabs_->setCurrentIndex(0);
  }
  loadThread_->deleteLater();
  loadThread_=nullptr;
  cancelLoad_.reset();
 });
 loadThread_->start();
}
void MainWindow::refreshFilter() {
 const auto expression=netscope::parse_filter(filter_->text().trimmed().toStdString());
 const auto selected=packetTable_->selectionModel()->selectedRows();
 int sourceRow=-1;
 if(!selected.isEmpty()) sourceRow=packetProxy_->mapToSource(selected.first()).row();
 packetProxy_->setExpression(expression);
 int selectedProxyRow=-1;
 if(sourceRow>=0) selectedProxyRow=packetProxy_->mapFromSource(packetModel_->index(sourceRow,0)).row();
 if(selectedProxyRow<0 && packetProxy_->rowCount()>0) selectedProxyRow=0;
 if(selectedProxyRow>=0) packetTable_->selectRow(selectedProxyRow);
 if(expression.kind==netscope::PacketFilter::Kind::Invalid) {
  filterStatus_->setText("Invalid filter: "+qstr(expression.error));
  filterStatus_->setStyleSheet("font-size:11px;color:#b42318;");
 } else {
  filterStatus_->setText(QString("Showing %1 of %2 frames  •  TCP blue / UDP green / ICMP amber")
   .arg(packetProxy_->rowCount()).arg(static_cast<qulonglong>(packets_.size())));
  filterStatus_->setStyleSheet("font-size:11px;color:#52647a;");
 }
 showPacketDetails();
}
void MainWindow::showPacketDetails() {
 details_->clear();hex_->clear();
 const auto selected=packetTable_->selectionModel()->selectedRows();
 if(selected.isEmpty()) return;
 const auto sourceIndex=packetProxy_->mapToSource(selected.first());
 if(!sourceIndex.isValid()) return;
 const auto index=static_cast<size_t>(sourceIndex.row());
 if(index>=packets_.size()) return;
 const auto& capture=packets_[index];
 auto* frame=new QTreeWidgetItem(details_,{"Frame " + QString::number(index+1)});
 frame->addChild(new QTreeWidgetItem({"Captured length: " + QString::number(capture.captured_length) + " bytes"}));
 if(capture.decoded) {
  const auto& p=capture.packet;
  auto* ipv4=new QTreeWidgetItem(details_,{"IPv4"});
  ipv4->addChild(new QTreeWidgetItem({"Source: " + qstr(p.source_ip)}));
  ipv4->addChild(new QTreeWidgetItem({"Destination: " + qstr(p.destination_ip)}));
  ipv4->addChild(new QTreeWidgetItem({"TTL: " + QString::number(p.ipv4_ttl)}));
  ipv4->addChild(new QTreeWidgetItem({"Header length: " + QString::number(p.ipv4_header_length) + " bytes"}));
  auto* transport=new QTreeWidgetItem(details_,{qstr(p.protocol)});
  if(p.protocol=="TCP"||p.protocol=="UDP") {
   transport->addChild(new QTreeWidgetItem({"Source port: " + QString::number(p.source_port)}));
   transport->addChild(new QTreeWidgetItem({"Destination port: " + QString::number(p.destination_port)}));
  }
  if(p.protocol=="TCP") {
   transport->addChild(new QTreeWidgetItem({"TCP flags: 0x"+QString::number(p.tcp_flags,16)+" ("+qstr(netscope::tcp_flag_names(p.tcp_flags))+")"}));
   transport->addChild(new QTreeWidgetItem({"Sequence number: " + QString::number(p.tcp_sequence)}));
   transport->addChild(new QTreeWidgetItem({"Acknowledgment number: " + QString::number(p.tcp_acknowledgment)}));
   transport->addChild(new QTreeWidgetItem({"TCP header length: " + QString::number(p.tcp_header_length) + " bytes"}));
   transport->addChild(new QTreeWidgetItem({"Window size: " + QString::number(p.tcp_window)}));
  }
  if(p.protocol=="ICMP") {
   transport->addChild(new QTreeWidgetItem({"Type: " + QString::number(p.icmp_type)}));
   transport->addChild(new QTreeWidgetItem({"Code: " + QString::number(p.icmp_code)}));
  }
 } else {
  new QTreeWidgetItem(details_,{"Unsupported or malformed Ethernet/IPv4 packet"});
 }
 details_->expandAll();
 try {
  if(indexed_) hex_->setPlainText(hexDump(cache_.get(*indexed_,index)));
 } catch(const std::exception& e) { hex_->setPlainText(QString("Unable to load packet bytes: ")+e.what()); }
}
void MainWindow::refreshFlows() {
 const auto records=tracker_.top_flows(tracker_.flow_count());
 flowTable_->setSortingEnabled(false);
 flowTable_->setRowCount(static_cast<int>(records.size()));
 for(int row=0;row<static_cast<int>(records.size());++row) {
  const auto& f=records[static_cast<size_t>(row)];
  const QStringList values={qstr(f.key.source_ip),QString::number(f.key.source_port),
   qstr(f.key.destination_ip),QString::number(f.key.destination_port),qstr(f.key.protocol),
   QString::number(f.stats.packets),QString::number(f.stats.bytes)};
  for(int col=0;col<values.size();++col) {
   if(col==1||col==3||col==5||col==6) {auto* cell=new QTableWidgetItem();cell->setData(Qt::DisplayRole,values[col].toULongLong());flowTable_->setItem(row,col,cell);}
   else put(flowTable_,row,col,values[col]);
  }
 }
 flowTable_->setSortingEnabled(true);
}
void MainWindow::refreshConversations() {
 const auto records=conversations_.top_conversations(conversations_.count());
 conversationTable_->setSortingEnabled(false);
 conversationTable_->setRowCount(static_cast<int>(records.size()));
 for(int row=0;row<static_cast<int>(records.size());++row){
  const auto& c=records[static_cast<size_t>(row)];
  put(conversationTable_,row,0,qstr(c.key.a.ip)+":"+QString::number(c.key.a.port));
  put(conversationTable_,row,1,qstr(c.key.b.ip)+":"+QString::number(c.key.b.port));
  put(conversationTable_,row,2,qstr(c.key.protocol));
  const auto setNumber=[this,row](int col,qulonglong n){auto* item=new QTableWidgetItem();item->setData(Qt::DisplayRole,n);conversationTable_->setItem(row,col,item);};
  setNumber(3,c.stats.packets_a_to_b);setNumber(4,c.stats.packets_b_to_a);setNumber(5,c.stats.bytes());
  auto* duration=new QTableWidgetItem();duration->setData(Qt::DisplayRole,static_cast<double>(c.stats.duration_us())/1e6);conversationTable_->setItem(row,6,duration);
  auto* rate=new QTableWidgetItem();rate->setData(Qt::DisplayRole,c.stats.throughput_bps());conversationTable_->setItem(row,7,rate);
  put(conversationTable_,row,8,c.key.protocol=="TCP"?qstr(c.stats.tcp_state()):"—");
 }
 conversationTable_->setSortingEnabled(true);
}
void MainWindow::populateBars(QVBoxLayout* layout,const std::vector<std::pair<QString,size_t>>& data,size_t total) {
 while(auto* item=layout->takeAt(0)) {
  if(item->widget()) delete item->widget();
  delete item;
 }
 for(size_t i=0;i<std::min<size_t>(8,data.size());++i) {
  const auto& [name,count]=data[i];
  auto* label=new QLabel(QString("%1  —  %2 packets").arg(name).arg(static_cast<qulonglong>(count)));
  layout->addWidget(label);
  auto* bar=new QProgressBar();
  bar->setRange(0,1000);
  bar->setValue(total?static_cast<int>(1000.0*count/total):0);
  bar->setFormat(total?QString::number(100.0*count/total,'f',1)+"%":"0%");
  layout->addWidget(bar);
 }
 if(data.empty()) layout->addWidget(new QLabel("No decoded traffic"));
 layout->addStretch();
}
void MainWindow::refreshSummary() {
 std::map<std::string,size_t> protocols,talkers;
 size_t decoded=0;
 for(const auto& capture:packets_) {
  if(!capture.decoded) continue;
  ++decoded;
  ++protocols[capture.packet.protocol];
  ++talkers[capture.packet.source_ip];
 }
 summary_->setText(QString("%1     |     %2 frames     |     %3 decoded IPv4     |     %4 directional flows | %5 conversations")
  .arg(QFileInfo(currentFile_).fileName())
  .arg(static_cast<qulonglong>(packets_.size()))
  .arg(static_cast<qulonglong>(decoded))
  .arg(static_cast<qulonglong>(tracker_.flow_count()))
  .arg(static_cast<qulonglong>(conversations_.count())));
 auto rank=[](const std::map<std::string,size_t>& counts) {
  std::vector<std::pair<QString,size_t>> result;
  for(const auto& [name,count]:counts) result.emplace_back(qstr(name),count);
  std::sort(result.begin(),result.end(),[](const auto& a,const auto& b){return a.second==b.second?a.first<b.first:a.second>b.second;});
  return result;
 };
 populateBars(protocolBars_,rank(protocols),decoded);
 populateBars(talkerBars_,rank(talkers),decoded);
}
QString MainWindow::hexDump(const std::vector<uint8_t>& bytes) {
 std::ostringstream out;
 for(size_t i=0;i<bytes.size();i+=16) {
  out<<std::hex<<std::setfill('0')<<std::setw(8)<<i<<"  ";
  for(size_t j=0;j<16;++j) {
   if(i+j<bytes.size()) out<<std::setw(2)<<static_cast<unsigned>(bytes[i+j])<<' ';
   else out<<"   ";
  }
  out<<" |";
  for(size_t j=0;j<16&&i+j<bytes.size();++j) {
   const unsigned char c=bytes[i+j];
   out<<(c>=32&&c<=126?static_cast<char>(c):'.');
  }
  out<<"|\n";
 }
 return QString::fromStdString(out.str());
}

void MainWindow::refreshTimeline() {
 const auto buckets=timeline_.buckets();
 timelineTable_->setRowCount(static_cast<int>(buckets.size()));
 uint64_t peak=1;
 for(const auto& b:buckets) peak=std::max(peak,b.bytes);
 for(int i=0;i<static_cast<int>(buckets.size());++i) {
  const auto& b=buckets[static_cast<size_t>(i)];
  put(timelineTable_,i,0,QDateTime::fromSecsSinceEpoch(static_cast<qint64>(b.second),Qt::UTC).toString("yyyy-MM-dd HH:mm:ss"));
  put(timelineTable_,i,1,QString::number(b.packets));
  put(timelineTable_,i,2,QString::number(b.bytes));
  auto* bar=new QProgressBar(timelineTable_);
  bar->setRange(0,1000);
  bar->setValue(static_cast<int>(1000.0*static_cast<double>(b.bytes)/peak));
  bar->setFormat(QString::number(b.bytes)+" bytes");
  timelineTable_->setCellWidget(i,3,bar);
 }
}
void MainWindow::exportPackets() {
 if(packets_.empty()) {QMessageBox::information(this,"No packets","Open a PCAP file first.");return;}
 const auto path=QFileDialog::getSaveFileName(this,"Export packets", "packets.csv", "CSV (*.csv)");
 if(path.isEmpty()) return;
 QFile file(path);
 if(!file.open(QIODevice::WriteOnly|QIODevice::Text)) {QMessageBox::warning(this,"Export failed",file.errorString());return;}
 QTextStream out(&file);
 out<<"Frame,TimestampUTC,SourceIP,DestinationIP,Protocol,SourcePort,DestinationPort,Length,TCPFlags\n";
 for(size_t i=0;i<packets_.size();++i) {
  const auto& c=packets_[i];const auto& p=c.packet;
  out<<i+1<<","<<QDateTime::fromMSecsSinceEpoch(static_cast<qint64>(c.timestamp_us/1000),Qt::UTC).toString("yyyy-MM-ddTHH:mm:ss.zzzZ")<<",";
  out<<qstr(netscope::csv_escape(c.decoded?p.source_ip:""))<<","<<qstr(netscope::csv_escape(c.decoded?p.destination_ip:""))<<",";
  out<<qstr(netscope::csv_escape(c.decoded?p.protocol:""))<<","<<p.source_port<<","<<p.destination_port<<","<<c.captured_length<<",";
  out<<(p.protocol=="TCP"?qstr(netscope::tcp_flag_names(p.tcp_flags)):QString())<<"\n";
 }
 status_->setText("Exported packet CSV: "+path);
}
void MainWindow::exportFlows() {
 if(packets_.empty()) {QMessageBox::information(this,"No capture","Open a PCAP file first.");return;}
 const auto path=QFileDialog::getSaveFileName(this,"Export flows","flows.csv","CSV (*.csv)");
 if(path.isEmpty()) return;
 QFile file(path);
 if(!file.open(QIODevice::WriteOnly|QIODevice::Text)) {QMessageBox::warning(this,"Export failed",file.errorString());return;}
 QTextStream out(&file);
 out<<"SourceIP,SourcePort,DestinationIP,DestinationPort,Protocol,Packets,Bytes\n";
 for(const auto& f:tracker_.top_flows(tracker_.flow_count())) {
  out<<qstr(netscope::csv_escape(f.key.source_ip))<<","<<f.key.source_port<<",";
  out<<qstr(netscope::csv_escape(f.key.destination_ip))<<","<<f.key.destination_port<<",";
  out<<qstr(netscope::csv_escape(f.key.protocol))<<","<<f.stats.packets<<","<<f.stats.bytes<<"\n";
 }
 status_->setText("Exported flow CSV: "+path);
}

void MainWindow::exportConversations(){
 if(conversations_.count()==0){QMessageBox::information(this,"No conversations","Open a PCAP with TCP/UDP traffic first.");return;}
 const auto path=QFileDialog::getSaveFileName(this,"Export conversations","conversations.csv","CSV (*.csv)");
 if(path.isEmpty())return;
 QFile file(path);
 if(!file.open(QIODevice::WriteOnly|QIODevice::Text)){QMessageBox::warning(this,"Export failed",file.errorString());return;}
 QTextStream out(&file);
 out<<"EndpointA,PortA,EndpointB,PortB,Protocol,PacketsAtoB,PacketsBtoA,BytesAtoB,BytesBtoA,DurationSeconds,AverageBitsPerSecond,TCPState\n";
 for(const auto& c:conversations_.top_conversations(conversations_.count())){
  out<<qstr(netscope::csv_escape(c.key.a.ip))<<","<<c.key.a.port<<","<<qstr(netscope::csv_escape(c.key.b.ip))<<","<<c.key.b.port<<","<<qstr(c.key.protocol)<<",";
  out<<c.stats.packets_a_to_b<<","<<c.stats.packets_b_to_a<<","<<c.stats.bytes_a_to_b<<","<<c.stats.bytes_b_to_a<<",";
  out<<QString::number(static_cast<double>(c.stats.duration_us())/1e6,'f',6)<<","<<QString::number(c.stats.throughput_bps(),'f',1)<<",";
  out<<(c.key.protocol=="TCP"?qstr(c.stats.tcp_state()):QString())<<"\n";
 }
 status_->setText("Exported conversation CSV: "+path);
}

void MainWindow::restorePreferences() {
 QSettings settings("NetScope Project","NetScope");
 const bool dark=settings.value("appearance/dark",false).toBool();
 applyTheme(dark);
 const auto savedSize=settings.value("window/size").toSize();
 if(savedSize.isValid() && savedSize.width()>=700 && savedSize.height()>=450) resize(savedSize);
}
void MainWindow::applyTheme(bool dark) {
 darkTheme_=dark;
 if(lightThemeAction_) lightThemeAction_->setChecked(!dark);
 if(darkThemeAction_) darkThemeAction_->setChecked(dark);
 const QString css=dark ? QString::fromUtf8(R"CSS(
 QMainWindow,QWidget{background:#121b2b;color:#e8eff9;font-size:12px}
 QMenuBar,QMenu,QToolBar,QStatusBar{background:#19263a;color:#e8eff9;border:0}
 QMenuBar::item:selected,QMenu::item:selected{background:#2c476b}
 QToolButton,QPushButton{background:#253954;color:#e8eff9;border:1px solid #395374;border-radius:5px;padding:7px}
 QToolButton:hover,QPushButton:hover{background:#31537c}
 QLabel#pageHeading{font-size:20px;font-weight:700;padding:12px;color:#f0f6ff}
 QLabel#filterStatus{color:#9ab0c9;padding-left:4px}
 QLabel#summaryCard{font-size:15px;font-weight:600;padding:12px;background:#1b2a40;border:1px solid #334963;border-radius:7px}
 QTabWidget::pane{border:1px solid #334963;background:#172337}
 QTabBar::tab{background:#1a2940;color:#b9c9dc;padding:10px 18px;border:1px solid #334963}
 QTabBar::tab:selected{background:#284c78;color:white;font-weight:700}
 QLineEdit{padding:10px;border:1px solid #46607e;border-radius:6px;background:#1b2a40;color:white}
 QTableView,QTableWidget,QTreeWidget,QPlainTextEdit{background:#172337;alternate-background-color:#20314a;color:#e8eff9;border:1px solid #334963;gridline-color:#30445e;selection-background-color:#2469a8;selection-color:white}
 QHeaderView::section{background:#273b55;color:#f1f6ff;padding:8px;border:0;border-right:1px solid #405675;font-weight:600}
 QGroupBox{font-weight:600;border:1px solid #344b66;border-radius:7px;margin-top:12px;padding:10px;background:#1a2940}
 QGroupBox::title{subcontrol-origin:margin;left:12px;padding:0 5px}
 QProgressBar{background:#2a3d58;border:0;border-radius:4px;text-align:center;min-height:16px}
 QProgressBar::chunk{background:#39a2ff;border-radius:4px}
 QSplitter::handle{background:#334963}
 QScrollBar{background:#1b2a40}
 )CSS") : QString::fromUtf8(R"CSS(
 QMainWindow{background:#f3f6fb} QWidget{font-size:12px}
 QToolBar{background:#eaf0f8;border:0;spacing:6px;padding:5px}
 QToolButton,QPushButton{padding:6px;border-radius:5px}
 QLabel#pageHeading{font-size:20px;font-weight:700;padding:12px;color:#17385d}
 QLabel#filterStatus{font-size:11px;color:#52647a;padding-left:4px}
 QLabel#summaryCard{font-size:15px;font-weight:600;padding:12px;background:white;border:1px solid #dce4ee;border-radius:7px}
 QTabWidget::pane{border:1px solid #dbe2ec;background:white}
 QTabBar::tab{padding:10px 18px}
 QTabBar::tab:selected{background:white;color:#1558a6;font-weight:700}
 QLineEdit{padding:10px;border:1px solid #cad5e2;border-radius:6px;background:white}
 QTreeWidget,QTableWidget,QTableView,QPlainTextEdit{background:white;border:1px solid #e1e6ee;gridline-color:#e9edf3}
 QHeaderView::section{background:#eaf0f8;padding:8px;border:0;border-right:1px solid #d9e1eb;font-weight:600}
 QGroupBox{font-weight:600;border:1px solid #dce4ee;border-radius:7px;margin-top:12px;padding:10px;background:white}
 QGroupBox::title{subcontrol-origin:margin;left:12px;padding:0 5px}
 QProgressBar{background:#eaf0f7;border:0;border-radius:4px;text-align:center;min-height:16px}
 QProgressBar::chunk{background:#3182ce;border-radius:4px}
 )CSS");
 setStyleSheet(css);
 QSettings("NetScope Project","NetScope").setValue("appearance/dark",dark);
}

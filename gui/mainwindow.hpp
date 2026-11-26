#pragma once
#include "netscope/flow.hpp"
#include "netscope/conversation.hpp"
#include "netscope/filter.hpp"
#include "netscope/analytics.hpp"
#include "capture.hpp"
#include "netscope/indexed_pcap.hpp"
#include "packetmodel.hpp"
#include <QPointer>
#include <QThread>
#include <atomic>
#include <memory>
#include <QMainWindow>
#include <QString>
#include <cstdint>
#include <vector>
class QTableWidget;
class QTableView;
class QTreeWidget;
class QPlainTextEdit;
class QLabel;
class QLineEdit;
class QTabWidget;
class QSplitter;
class QProgressBar;
class QAction;
class QVBoxLayout;
class MainWindow final : public QMainWindow {
public:
 explicit MainWindow(QWidget* parent=nullptr);
 ~MainWindow() override;
private:
 void openCapture();
 void applyTheme(bool dark);
 void restorePreferences();
 void loadCapture(const QString& filename);
 void refreshFilter();
 void showPacketDetails();
 void refreshFlows();
 void refreshConversations();
 void exportConversations();
 void refreshSummary();
 void exportFlows();
 void exportPackets();
 void refreshTimeline();
 void populateBars(QVBoxLayout* layout, const std::vector<std::pair<QString,size_t>>& data, size_t total);
 static QString hexDump(const std::vector<uint8_t>& bytes);
 std::vector<CapturedPacket> packets_;
 std::unique_ptr<netscope::IndexedPcap> indexed_;
 netscope::PacketCache cache_{64ull*1024*1024};
 netscope::FlowTracker tracker_;
 netscope::ConversationTracker conversations_;
 netscope::TrafficTimeline timeline_;
 QString currentFile_;
 QTableView* packetTable_=nullptr;
 PacketModel* packetModel_=nullptr;
 PacketProxy* packetProxy_=nullptr;
 QThread* loadThread_=nullptr;
 std::shared_ptr<std::atomic_bool> cancelLoad_;
 QProgressBar* loadProgress_=nullptr;
 QAction* openAction_=nullptr;
 QTableWidget* flowTable_=nullptr;
 QTableWidget* conversationTable_=nullptr;
 QTreeWidget* details_=nullptr;
 QPlainTextEdit* hex_=nullptr;
 QLineEdit* filter_=nullptr;
 QLabel* summary_=nullptr;
 QLabel* status_=nullptr;
 QTabWidget* tabs_=nullptr;
 QSplitter* mainSplitter_=nullptr;
 QVBoxLayout* protocolBars_=nullptr;
 QVBoxLayout* talkerBars_=nullptr;
 QLabel* filterStatus_=nullptr;
 QTableWidget* timelineTable_=nullptr;
 QAction* lightThemeAction_=nullptr;
 QAction* darkThemeAction_=nullptr;
 bool darkTheme_=false;
};

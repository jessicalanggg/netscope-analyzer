#pragma once
#include "capture.hpp"
#include "netscope/filter.hpp"
#include <QAbstractTableModel>
#include <QSortFilterProxyModel>
#include <vector>
class PacketModel final : public QAbstractTableModel {
public:
 explicit PacketModel(QObject* parent=nullptr):QAbstractTableModel(parent){}
 void setPackets(const std::vector<CapturedPacket>* packets);
 const CapturedPacket* packetAt(int row) const {return packets_&&row>=0&&static_cast<size_t>(row)<packets_->size()?&(*packets_)[static_cast<size_t>(row)]:nullptr;}
 int rowCount(const QModelIndex& parent={}) const override;
 int columnCount(const QModelIndex& parent={}) const override;
 QVariant data(const QModelIndex& index,int role=Qt::DisplayRole) const override;
 QVariant headerData(int section,Qt::Orientation orientation,int role=Qt::DisplayRole) const override;
private:
 const std::vector<CapturedPacket>* packets_=nullptr;
};
class PacketProxy final : public QSortFilterProxyModel {
public:
 explicit PacketProxy(QObject* parent=nullptr):QSortFilterProxyModel(parent){}
 void setExpression(const netscope::PacketFilter& expression) {expression_=expression;invalidateFilter();}
protected:
 bool filterAcceptsRow(int sourceRow,const QModelIndex& sourceParent) const override;
 bool lessThan(const QModelIndex& left,const QModelIndex& right) const override;
private:
 netscope::PacketFilter expression_;
};

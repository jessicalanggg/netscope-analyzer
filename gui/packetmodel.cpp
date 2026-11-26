#include "packetmodel.hpp"
#include <QBrush>
#include <QColor>
#include <QStringList>
#include <algorithm>
void PacketModel::setPackets(const std::vector<CapturedPacket>* packets) {
 beginResetModel(); packets_=packets; endResetModel();
}
int PacketModel::rowCount(const QModelIndex& parent) const {return parent.isValid()||!packets_?0:static_cast<int>(packets_->size());}
int PacketModel::columnCount(const QModelIndex& parent) const {return parent.isValid()?0:7;}
QVariant PacketModel::headerData(int section,Qt::Orientation orientation,int role) const {
 if(role!=Qt::DisplayRole) return {};
 if(orientation==Qt::Vertical) return section+1;
 static const QStringList headers={"No.","Source","Destination","Protocol","Src Port","Dst Port","Length"};
 return section>=0&&section<headers.size()?QVariant(headers[section]):QVariant();
}
QVariant PacketModel::data(const QModelIndex& index,int role) const {
 if(!index.isValid()||!packets_||index.row()<0||static_cast<size_t>(index.row())>=packets_->size()) return {};
 const auto& c=(*packets_)[static_cast<size_t>(index.row())]; const auto& p=c.packet;
 if(role==Qt::UserRole) return index.row();
 if(role==Qt::BackgroundRole) return QBrush(QColor(!c.decoded?"#f2f3f6":p.protocol=="TCP"?"#e6f2ff":p.protocol=="UDP"?"#e9f8ee":(p.protocol=="ICMP"||p.protocol=="ICMPv6")?"#fff2df":"#f2f3f6"));
 if(role!=Qt::DisplayRole) return {};
 switch(index.column()) {
 case 0:return index.row()+1;
 case 1:return c.decoded?QString::fromStdString(p.source_ip):QString("—");
 case 2:return c.decoded?QString::fromStdString(p.destination_ip):QString("—");
 case 3:return c.decoded?QString::fromStdString(p.protocol):QString("Undecoded");
 case 4:return c.decoded&&(p.protocol=="TCP"||p.protocol=="UDP")?QVariant(p.source_port):QVariant(QString("—"));
 case 5:return c.decoded&&(p.protocol=="TCP"||p.protocol=="UDP")?QVariant(p.destination_port):QVariant(QString("—"));
 case 6:return static_cast<qulonglong>(c.captured_length);
 default:return {};
 }
}
bool PacketProxy::filterAcceptsRow(int row,const QModelIndex& parent) const {
 const auto* m=dynamic_cast<const PacketModel*>(sourceModel());
 if(!m) return false;
 const auto* packet=m->packetAt(row);
 return packet&&expression_.matches(packet->decoded?&packet->packet:nullptr,static_cast<size_t>(row)+1,packet->captured_length);
}
bool PacketProxy::lessThan(const QModelIndex& a,const QModelIndex& b) const {
 if(a.column()==0||a.column()==4||a.column()==5||a.column()==6)
  return sourceModel()->data(a,Qt::DisplayRole).toULongLong()<sourceModel()->data(b,Qt::DisplayRole).toULongLong();
 return QSortFilterProxyModel::lessThan(a,b);
}

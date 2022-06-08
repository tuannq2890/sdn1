from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub

import tensorflow as tf
import time
import os
import pandas as pd
from pandas import read_csv
import numpy as np

import switch
from datetime import datetime

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import confusion_matrix
from sklearn.metrics import accuracy_score

class SimpleMonitor13(switch.SimpleSwitch13):

    def __init__(self, *args, **kwargs):

        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.model = tf.keras.models.load_model('model_1652172779.h5')
        self.monitor_thread = hub.spawn(self._monitor)

        #start = datetime.now()

        #self.flow_training()

        #end = datetime.now()
        #print("Training time: ", (end-start))

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
                #self.logger.info("monitor")
            hub.sleep(10)

            #self.flow_predict()

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):

        timestamp = datetime.now()
        timestamp = timestamp.timestamp()
        #self.logger.info("reply")

        file0 = open("PredictFlowStatsfile.csv","w")
        file0.write('timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,packet_count,byte_count,packet_count_per_second,packet_count_per_nsecond,byte_count_per_second,byte_count_per_nsecond\n')
        body = ev.msg.body
        icmp_code = -1
        icmp_type = -1
        tp_src = 0
        tp_dst = 0

        for stat in sorted([flow for flow in body if (flow.priority == 1) ], key=lambda flow:
            (flow.match['eth_type'],flow.match['ipv4_src'],flow.match['ipv4_dst'],flow.match['ip_proto'])):
        
            ip_src = stat.match['ipv4_src']
            ip_dst = stat.match['ipv4_dst']
            ip_proto = stat.match['ip_proto']
            
            if stat.match['ip_proto'] == 1:
                icmp_code = stat.match['icmpv4_code']
                icmp_type = stat.match['icmpv4_type']
                
            elif stat.match['ip_proto'] == 6:
                tp_src = stat.match['tcp_src']
                tp_dst = stat.match['tcp_dst']

            elif stat.match['ip_proto'] == 17:
                tp_src = stat.match['udp_src']
                tp_dst = stat.match['udp_dst']

            flow_id = str(ip_src) + str(tp_src) + str(ip_dst) + str(tp_dst) + str(ip_proto)
          
            try:
                packet_count_per_second = stat.packet_count/stat.duration_sec
                packet_count_per_nsecond = stat.packet_count/stat.duration_nsec
            except:
                packet_count_per_second = 0
                packet_count_per_nsecond = 0
                
            try:
                byte_count_per_second = stat.byte_count/stat.duration_sec
                byte_count_per_nsecond = stat.byte_count/stat.duration_nsec
            except:
                byte_count_per_second = 0
                byte_count_per_nsecond = 0
                
            file0.write("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n"
                .format(timestamp, ev.msg.datapath.id, flow_id, ip_src, tp_src,ip_dst, tp_dst,
                        stat.match['ip_proto'],icmp_code,icmp_type,
                        stat.duration_sec, stat.duration_nsec,
                        stat.idle_timeout, stat.hard_timeout,
                        stat.flags, stat.packet_count,stat.byte_count,
                        packet_count_per_second,packet_count_per_nsecond,
                        byte_count_per_second,byte_count_per_nsecond))
            
        file0.close()
        self.flow_predict(ev)

    def drop_flow(self, datapath, priority, match, idle = 0, hard = 0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        #action = []
        #self.logger.info("---------start drop-------------")

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, [])]
        #self.logger.info("------instruction success---------")
        mod = parser.OFPFlowMod(datapath=datapath, idle_timeout=idle, hard_timeout=hard, priority=priority, match=match, instructions=inst)
        #self.logger.info("------modify success-------")
        datapath.send_msg(mod)
        #self.logger.info("------send modify success--------")

    def delete_flow(self, datapath, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod(datapath=datapath, table_id=ofproto.OFPTT_ALL, command=ofproto.OFPFC_DELETE,
                            out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY, match=match)

        datapath.send_msg(mod)

    def flow_predict(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.logger.info("predict")

        try:
            predict_flow_dataset = pd.read_csv('PredictFlowStatsfile.csv')
            predict_flow_dataset_copy = predict_flow_dataset.values

            predict_flow_dataset.iloc[:, 2] = predict_flow_dataset.iloc[:, 2].str.replace('.', '')
            predict_flow_dataset.iloc[:, 3] = predict_flow_dataset.iloc[:, 3].str.replace('.', '')
            predict_flow_dataset.iloc[:, 5] = predict_flow_dataset.iloc[:, 5].str.replace('.', '')

            predict_flow_dataset = predict_flow_dataset.astype('float64')
            predict_flow_dataset = predict_flow_dataset.values.reshape((predict_flow_dataset.shape[0],predict_flow_dataset.shape[1],1))

            #self.logger.info("load data success--------------------------------------------------------------------")

            #model = tf.keras.models.load_model('model_1652172779.h5')

            #self.logger.info("load model success------------------------------------------------------------------------------")

            pre_flow = self.model.predict(predict_flow_dataset)

            #X_predict_flow = predict_flow_dataset.iloc[:, :].values
            #X_predict_flow = X_predict_flow.astype('float64')
            
            #y_flow_pred = self.flow_model.predict(X_predict_flow)

            legitimate_trafic = 0
            ddos_trafic = 0

            #predict_flow_dataset = predict_flow_dataset.reshape((predict_flow_dataset.shape[0], predict_flow_dataset.shape[1]))
            df = pd.DataFrame(predict_flow_dataset_copy)

            label_value = np.argmax(pre_flow, axis=1)
            count_0 = (label_value == 0).sum()
            self.logger.info("Probality of legitimate traffic: {} ".format(count_0/pre_flow.shape[0]))

            count_1 = (label_value == 1).sum()

            self.logger.info("Probality of ICMP DDOS traffic: {} ".format(count_1/pre_flow.shape[0]))
            if (count_1):
                dst1 = df.loc[np.where(label_value==1), 5]
                dsts1 = np.array(dst1)
                self.logger.info("-->Victim: {}".format(np.unique(dsts1)))
                src1 = df.loc[np.where(label_value == 1), 3]
                srcs1 = np.array(src1)
                srcs1 = np.unique(srcs1)
                self.logger.info("-->Attacker: {}".format(srcs1))
                for src in srcs1:
                    match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src)
                    #self.logger.info("------match success--------")
                    self.delete_flow(datapath, match)
                    self.drop_flow(datapath, 2, match, idle=100, hard=300)
                    #self.logger.info("------drop success------")
                    self.logger.info("Block ip: {}".format(src))

            count_2 = (label_value == 2).sum()
            self.logger.info("Probality of TCP-SYN DDOS traffic: {}".format(count_2/pre_flow.shape[0]))
            if (count_2):
                dst2 = df.loc[np.where(label_value==2), 5]
                dsts2 = np.array(dst2)
                self.logger.info("-->Victim: {}".format(np.unique(dsts2)))
                src2 = df.loc[np.where(label_value == 2), 3]
                srcs2 = np.array(src2)
                srcs2 = np.unique(srcs2)
                self.logger.info("-->Attacker: {}".format(srcs2))
                for src in srcs2:
                    match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src)
                    #self.logger.info("-------match success--------")
                    self.delete_flow(datapath, match)
                    self.drop_flow(datapath, 2, match, idle=100, hard=300)
                    #self.logger.info("-------drop success---------")
                    self.logger.info("Block ip: {}".format(src))

            count_3 = (label_value == 3).sum()
            self.logger.info("Probality of UDP DDOS traffic: {}".format(count_3/pre_flow.shape[0]))
            if (count_3):
                dst3 = df.loc[np.where(label_value==3), 5]
                dsts3 = np.array(dst3)
                self.logger.info("-->Victim: {}".format(np.unique(dsts3)))
                src3 = df.loc[np.where(label_value == 3), 3]
                srcs3 = np.array(src3)
                srcs3 = np.unique(srcs3)
                self.logger.info("-->Attacker: {}".format(srcs3))
                for src in srcs3:
                    match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src)
                    #self.logger.info("--------match success---------")
                    self.delete_flow(datapath, match)
                    self.drop_flow(datapath, 2, match, idle=100, hard=300)
                    #self.logger.info("--------drop success----------")
                    self.logger.info("Block ip: {}".format(src))

            #for i in y_flow_pred:
                #if i == 0:
                    #legitimate_trafic = legitimate_trafic + 1
                #else:
                    #ddos_trafic = ddos_trafic + 1
                    #victim = int(predict_flow_dataset.iloc[i, 5])%20
                    
                    
                    

            self.logger.info("------------------------------------------------------------------------------")
            #if (legitimate_trafic/len(y_flow_pred)*100) > 80:
                #self.logger.info("legitimate trafic ...")
            #else:
                #self.logger.info("ddos trafic ...")
                #self.logger.info("victim is host: h{}".format(victim))

            self.logger.info("------------------------------------------------------------------------------")
            
            file0 = open("PredictFlowStatsfile.csv","w")
            
            file0.write('timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,packet_count,byte_count,packet_count_per_second,packet_count_per_nsecond,byte_count_per_second,byte_count_per_nsecond\n')
            file0.close()

        except:
            pass

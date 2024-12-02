import logging
import layers.packet
from scapy.all import IP, TCP
from joblib import load
import numpy as np
from censors.censor import Censor
import os
import pandas as pd

def parse_flow(flow, client_ip, logger):
    client_flags_count = {}
    ips = []

    i=0
    flow_size=0
    max_packet_size_per_flow = 0
    fragmented_packets = []
    #TCP_seq = []
    IPoverlapping = 0
    TCPoverlapping = 0
    TCP_seq_range = []
    corrupt_chksm = 0
    corrupt_dataofs = 0
    low_ttl = 0
    all_ttl = {}
    Non_zero_SYN=0
    flow_flags = {}
    for count, packet in enumerate(flow):#flows[flow]:
        #try:
        # logger.debug(f"PROCESSING THE {count}th PACKET")
        
        if packet[IP].src != client_ip and str(packet[TCP].flags).find('R') == -1 :
            continue
        #print("/**Packet {}**/".format(i+1))
        #print("--Summary : {}".format(packet.summary()))
        #if packet[TCP].dport == 80:
        '''packet max size'''
        max_packet_size_per_flow = max(len(packet[TCP].payload),max_packet_size_per_flow) 

        '''flow size'''
        flow_size += len(packet[TCP].payload)

        '''extract fragmented packets'''
        if packet[IP].flags==1 or packet[IP].frag > 0:
            fragmented_packets.append(packet)

        '''Extracting Payloads'''
        payload = bytes(packet[TCP].payload)
        #print("--payload {}\n".format(payload))

        '''Extracting Flags'''
        flags = str(packet[TCP].flags)
        # logger.debug(f"WE GOT A PACKET FROM {packet[IP].src} WITH FLAGS {flags}")
        if packet[IP].src == client_ip:
            # logger.debug(flags)
            '''Check if it is a non-zero SYN'''
            if flags == 'S' and len(payload) != 0:
                Non_zero_SYN+=1
            # add to current pcap flags
            if flags in flow_flags.keys():
                flow_flags[flags]+=1
            else:
                flow_flags[flags]=1

            # add to all pcap flags
            if flags in client_flags_count.keys():
                client_flags_count[flags]+=1
            else:
                client_flags_count[flags]=1
        #elif packet[IP].src == censor_ip:
        #    if flags in censor_flags_count.keys():
        #        censor_flags_count[flags]+=1
        #    else:
        #        censor_flags_count[flags]=1

        '''Extracting IPs'''
        ips.append(packet[IP].dst)

        '''Extracting Checksum and dataofs'''
        chksum = packet[TCP].chksum
        dataofs = packet[TCP].dataofs
        #print("--TCP checksum {}".format(chksum))
        #print('--TCP dataofs: ',dataofs)
        del packet[TCP].chksum
        del packet[TCP].dataofs
        try:
            out_all = packet.show2(dump=True)
        

            ## extract checksum
            out = out_all[out_all.find('###[ TCP ]###'):]
            out = out[out.find('chksum    = ')+len('chksum    = '):]
            out = out[:out.find(' ')]
            try:
                correct_chksum = int(out, 16)
                #print("--Recomputed TCP checksum {}".format(correct_chksum))
                if correct_chksum != chksum:
                    corrupt_chksm+=1
            except ValueError:
                #print('{} found as correct_chksum')
                pass
            ## extract dataofs
            out = out_all[out_all.find('###[ TCP ]###'):]
            out = out[out.find('dataofs   = ')+len('dataofs   = '):]
            out = out[:out.find(' ')]
            try:
                correct_dataofs = int(out)
                #print("--Recomputed TCP dataofs {}".format(correct_dataofs))
                if correct_dataofs != dataofs:
                    corrupt_dataofs+=1
            except ValueError:
                #print('{} found as correct_dataofs')
                pass
        except:
            pass

        '''Extracting ttl'''
        #print(packet[IP].ttl)
        if packet[IP].ttl <= 10:
            low_ttl+=1
        if packet[IP].src in all_ttl.keys():
            all_ttl[packet[IP].src].append(packet[IP].ttl)
        else:
            all_ttl[packet[IP].src] = [packet[IP].ttl]
        

        '''geneva TCP seq range'''
        #print("--packet's TCP sequence range is [{},{}]".format(packet[TCP].seq,packet[TCP].seq+len(bytes(packet[TCP].payload))))
        if len(bytes(packet[TCP].payload)) != 0 and packet[IP].src == client_ip:
            TCP_seq_range.append([packet[TCP].seq, packet[TCP].seq+len(bytes(packet[TCP].payload))])

        #except Exception as e:
        #    pass
        i+=1
        ## TTL Variance
    ttl_var=0
    #print(all_ttl)
    for ip in all_ttl.keys():
        if ip == client_ip:
            ttl_var+=np.var(all_ttl[ip])
    #if len(all_ttl.keys()) != 0:
    #    ttl_var = ttl_var/len(all_ttl.keys())
    

    ## Overlapping TCP segements
    overlapped = [] # a list of overlapped seq ranges indices

    for i in range(len(TCP_seq_range)):
        seq_r = TCP_seq_range[i]
        if seq_r[1] == seq_r[0]:
            continue

        for j in range(len(TCP_seq_range)):
            check_r = TCP_seq_range[j]
            if i==j:   
                continue
            if check_r[1] == check_r[0]:
                continue
            #if seq_r[0] == check_r[0] and seq_r[1] == check_r[1]:
            #    j+=1
            #    continue
            if check_r[0] >= seq_r[0] and check_r[0] < seq_r[1]:
                ov=[]
                ov.append(i)
                ov.append(j)
                ov.sort()
                if ov not in overlapped:
                    #print(ov)
                    overlapped.append(ov)
                    continue
            elif check_r[0] <= seq_r[0] and seq_r[0] < check_r[1]:
                ov=[]
                ov.append(i)
                ov.append(j)
                ov.sort()
                if ov not in overlapped:
                    #print(ov)
                    overlapped.append(ov)
                    continue
    TCPoverlapping = len(overlapped)

    ## Overlapping IP Fragments
    if len(fragmented_packets) != 0:
        ## collecting unique IP IDs
        uniqipids={}
        for a in fragmented_packets:
            uniqipids[a[IP].id]='we are here'

        for ipid in uniqipids.keys():
            #print("Packet fragments found. Collecting fragments now.")
            fragmenttrain = [a for a in fragmented_packets if a[IP].id == ipid]
            allocated_bytes = []
            for a in fragmenttrain:
                frag_offset = a[IP].frag*8
                for byte in range(frag_offset, frag_offset+len(a[IP].payload)+1):
                    if byte not in allocated_bytes:
                        allocated_bytes.append(byte)
                    else:
                        #print("Overlapping packets are found!")
                        IPoverlapping+=1
    else:
        print('No fragment is found!')    
    
    
    return Non_zero_SYN, flow_flags, flow_size, max_packet_size_per_flow, IPoverlapping, TCPoverlapping, corrupt_chksm, corrupt_dataofs, low_ttl, ttl_var
    
    
    
def process_flow(flow, client_ip, environment_id, logger):
    Non_zero_SYN,flow_flags, flow_size, max_packet_size_per_flow, IPoverlapping, TCPoverlapping, corrupt_chksm, corrupt_dataofs, low_ttl, ttl_var = parse_flow(flow, client_ip, logger) 
    
        
        
    print('SYN with non-zero payload',Non_zero_SYN)    
    print('flow_size',flow_size)
    print('max_packet_size_per_flow',max_packet_size_per_flow)
    print('IPoverlapping',IPoverlapping)
    print('TCPoverlapping',TCPoverlapping)
    print('corrupt_chksm',corrupt_chksm)
    print('corrupt_dataofs',corrupt_dataofs)
    print('low_ttl',low_ttl)
    print('flow_flags',flow_flags)
    print('ttl_var',ttl_var)
        
            
    #Non_zero_SYN, flags, flow_size, max_pckt_size_per_flow, IPoverlapping, TCPoverlapping, corrupt_chksm, corrupt_dataofs, low_ttl, ttl_var = parse_pcap(filename)
    
    data = {}
    #for flow_i in  range(len(allpcap_flow_size)):
    record={}
    record['# Non_zero_SYN'] = Non_zero_SYN
    record['flags'] = flow_flags
    record['size']=flow_size
    record['Max_pckt_size'] = max_packet_size_per_flow
    #record['# overlapping IP fragments']=IPoverlapping[flow_i]
    record['# overlapping TCP segments']= TCPoverlapping
    #record['# of corrupt checksum']=corrupt_chksm
    record['# of corrupt dataofs']=corrupt_dataofs
    #record['# low ttl'] = low_ttl
    record['ttl variance'] = ttl_var

    data[str(environment_id)] = record
    if record['flags'] in [{},{'S': 1}]:
        # logger.debug("FLAGS ARE JUST " + str(record['flags']))
        return None
    if data != {}:
        df = pd.DataFrame.from_dict(data, orient='index')
    else:
        # logger.debug("THE DATA IS BULLSHIT")
        return None
    
    # store envirnment data to csv
    # csv_path = os.path.join(RUN_DIRECTORY, "csv")
    # if not os.path.exists(csv_path):
    #     os.mkdir(csv_path)
    
    
    # if index != None:
    #     df.to_csv(os.path.join(csv_path,str(environment_id)+"_client" +str(index)+'.csv'), sep=',')
    # else:
    #     df.to_csv(os.path.join(csv_path,str(environment_id)+'.csv'), sep=',')
    
    return df

class CombinedCensor(Censor):

    # I created an additional model path param so you enter the path of the ML model .joblib
    def __init__(self, environment_id, forbidden, log_dir, log_level, port, queue_num):
        #Same initialization as censor 1
        super().__init__(environment_id, log_dir, log_level, port, queue_num)
        self.forbidden = forbidden
        self.drop_all_from = None
        self.detected_packets = 0
        self.flow = []
        self.client_ip = False
        self.tcb = 0
        self.environment_id2 = environment_id
        
        # Load pretrained ML model
        model_path = "ML detectors/rfc.joblib"
        if not os.path.exists(model_path):
            model_path = "/code/ML detectors/rfc.joblib"
        print("LOADING THE GOD DAMN DETECTOR")
        self.detector = load(model_path)
        # Define features in a packet
        self.feature_extractor = ['# Non_zero_SYN', 'size', 'Max_pckt_size', '# overlapping TCP segments', '# of corrupt dataofs', 'ttl variance', 
        'A', 'PA', 'SA', 'FA', 'RA', 'FPA', 'S', 'R', 'U', 'SEC', 'SRPUEC', 'FSRPAUE', 'FPCN', 'P', 'SAE', 'SPUE', 'F', 'RUE', 'FPUC', 
        'FUCN', 'SUC', 'FSRPAC', 'FSAN', 'SRAECN', 'AEC', 'FSRPEC', 'FUECN', 'FRA', 'PAU', 'SRACN', 'SE', 'SCN', 'FRPAUE', 'FSRPAEN', 
        'FRPEN', 'FSREC', 'SRPAUC', 'FRAECN', 'FSRUECN', 'SAC', 'RPAU', 'FPAE', 'SPAUECN', 'FRAUEN', 'FRAUN', 'PUN', 'FRPACN', 'SRPAUE', 
        'FSUE', 'FSU', 'SP', 'RPA', 'FSPAUECN', 'SPC', 'SRPACN', 'RPAUECN', 'SU', 'FSRAE', 'FRPAU', 'RAECN', 'FPEN', 'SRPECN', 'SPUN', 
        'SRAUE', 'FPUECN', 'RPAE', 'SUEC', 'RPUN', 'FPAUEN', 'RAUE', 'FR', 'SRUCN', 'FSPAE', 'FSRAECN', 'SR', 'FSPEN', 'FSRPUEN', 'FAE', 
        'SRAUECN', 'SPEN', 'FRUC', 'FRAN', 'FSPE', 'FSPUEC', 'SRPAN', 'FUEN', 'FRPAECN', 'SRPUCN', 'SRAE', 'FSPAN', 'SRA', 'PUE', 'FSUN', 
        'RAE', 'CN', 'FRPAC', 'SRAC', 'RN', 'SRPAUECN', 'FSRC', 'FRAEC', 'FSPUEN', 'SRUE', 'FSUC', 'SRPUECN', 'FRAE', 'FUN', 'FRPAUEC', 
        'FSPA', 'SRPUC', 'SAUE', 'RPAUE', 'FRPAEC', 'AUECN', 'SPAEN', 'RPU', 'FSPUECN', 'SRPEC', 'FSRPAUN', 'FAEN', 'AU', 'FSRPECN', 
        'PUC', 'FPAUN', 'FRUEN', 'FSPAUEC', 'SPUCN', 'SRPAEC', 'FUEC', 'FRUN', 'SEN', 'FSPAUE', 'FSRPAU', 'RPEN', 'FRPAUECN', 'FSAUCN', 
        'FRPUEC', 'EC', 'FRUCN', 'RAUECN', 'SUECN', 'PUCN', 'FPAEN', 'FSRAC', 'PAUN', 'FPACN', 'FRAUEC', 'RUEN', 'FAUECN', 'FSRAUEC', 
        'FPUEC', 'SRAUEN', 'FSUEC', 'FAUN', 'SPE', 'FRPN', 'RPECN', 'RAN', 'SACN', 'FSRUC', 'FS', 'FRPA', 'SPUC', 'SRPUN', 'RP', 'FSRPN', 
        'SPAN', 'SRAUC', 'PCN', 'RUECN', 'SPN']
    
    # Check_censor Determines whether to censor a packet based on ML model or forbidden keywords.
    def check_censor(self, packet):
        first_packet = False

        if self.drop_all_from == packet["IP"].src:
            self.logger.debug("Dropping all from this IP %s..." % self.drop_all_from)
            return True

        # Only censor TCP packets for now
        if "TCP" not in packet:
            return False

        # Initial TCP synchronization
        if packet["TCP"].sprintf('%TCP.flags%') == "S":
            self.tcb = packet["TCP"].seq + 1
            self.logger.debug(("Synchronizing TCB (%d) on packet " + layers.packet.Packet._str_packet(packet)) % self.tcb)
            return False

        # If we're tracking this packet stream
        if packet["TCP"].seq == self.tcb:
            self.tcb += len(self.get_payload(packet))
        else:
            self.logger.debug("Ignoring packet: " + layers.packet.Packet._str_packet(packet))
            return False
        
        if not self.client_ip:
            self.client_ip = packet[IP].src
            self.logger.debug(f"THE CLIENT IP IS {self.client_ip}")
            first_packet = True

        self.logger.debug("Censor init'd")
        self.flow.append(packet)

        self.logger.debug(f"THERE ARE {len(self.flow)} PACKETS IN THE FLOW BOZO")
        
        if not first_packet:
            flow_df = process_flow(self.flow, self.client_ip, self.environment_id2, self.logger)
            # if flow_df != None:
            try:
                self.logger.debug(flow_df["flags"])
            except TypeError:
                first_packet = True
        # try:

        # return False
        # Log the packet
        # self.logger.debug("Inbound packet to censor: " + layers.packet.Packet._str_packet(packet))

        # Check if the IP is marked for dropping
        
    
        # Only process TCP packets    
        
        if not first_packet:
            # Extract features and classify using the ML model
            features = self.extract_features(flow_df) # Pass in the flow dataframe
            if self.is_geneva(features):
                self.drop_all_from = packet["IP"].src
                self.logger.debug("Packet detected as Geneva.")
                self.detected_packets += 1
                self.logger.debug(f"DETECTION RATE: {self.detected_packets/len(self.flow)}")
                return True
            
        self.logger.debug(f"DETECTION RATE: {self.detected_packets/len(self.flow)}")
            
        # # Process packet payload for forbidden keywords
        for keyword in self.forbidden:
            if keyword in self.get_payload(packet):
                self.drop_all_from = packet["IP"].src
                self.logger.debug("Packet triggered censor due to forbidden keyword.")
                return True
        
        return False
        # except  as e:
        #     self.logger.exception("ClassificationCensor encountered an error.")
        #     return False

    """
    Checks the packet payload for forbidden keywords.
    """
    def contains_forbidden_keywords(self, packet):
        payload = self.get_payload(packet)
        for keyword in self.forbidden:
            if keyword in payload:
                print("Packet payload contains forbidden keyword.")
                return True
        return False

    """
    Extracts features from the packet for ML classification.
    """
    def extract_features(self, df):
        new_cols = ['A', 'PA', 'SA', 'FA', 'RA', 'FPA', 'S', 'R', 'U', 'SEC', 'SRPUEC', 'FSRPAUE', 'FPCN', 'P', 'SAE', 'SPUE', 'F', 'RUE', 'FPUC', 'FUCN', 'SUC', 'FSRPAC', 'FSAN', 'SRAECN', 'AEC', 'FSRPEC', 'FUECN', 'FRA', 'PAU', 'SRACN', 'SE', 'SCN', 'FRPAUE', 'FSRPAEN', 'FRPEN', 'FSREC', 'SRPAUC', 'FRAECN', 'FSRUECN', 'SAC', 'RPAU', 'FPAE', 'SPAUECN', 'FRAUEN', 'FRAUN', 'PUN', 'FRPACN', 'SRPAUE', 'FSUE', 'FSU', 'SP', 'RPA', 'FSPAUECN', 'SPC', 'SRPACN', 'RPAUECN', 'SU', 'FSRAE', 'FRPAU', 'RAECN', 'FPEN', 'SRPECN', 'SPUN', 'SRAUE', 'FPUECN', 'RPAE', 'SUEC', 'RPUN', 'FPAUEN', 'RAUE', 'FR', 'SRUCN', 'FSPAE', 'FSRAECN', 'SR', 'FSPEN', 'FSRPUEN', 'FAE', 'SRAUECN', 'SPEN', 'FRUC', 'FRAN', 'FSPE', 'FSPUEC', 'SRPAN', 'FUEN', 'FRPAECN', 'SRPUCN', 'SRAE', 'FSPAN', 'SRA', 'PUE', 'FSUN', 'RAE', 'CN', 'FRPAC', 'SRAC', 'RN', 'SRPAUECN', 'FSRC', 'FRAEC', 'FSPUEN', 'SRUE', 'FSUC', 'SRPUECN', 'FRAE', 'FUN', 'FRPAUEC', 'FSPA', 'SRPUC', 'SAUE', 'RPAUE', 'FRPAEC', 'AUECN', 'SPAEN', 'RPU', 'FSPUECN', 'SRPEC', 'FSRPAUN', 'FAEN', 'AU', 'FSRPECN', 'PUC', 'FPAUN', 'FRUEN', 'FSPAUEC', 'SPUCN', 'SRPAEC', 'FUEC', 'FRUN', 'SEN', 'FSPAUE', 'FSRPAU', 'RPEN', 'FRPAUECN', 'FSAUCN', 'FRPUEC', 'EC', 'FRUCN', 'RAUECN', 'SUECN', 'PUCN', 'FPAEN', 'FSRAC', 'PAUN', 'FPACN', 'FRAUEC', 'RUEN', 'FAUECN', 'FSRAUEC', 'FPUEC', 'SRAUEN', 'FSUEC', 'FAUN', 'SPE', 'FRPN', 'RPECN', 'RAN', 'SACN', 'FSRUC', 'FS', 'FRPA', 'SPUC', 'SRPUN', 'RP', 'FSRPN', 'SPAN', 'SRAUC', 'PCN', 'RUECN', 'SPN']
        for col in new_cols:
            values = []
            for elt in df['flags']:
                #dictt = ast.literal_eval(elt)
                dictt = elt
                if col in dictt.keys():
                    values.append(dictt[col])
                else:
                    values.append(0)
            df[col] = values


        del df['flags']
        X = df.values
        return X

    """
    Uses the ML model to classify if the packet exhibits Geneva behavior.
    """
    #Detection algorithm:
    def is_geneva(self, features):
        try:
            eval_y_prob = self.detector.predict_proba(features)
            y_pred = eval_y_prob.argmax(axis=1)
            return y_pred[0] == 0  # True if classified as Geneva
        except Exception as e:
            self.logger.error(f"Error in ML classification: {e}")
            return False

    """
    Marks the source IP for dropping and drops the packet.
    """
    def censor(self, scapy_packet):
        self.drop_all_from = scapy_packet["IP"].src
        print(f"Marking IP {self.drop_all_from} for dropping.")
        return "drop"
import logging
import layers.packet
from scapy.all import IP, TCP
from joblib import load
import numpy as np
from censors.censor import Censor
import os

class ClassificationCensor(Censor):

    # I created an additional model path param so you enter the path of the ML model .joblib
    def __init__(self, environment_id, forbidden, log_dir, log_level, port, queue_num, model_path="ML detectors/rfc.joblib"):
        #Same initialization as censor 1
        super().__init__(environment_id, log_dir, log_level, port, queue_num)
        self.forbidden = forbidden
        self.drop_all_from = None
        self.tcb = 0
        # Load pretrained ML model
        if not os.path.exists(model_path):
            model_path = "../" + model_path
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
        try:
            # Log the packet
            print("Inbound packet to censor: " + layers.packet.Packet._str_packet(packet))

            # Check if the IP is marked for dropping
            if self.drop_all_from == packet["IP"].src:
                print(f"Dropping all packets from {self.drop_all_from}...")
                return True
        
            # Only process TCP packets
            if "TCP" not in packet:
                return False
            
            # Handle TCP synchronization
            if packet["TCP"].sprintf('%TCP.flags%') == "S":
                self.tcb = packet["TCP"].seq + 1
                return False
        
            # Process packet payload for forbidden keywords
            for keyword in self.forbidden:
                if keyword in self.get_payload(packet):
                    print("Packet triggered censor due to forbidden keyword.")
                    return True

            # Extract features and classify using the ML model
            features = self.extract_features(packet)
            if self.is_geneva(features):
                print("Packet detected as Geneva.")
                return True
            
            return False
        except Exception as e:
            self.logger.exception("ClassificationCensor encountered an error.")
            return False

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
    def extract_features(self, packet):
        features = []
        for feature in self.feature_extractor:
            # Extract feature or default to 0
            features.append(packet.get(feature, 0))
        return features

    """
    Uses the ML model to classify if the packet exhibits Geneva behavior.
    """
    #Detection algorithm:
    def is_geneva(self, features):
        try:
            eval_y_prob = self.detector.predict_proba([features])
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
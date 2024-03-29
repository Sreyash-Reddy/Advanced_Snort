import numpy as np
import pandas as pd
from scapy.layers.inet import TCP, UDP, IP
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
from scapy.all import *

training_dataset_with_all_columns = pd.read_csv("Dataset.csv")
training_dataset = training_dataset_with_all_columns[
    ['protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'class']]
training_dataset = training_dataset.drop_duplicates()


def preprocess(dataframe):
    dataframe = pd.get_dummies(dataframe, columns=['protocol_type', 'service', 'flag'])
    dataframe.loc[dataframe['class'] == "normal", "class"] = 0
    dataframe.loc[dataframe['class'] != 0, "class"] = 1
    return dataframe


preprocessed_training_data = preprocess(training_dataset)

x = preprocessed_training_data.drop('class', axis=1).values
y = preprocessed_training_data['class'].values

y = y.astype('int')
x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=42)


decision_tree_model = DecisionTreeClassifier().fit(x_train, y_train)

services = {
    20: "ftp_data",
    23: "telnet",
    25: "smtp",
    37: "time",
    53: "domain_u",
    80: "http",
    109: "pop_2",
    110: "pop_3",
    119: "nntp",
    143: "imap4",
    194: "IRC",
    389: "ldap",
    631: "printer",
    443: "http_443",
    22: "ssh",
    21: "ftp",
    6000: "X11",
    6001: "X11",
    6002: "X11",
    6003: "X11",
    6004: "X11",
    6005: "X11",
    6006: "X11",
    6007: "X11",
    6008: "X11",
    6009: "X11",
    6010: "X11",
    6011: "X11",
    6012: "X11",
    6013: "X11"
}

protocols = {
    6: "tcp",
    17: "udp"
}

prediction = {
    0: "normal",
    1: "anomaly"
}


def packet_callback(packet):
    if IP in packet:
        serviceInt = 0
        protocol_type = protocols.get(packet[IP].proto)
        src_bytes = len(packet[IP].payload)
        dst_bytes = len(packet[IP].payload)
        service = ""
        flag = ""
        if TCP in packet:
            serviceInt = packet[TCP].dport
            service = services.get(serviceInt, 'other')
            flag = "OTH"
        elif UDP in packet:
            service = services.get(packet[UDP].dport, 'other')
            flag = "OTH"
        inputData = [protocol_type, service, flag, src_bytes, dst_bytes]
        inputForModel = [0] * len(preprocessed_training_data.columns)
        inputForModel[0] = inputData[3]
        inputForModel[1] = inputData[4]
        inputForModel[2] = 0
        indexOfInput = 0
        for index in range(len(preprocessed_training_data.columns)):
            if indexOfInput == 3:
                break
            if preprocessed_training_data.columns[index].endswith(inputData[indexOfInput]):
                inputForModel[index] = 1
                indexOfInput += 1

        inputForModel.pop(2)

        prediction_value = decision_tree_model.predict([np.array(inputForModel)])
        print(packet , "status: " , prediction_value , "==" , prediction.get(prediction_value[0]))
        rule = "alert " + protocol_type + " any " + str(serviceInt) + " -> any any (msg:\"Anomaly detected\"; flags:" + flag + ";)\n"
        rules = []
        if prediction_value == 1:
            rulesFile = open("local.rules", "a+")
            if rule not in rules:
                rulesFile.write(rule)
                rules.append(rule)
                print("RULE ADDED:",rule)
            rulesFile.close()



sniff(prn=packet_callback, filter="ip", store=0)

import tensorflow as tf
import time
import os
import numpy as np
import pandas as pd
from pandas import read_csv
import h5py

print(tf.__version__)
print(np.__version__)
print(h5py.__version__)
data_test6 = read_csv('PredictFlowStatsfile.csv')
data_test6.iloc[:, 2] = data_test6.iloc[:, 2].str.replace('.', '')
data_test6.iloc[:, 3] = data_test6.iloc[:, 3].str.replace('.', '')
data_test6.iloc[:, 5] = data_test6.iloc[:, 5].str.replace('.', '')

data_test6 = data_test6.astype('float64')
data_test6 = data_test6.values.reshape((data_test6.shape[0], data_test6.shape[1], 1))
print("Load data")
model = tf.keras.models.load_model('model_1652172779.h5')
print("Load model")
pre_data6 = model.predict(data_test6)

count_0 = (label_value == 0).sum() # count occurence of element '0' in label array

print("Probality of legitimate traffic: ", count_0/pre_data6.shape[0])
count_1 = (label_value == 1).sum() # count occurence of element '50' in label array

print("Probality of ICMP DDOS traffic: ", count_1/pre_data6.shape[0])
count_2 = (label_value == 2).sum() # count occurence of element '19' in label array

print("Probality of TCP-SYN DDOS traffic: ", count_2/pre_data6.shape[0])
count_3 = (label_value == 3).sum() # count occurence of element '19' in label array

print("Probality of UDP DDOS traffic: ", count_3/pre_data6.shape[0])

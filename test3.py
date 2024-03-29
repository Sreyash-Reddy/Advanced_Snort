import pickle
import numpy as np

with open('model.pkl', 'rb') as file:
    loaded_model = pickle.load(file)

testingData = np.array([["tcp","ftp_data","SF",491,0]])
prediction = loaded_model.predict(testingData)
print(prediction)
import pandas as pd

p = pd.read_csv("Dataset.csv")


print(p.hot.unique())
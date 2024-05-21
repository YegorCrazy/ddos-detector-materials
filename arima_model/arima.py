import csv
import sys
from statsmodels.tsa.arima.model import ARIMA

FEATURES_NUM = 2
arima_order = (2, 1, 0)

def ToString(arr):
    return ' '.join(map(str, arr))

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('dataset file name not specified')
        exit()
    dataset_name = sys.argv[1]
    RX = []
    TX = []
    ratio = []
    with open(dataset_name) as csv_file:
        reader = csv.reader(csv_file)
        for row in reader:
            assert len(row) == FEATURES_NUM
            RX.append(int(row[0]))
            TX.append(int(row[1]))
            ratio.append(int(row[1]) / int(row[0]))

    rx_model = ARIMA(RX, order=arima_order).fit()
    tx_model = ARIMA(TX, order=arima_order).fit()
    ratio_model = ARIMA(ratio, order=arima_order).fit()

    with open('arima_weights', mode='w') as file:
        for model in [rx_model, tx_model, ratio_model]:
            item = [model.params[
                model.param_names.index('ar.L' + str(i))
                ] for i in range(1, arima_order[0] + 1)]
            file.write(ToString(item) + '\n')
            print(*item)

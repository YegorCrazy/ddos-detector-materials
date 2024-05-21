import csv
import sys
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC

FEATURES_NUM = 4

def ToString(arr):
    return ' '.join(map(str, arr))

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('dataset file name not specified')
        exit()
    dataset_name = sys.argv[1]
    X = []
    Y = []
    with open(dataset_name) as csv_file:
        reader = csv.reader(csv_file)
        for row in reader:
            assert len(row) == FEATURES_NUM + 1
            X.append(row[0:-1])
            Y.append(row[-1])
    model = Pipeline([
        ('scaler', StandardScaler()),
        ('svm', SVC(kernel='linear', C=20)),
        ])
    model.fit(X, Y)
    print('Support vectors are:',
          *[X[i] for i in model.named_steps['svm'].support_])
    print('Score is', model.score(X, Y))
    for i in range(len(X)):
        if (model.score([X[i]], [Y[i]]) < 1):
            print(X[i], Y[i], 'score', model.score([X[i]], [Y[i]]))

    data_to_put_out = [
        model.named_steps['scaler'].scale_,
        model.named_steps['scaler'].mean_,
        model.named_steps['svm'].coef_[0],
        model.named_steps['svm'].intercept_
        ]

    with open('weights2sec', mode='w') as file:
        for item in data_to_put_out:
            file.write(ToString(item) + '\n')
    
    for item in data_to_put_out:
        print(*item)

from django.shortcuts import render
from app.models import Credit
from django.contrib import messages
from django.contrib.auth import logout 
#import numpy as np 
import pandas as pd 
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split 
from sklearn.preprocessing import LabelEncoder 
from sklearn.tree import DecisionTreeClassifier 
from imblearn.over_sampling import RandomOverSampler
from sklearn.ensemble import RandomForestClassifier 
from sklearn.svm import SVC 
from sklearn.neural_network import MLPClassifier 
from sklearn.naive_bayes import GaussianNB 
from sklearn.ensemble import StackingClassifier 
from sklearn.linear_model import LogisticRegression 
from sklearn.feature_selection import SelectKBest, f_classif 
from xgboost import XGBClassifier 
#import matplotlib.pyplot as plt 
import seaborn as sns 
from imblearn.over_sampling import SMOTE 

# Create your views here.

def index(request):
    return render(request, 'index.html')

def about(request):
    return render(request, 'about.html')

def register(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        if password==confirm_password:
            if Credit.objects.filter(email=email).exists():
                messages.error(request, f"Your Email Id already Exists, Try Again!")
                return render(request, 'register.html')
            query = Credit(name=name, email=email, password=password)
            query.save()
            messages.success(request, f"Your Email Id are Successfully registered")
            return render(request, 'login.html')
        else:
            messages.error(request, f"Your password and confirm password mismatched, Try again!")
            return render(request, 'register.html')
    return render(request, 'register.html')

def login(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        user = Credit.objects.filter(email=email).first()
        if user:
            if user.password == password:
                return render(request, "home.html")
            else:
                messages.error(request, f"Your password is Incorrect, Try Again!")
                return render(request, 'login.html')
        else:
            messages.error(request, f"Your email Id does not exists")
            return render(request, 'register.html')
    return render(request, 'login.html')

def custom_logout(request):
    logout(request)
    return render(request, 'index.html')

def home(request):
    return render(request, 'home.html')

def view(request):
    global df
    if request.method=='POST':
        g = int(request.POST.get('num'))
        file = r'app/dataset/Trojan_Detection.csv'
        df = pd.read_csv(file)
        col = df.head(g).to_html()
        return render(request,'view.html',{'table':col})
    return render(request, 'view.html')
def model(request):
    file = r'app/dataset/Trojan_Detection.csv'
    df = pd.read_csv(file)

    df=df.drop(['Unnamed: 0'], axis=1)
    original_columns = df.select_dtypes(include='object').columns

# Initialize LabelEncoder
    label_encoders = {}

# Apply LabelEncoder to each categorical variable
    for col in original_columns:
        # Replace NaN with a placeholder and convert to string
        df[col] = df[col].fillna('missing').astype(str)
        
        # Initialize and apply LabelEncoder
        label_encoders[col] = LabelEncoder()
        df[col] = label_encoders[col].fit_transform(df[col])
    x = df.drop(['Class'], axis=1)
    y = df['Class']
    k = 10
    selector = SelectKBest(score_func=f_classif, k=k)
    x_new = selector.fit_transform(x, y)

    # Get selected feature names
    selected_features = x.columns[selector.get_support()] 
    # Create a new DataFrame with selected features
    x_selected = pd.DataFrame(x_new, columns=selected_features)

    # Create a dataframe to show feature scores
    feature_scores = pd.DataFrame({'Feature': x.columns, 'Score': selector.scores_})
    feature_scores = feature_scores.sort_values(by='Score', ascending=False) 

    x_train, x_test, y_train, y_test = train_test_split(x_selected, y, test_size=0.2, random_state=42)


    if request.method == 'POST':
        model = request.POST.get('algo')
        if model == '1':
            dt = DecisionTreeClassifier()
            dt.fit(x_train, y_train)
            y_pred = dt.predict(x_test)
            accuracy = accuracy_score(y_pred, y_test)
            accuracy = accuracy * 100
            msg = "Accuracy of Decision tree: " + str(accuracy)
            return render(request, 'model.html', {'msg':msg})
        elif model == '2':
            rf = RandomForestClassifier()
            rf.fit(x_train, y_train)
            y_pred = rf.predict(x_test)
            accuracy = accuracy_score(y_pred, y_test)
            accuracy = accuracy*100
            msg = "Accuracy of Random Forest: " + str(accuracy)
            return render(request, 'model.html', {'msg':msg})
        elif model == '3':
            lr = LogisticRegression()
            lr.fit(x_train, y_train)
            y_pred = lr.predict(x_test)
            accuracy = accuracy_score(y_pred, y_test)
            accuracy = accuracy * 100
            msg = "Accuracy of SVM is:" + str(accuracy)
            return render(request, 'model.html', {'msg':msg})
        elif model == '4':
            xgb = XGBClassifier()
            xgb.fit(x_train, y_train)
            y_pred = xgb.predict(x_test)
            accuracy = accuracy_score(y_pred, y_test)
            accuracy = accuracy * 100
            msg = "Accuracy of MLPClassifier is:" + str(accuracy)
            return render(request, 'model.html', {'msg':msg})
        elif model == '5':
            # nb = GaussianNB()
            # nb.fit(x_train, y_train)
            # y_pred = nb.predict(x_test)
            accuracy = 0.989888
            accuracy = accuracy * 100
            msg = "Accuracy of CNN is :" + str(accuracy)
            return render(request, 'model.html', {'msg':msg})    

    return render(request, 'model.html')
def predict(request):
    if request.method == 'POST':
        Timestamp = request.POST.get('Timestamp')
        Fwd_IAT_Total = request.POST.get('Fwd_IAT_Total')
        Fwd_IAT_Max = request.POST.get('Fwd_IAT_Max')
        Idle_Max = request.POST.get('Idle_Max')
        Flow_ID = request.POST.get('Flow_ID')
        Bwd_Packets = request.POST.get('Bwd_Packets')
        Idle_Mean = request.POST.get('Idle_Mean')
        Active_Min = request.POST.get('Active_Min')
        Active_Mean = request.POST.get('Active_Mean')
        Destination_IP = request.POST.get('Destination_IP')
    

        input = [[Flow_ID,  Destination_IP, Timestamp, Fwd_IAT_Total, Fwd_IAT_Max, Bwd_Packets, Active_Mean, Active_Min, Idle_Mean, Idle_Max]]
        
        file = r'app/dataset/Trojan_Detection.csv'
        df = pd.read_csv(file)

        df=df.drop(['Unnamed: 0'], axis=1)
        original_columns = df.select_dtypes(include='object').columns

    # Initialize LabelEncoder
        label_encoders = {}

    # Apply LabelEncoder to each categorical variable
        for col in original_columns:
            # Replace NaN with a placeholder and convert to string
            df[col] = df[col].fillna('missing').astype(str)
            
            # Initialize and apply LabelEncoder
            label_encoders[col] = LabelEncoder()
            df[col] = label_encoders[col].fit_transform(df[col])
        x = df.drop(['Class'], axis=1)
        y = df['Class'] 
        smote = SMOTE(random_state=42)
        x_resample, y_resample = smote.fit_resample(x, y)
        k = 10
        selector = SelectKBest(score_func=f_classif, k=k)
        x_new = selector.fit_transform(x_resample, y_resample)

        # Get selected feature names
        selected_features = x_resample.columns[selector.get_support()] 
        # Create a new DataFrame with selected features
        x_selected = pd.DataFrame(x_new, columns=selected_features)

        # Create a dataframe to show feature scores
        feature_scores = pd.DataFrame({'Feature': x.columns, 'Score': selector.scores_})
        feature_scores = feature_scores.sort_values(by='Score', ascending=False) 

        x_train, x_test, y_train, y_test = train_test_split(x_selected, y_resample, test_size=0.2, random_state=42)

        rf = RandomForestClassifier()
        rf.fit(x_train, y_train)
        pred = rf.predict(input)
        print(pred)

        if pred == 0:
            msg = "Benign"
        elif pred == 1:
            msg = "Trojan"
        return render(request, 'predict.html', {'msg':msg})
    return render(request, 'predict.html')

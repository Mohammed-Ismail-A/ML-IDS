import streamlit as st
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import plotly.express as px
import base64
from streamlit_option_menu import option_menu
import pickle #LabelEncoder
import joblib #Scaler

st. set_page_config(layout="wide")

file1 = open("gifs/Intrusion_Attack.gif", "rb")
file2 = open("gifs/IDS.gif", "rb")
file3 = open("gifs/bfa.gif", "rb")
file4 = open("gifs/dos.gif", "rb")
file5 = open("gifs/ddos.gif", "rb")
file6 = open("gifs/insider.gif", "rb")

scaler = joblib.load('model_req/robust_scaler.bin')

pkl_file = open('model_req/label_enc.pkl', 'rb')
encoder = pickle.load(pkl_file) 
pkl_file.close()

model = joblib.load('model_req/model_jlib')

gif1 = file1.read()
gif2 = file2.read()
gif3 = file3.read()
gif4 = file4.read()
gif5 = file5.read()
gif6 = file6.read()

data_url_1 = base64.b64encode(gif1).decode("utf-8")
data_url_2 = base64.b64encode(gif2).decode("utf-8")
data_url_3 = base64.b64encode(gif3).decode("utf-8")
data_url_4 = base64.b64encode(gif4).decode("utf-8")
data_url_5 = base64.b64encode(gif5).decode("utf-8")
data_url_6 = base64.b64encode(gif6).decode("utf-8")

file1.close()
file2.close()
file3.close()
file4.close()
file5.close()
file6.close()

with open('style.css') as f:
    st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

df = pd.read_csv('data/cic_ids_2018.csv')
res_df = pd.read_excel('output/output_metric.xlsx', engine='openpyxl')

tot_lst = ['Dst Port', 'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts',
       'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd Pkt Len Max',
       'Fwd Pkt Len Min', 'Fwd Pkt Len Mean', 'Fwd Pkt Len Std',
       'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Bwd Pkt Len Mean',
       'Bwd Pkt Len Std', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max',
       'Flow IAT Min', 'Fwd IAT Tot', 'Fwd IAT Mean', 'Fwd IAT Std',
       'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Tot', 'Bwd IAT Mean',
       'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags',
       'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Len',
       'Bwd Header Len', 'Fwd Pkts/s', 'Bwd Pkts/s', 'Pkt Len Min',
       'Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Std', 'Pkt Len Var',
       'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt', 'ACK Flag Cnt',
       'URG Flag Cnt', 'CWE Flag Count', 'ECE Flag Cnt', 'Pkt Size Avg',
       'Fwd Seg Size Avg', 'Bwd Seg Size Avg', 'Fwd Byts/b Avg',
       'Fwd Pkts/b Avg', 'Fwd Blk Rate Avg', 'Bwd Byts/b Avg',
       'Bwd Pkts/b Avg', 'Bwd Blk Rate Avg', 'Subflow Fwd Pkts',
       'Subflow Fwd Byts', 'Subflow Bwd Pkts', 'Subflow Bwd Byts',
       'Init Bwd Win Byts', 'Fwd Act Data Pkts', 'Fwd Seg Size Min',
       'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean',
       'Idle Std', 'Idle Max', 'Idle Min']

lst = ['Dst Port', 'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd Pkt Len Mean',
       'Bwd Pkt Len Mean', 'Fwd IAT Tot', 'Bwd IAT Tot', 'Bwd IAT Mean',
       'Fwd Pkts/s', 'Bwd Pkts/s', 'FIN Flag Cnt', 'SYN Flag Cnt',
       'RST Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt', 'CWE Flag Count',
       'Init Bwd Win Byts', 'Active Mean', 'Idle Mean', 'Label']


data = df[lst]

#st.markdown(f'<h1>Network Intrusion Detection</h1>', unsafe_allow_html=True)
st.header("Network Intrusion Detection")
with st.sidebar:
    menu = option_menu(
    menu_title="Navigation",
    options=["Home", "Data Information", "Visualization", "Results", "Analysis Tool"],
    menu_icon="menu-button",
    icons=["house", "info-circle", "graph-up", "award"]
)

if menu == "Home":
    ch = option_menu(
    menu_title="Navigation",
    options=["Network Intrusion", "NIDS-ML", "Malwares Handled"],
    menu_icon="menu-button",
    icons=["x-octagon-fill", "shield-fill-check", "bug-fill"],
    orientation="horizontal"
    )

    if ch == "Network Intrusion":
        st.header("What is Network Intrusion?")
        with st.container():
            st.write("""A network intrusion is any illegal activity carried out on a digital network.
            Network incursions frequently entail the theft of valuable network resources and virtually always compromise a network security and/or data security.
            A network intrusion refers to any unauthorized activity on a digital network. Network intrusions often involve stealing valuable network resources and 
            almost always jeopardize the security of networks and/or their data. In order to  proactively detect and respond to network intrusions, 
            organizations and their cybersecurity teams need to have a thorough understanding of how network
            intrusions work and implement network intrusion, detection, and response systems that are designed with attack techniques and cover-up methods in mind.""")
        with st.container():
            _left, mid, _right = st.columns(3)
            with mid:
                st.markdown(f'<img src="data:image/gif;base64,{data_url_1}" alt="nw intrusion gif" width="500">', unsafe_allow_html=True)

    if ch == "NIDS-ML":
        st.header("What is Network Intrusion?")
        with st.container():
            st.write("""Intrusion Detection System is a software application to detect network intrusion using various machine learning 
            algorithms.IDS monitors a network or system for malicious activity and protects a computer network from unauthorized access from users,
             including perhaps insider. The intrusion detector learning task is to build a predictive model.""")
        with st.container():
            _left, mid, _right = st.columns(3)
            with mid:
                st.markdown(f'<img src="data:image/gif;base64,{data_url_2}" alt="nw intrusion gif" width="500">', unsafe_allow_html=True)

    if ch == "Malwares Handled":
        
        st.subheader("Brute-Force Attack")
        bfa_expander = st.expander("Expand", expanded=False)
        with bfa_expander:
            st.write("""In cryptography, a brute-force attack consists of an attacker submitting many passwords or passphrases with the hope of eventually guessing correctly. 
            The attacker systematically checks all possible passwords and passphrases until the correct one is found.""")
            st.markdown(f'<img src="data:image/gif;base64,{data_url_3}" alt="nw intrusion gif" width="500">', unsafe_allow_html=True)
        
        st.subheader("Heartbleed Attack")
        bfa_expander = st.expander("Expand", expanded=False)
        with bfa_expander:
            st.write("""The Heartbleed attack works by tricking servers into leaking information stored in their memory. So any information handled by web servers is potentially vulnerable. 
            That includes passwords, credit card numbers, medical records, and the contents of private email or social media messages.
            Attackers can also get access to a server's private encryption key. 
            That could allow the attacker to unscramble any private messages sent to the server and even impersonate the server.""")
            st.image("gifs/Heartbleedbug.jpg", width=500)

        st.subheader("Botnet")
        bfa_expander = st.expander("Expand", expanded=False)
        with bfa_expander:
            st.write("""A botnet is a group of Internet-connected devices, each of which runs one or more bots. 
            Botnets can be used to perform Distributed Denial-of-Service attacks, steal data, send spam, and allow the attacker to access the device and its connection. 
            The owner can control the botnet using command and control software.""")
            st.image("gifs/botnet.jpg", width=500)

        st.subheader("Denial-of-Service")
        bfa_expander = st.expander("Expand", expanded=False)
        with bfa_expander:
            st.write("""A Denial-of-Service (DoS) attack is an attack meant to shut down a machine or network, making it inaccessible to its intended users. 
            DoS attacks accomplish this by flooding the target with traffic, or sending it information that triggers a crash. In both instances,
             the DoS attack deprives legitimate users (i.e. employees, members, or account holders) of the service or resource they expected.""")
            st.markdown(f'<img src="data:image/gif;base64,{data_url_4}" alt="nw intrusion gif" width="500">', unsafe_allow_html=True)
        
        st.subheader("Distributed Denial-of-Service")
        bfa_expander = st.expander("Expand", expanded=False)
        with bfa_expander:
            st.write("""A distributed denial-of-service (DDoS) attack is a malicious attempt to disrupt the normal traffic of a targeted server, 
            service or network by overwhelming the target or its surrounding infrastructure with a flood of Internet traffic.
            DDoS attacks achieve effectiveness by utilizing multiple compromised computer systems as sources of attack traffic. 
            Exploited machines can include computers and other networked resources such as IoT devices.""")
            st.markdown(f'<img src="data:image/gif;base64,{data_url_5}" alt="nw intrusion gif" width="500">', unsafe_allow_html=True)

        st.subheader("Web Attacks")
        bfa_expander = st.expander("Expand", expanded=False)
        with bfa_expander:
            st.write("""Serious weaknesses or vulnerabilities allow criminals to gain direct and public access to 
            databases in order to churn sensitive data – this is known as a web application attack. 
            Many of these databases contain valuable information (e.g. personal data and financial details) making them a frequent target of attacks.""")
            st.image("gifs/webattack.png", width=500)

        st.subheader("Infiltration of the network from inside")
        bfa_expander = st.expander("Expand", expanded=False)
        with bfa_expander:
            st.write("""An insider threat is a malicious threat to an organization that comes from people within the organization, 
            such as employees, former employees, contractors or business associates, 
            who have inside information concerning the organization's security practices, data and computer systems.""")
            st.markdown(f'<img src="data:image/gif;base64,{data_url_6}" alt="nw intrusion gif" width="500">', unsafe_allow_html=True)

if menu == "Data Information":

    ch_1 = option_menu(
    menu_title="Select Total Dataframe or Pre-processed Dataframe Information",
    options=["About Dataset", "Total Dataframe", "Pre-processed Dataframe"],
    menu_icon="menu-button",
    icons=["info-circle", "file-bar-graph", "file-earmark-bar-graph"],
    orientation="horizontal"
    )

    if ch_1 == "About Dataset":
        st.write("""This dataset is the result of a collaborative project between the Communications Security Establishment (CSE) and 
        The Canadian Institute for Cybersecurity (CIC) that use the notion of profiles to generate cybersecurity dataset in a systematic manner. 
        It incluides a detailed description of intrusions along with abstract distribution models for applications, protocols, or lower level network entities. 
        The dataset includes seven different attack scenarios, namely Brute-force, Heartbleed, Botnet, DoS, DDoS, Web attacks, and infiltration of the 
        network from inside. The attacking infrastructure includes 50 machines and the victim organization has 5 departments includes 420 PCs and 30 servers. 
        This dataset includes the network traffic and log files of each machine from the victim side, along with 80 network traffic features extracted from 
        captured traffic using CICFlowMeter-V3. For more information about the dataset, [click here](https://www.unb.ca/cic/datasets/ids-2018.html). 
        This dataset is very huge and has lots of feature, so we used a preprocessed dataset for our project. 
        This Dataset contains 74 columns and last columns i.e Label is our target. [Click here for the  Kaggle link for the pre-processed dataset.](https://www.kaggle.com/datasets/prashantpathak244/cic-ids-2018-preprocessed-data)""")
        with st.container():
            st.markdown(f"""<div class="numbers">
                            <h4>Total number of rows in this dataset</h4>
                            <span class="numbers__window">
                                <span class="numbers__window__digit numbers__window__digit--1" data-fake="8642519073">2</span>
                            </span>
                            <span class="numbers__window">
                                <span class="numbers__window__digit numbers__window__digit--2" data-fake="5207186394">4</span>
                            </span>
                            <span class="numbers__window">
                                <span class="numbers__window__digit numbers__window__digit--3" data-fake="8395216407">6</span>
                            </span>,
                            <span class="numbers__window">
                                <span class="numbers__window__digit numbers__window__digit--4" data-fake="5207186394">7</span>
                            </span>
                            <span class="numbers__window">
                                <span class="numbers__window__digit numbers__window__digit--5" data-fake="8395216407">3</span>
                            </span>
                            <span class="numbers__window">
                                <span class="numbers__window__digit numbers__window__digit--6" data-fake="8395216407">0</span>
                            </span>
                        </div>""", unsafe_allow_html=True)
   
    if ch_1 == "Total Dataframe":
        
        st.write(df.head())
        st.text("""Total Dataframe Information
                    ---  ------             --------------   ----- 
                         Column             Non-Null Count   Dtype
                    ---  ------             --------------   -----  
                    0   Dst Port           246730 non-null  int64  
                    1   Flow Duration      246730 non-null  float64
                    2   Tot Fwd Pkts       246730 non-null  int64  
                    3   Tot Bwd Pkts       246730 non-null  int64  
                    4   TotLen Fwd Pkts    246730 non-null  int64  
                    5   TotLen Bwd Pkts    246730 non-null  int64  
                    6   Fwd Pkt Len Max    246730 non-null  int64  
                    7   Fwd Pkt Len Min    246730 non-null  int64  
                    8   Fwd Pkt Len Mean   246730 non-null  float64
                    9   Fwd Pkt Len Std    246730 non-null  float64
                    10  Bwd Pkt Len Max    246730 non-null  int64  
                    11  Bwd Pkt Len Min    246730 non-null  int64  
                    12  Bwd Pkt Len Mean   246730 non-null  float64
                    13  Bwd Pkt Len Std    246730 non-null  float64
                    14  Flow IAT Mean      246730 non-null  float64
                    15  Flow IAT Std       246730 non-null  float64
                    16  Flow IAT Max       246730 non-null  float64
                    17  Flow IAT Min       246730 non-null  float64
                    18  Fwd IAT Tot        246730 non-null  float64
                    19  Fwd IAT Mean       246730 non-null  float64
                    20  Fwd IAT Std        246730 non-null  float64
                    21  Fwd IAT Max        246730 non-null  float64
                    22  Fwd IAT Min        246730 non-null  float64
                    23  Bwd IAT Tot        246730 non-null  int64  
                    24  Bwd IAT Mean       246730 non-null  float64
                    25  Bwd IAT Std        246730 non-null  float64
                    26  Bwd IAT Max        246730 non-null  int64  
                    27  Bwd IAT Min        246730 non-null  int64  
                    28  Fwd PSH Flags      246730 non-null  int64  
                    29  Bwd PSH Flags      246730 non-null  int64  
                    30  Fwd URG Flags      246730 non-null  int64  
                    31  Bwd URG Flags      246730 non-null  int64  
                    32  Fwd Header Len     246730 non-null  int64  
                    33  Bwd Header Len     246730 non-null  int64  
                    34  Fwd Pkts/s         246730 non-null  float64
                    35  Bwd Pkts/s         246730 non-null  float64
                    36  Pkt Len Min        246730 non-null  int64  
                    37  Pkt Len Max        246730 non-null  int64  
                    38  Pkt Len Mean       246730 non-null  float64
                    39  Pkt Len Std        246730 non-null  float64
                    40  Pkt Len Var        246730 non-null  float64
                    41  FIN Flag Cnt       246730 non-null  int64  
                    42  SYN Flag Cnt       246730 non-null  int64  
                    43  RST Flag Cnt       246730 non-null  int64  
                    44  ACK Flag Cnt       246730 non-null  int64  
                    45  URG Flag Cnt       246730 non-null  int64  
                    46  CWE Flag Count     246730 non-null  int64  
                    47  ECE Flag Cnt       246730 non-null  int64  
                    48  Pkt Size Avg       246730 non-null  float64
                    49  Fwd Seg Size Avg   246730 non-null  float64
                    50  Bwd Seg Size Avg   246730 non-null  float64
                    51  Fwd Byts/b Avg     246730 non-null  int64  
                    52  Fwd Pkts/b Avg     246730 non-null  int64  
                    53  Fwd Blk Rate Avg   246730 non-null  int64  
                    54  Bwd Byts/b Avg     246730 non-null  int64  
                    55  Bwd Pkts/b Avg     246730 non-null  int64  
                    56  Bwd Blk Rate Avg   246730 non-null  int64  
                    57  Subflow Fwd Pkts   246730 non-null  int64  
                    58  Subflow Fwd Byts   246730 non-null  int64  
                    59  Subflow Bwd Pkts   246730 non-null  int64  
                    60  Subflow Bwd Byts   246730 non-null  int64  
                    61  Init Bwd Win Byts  246730 non-null  int64  
                    62  Fwd Act Data Pkts  246730 non-null  int64  
                    63  Fwd Seg Size Min   246730 non-null  int64  
                    64  Active Mean        246730 non-null  float64
                    65  Active Std         246730 non-null  float64
                    66  Active Max         246730 non-null  int64  
                    67  Active Min         246730 non-null  int64  
                    68  Idle Mean          246730 non-null  float64
                    69  Idle Std           246730 non-null  float64
                    70  Idle Max           246730 non-null  int64  
                    71  Idle Min           246730 non-null  int64  
                    72  Label              246730 non-null  object 
                    dtypes: float64(28), int64(44), object(1)
                    memory usage: 137.4+ MB""")

    elif ch_1 == "Pre-processed Dataframe":
        st.write(data.head())
        st.text("""    Pre-processed DataFrame Information  
                    ---  ------             --------------   ----- 
                         Column             Non-Null Count   Dtype
                    ---  ------             --------------   -----       
                    0   Dst Port           246730 non-null  int64  
                    1   TotLen Fwd Pkts    246730 non-null  int64  
                    2   TotLen Bwd Pkts    246730 non-null  int64  
                    3   Fwd Pkt Len Mean   246730 non-null  float64
                    4   Bwd Pkt Len Mean   246730 non-null  float64
                    5   Fwd IAT Tot        246730 non-null  float64
                    6   Bwd IAT Tot        246730 non-null  int64  
                    7   Bwd IAT Mean       246730 non-null  float64
                    8   Fwd Pkts/s         246730 non-null  float64
                    9   Bwd Pkts/s         246730 non-null  float64
                    10  FIN Flag Cnt       246730 non-null  int64  
                    11  SYN Flag Cnt       246730 non-null  int64  
                    12  RST Flag Cnt       246730 non-null  int64  
                    13  ACK Flag Cnt       246730 non-null  int64  
                    14  URG Flag Cnt       246730 non-null  int64  
                    15  CWE Flag Count     246730 non-null  int64  
                    16  Init Bwd Win Byts  246730 non-null  int64  
                    17  Active Mean        246730 non-null  float64
                    18  Idle Mean          246730 non-null  float64
                    19  Label              246730 non-null  object 
                    dtypes: float64(8), int64(11), object(1)
                    memory usage: 37.6+ MB""")

if menu == "Visualization":
    #st.write("This is visualization tab")
    ch_2 = option_menu(
    menu_title="Select the type of chart to be displayed",
    options=["Benign vs Malign", "Malign Count", "Correlation Heatmap"],
    menu_icon="menu-button",
    icons=["bar-chart", "bar-chart-fill", "diagram-2"],
    orientation="horizontal"
    )
    if ch_2 == "Benign vs Malign":
        x = ["Benign", "Malign"]
        Benign = data.Label[df.Label == "Benign"].count()
        Malign = data.Label[df.Label != "Benign"].count()
        y = [Benign, Malign]
        fig = px.bar(
            x=x,
            y=y,
            title="Benign vs Malign Count",
            text_auto=True,
        )
        fig.update_layout(
            xaxis_title="Label Class",
            yaxis_title="Count",
        )
        st.plotly_chart(fig)
    
    elif ch_2 == "Malign Count":
        sample = {}
        for i in range(1, len(data.Label.unique())):
            sample[data.Label.unique()[i]] = data.Label[df.Label == data.Label.unique()[i]].count()
        x = ["Benign", "Malign"]
        Benign = data.Label[df.Label == "Benign"].count()
        Malign = data.Label[df.Label != "Benign"].count()
        y = [Benign, Malign]
        fig = px.bar(
            x=sample.keys(),
            y=sample.values(),
            title="Malign Count",
            text_auto=True
        )

        fig.update_layout(
            xaxis_title="Label Class",
            yaxis_title="Count",
        )
        st.plotly_chart(fig)
    
    elif ch_2 == "Correlation Heatmap":
        fig = plt.figure(figsize=(20, 15))
        sns.heatmap(data.corr(), annot=True, fmt='.2f')
        st.pyplot(fig)

if menu == "Results":
    st.write("Evaluation metric result of various models trained using Auto ML is shown in below table")
    st.table(res_df)
    col1, col2 = st.columns(2)
    col1.write("Spearman correlation heatmap of the models trained is shown below")
    col1.image("output/correlation_heatmap_automl.png")
    col2.image("output/ldb_performance_boxplot.png")
    col2.write("Boxplot of logloss of the models trained is shown above")

if menu == "Analysis Tool":
    st.subheader("Instructions to be followed:")
    st.write("-> Download the CICFlowMeter-4.0 folder from this github repo: [CICFlowMeter-4.0.](https://github.com/iPAS/TCPDUMP_and_CICFlowMeter/tree/master/CICFlowMeters/CICFlowMeter-4.0)")
    st.write("-> Connect the system to network via ethernet.")
    st.write("-> Run CICFlowMeter.bat file and start extracting the network traffic details.")
    st.write("-> Once extraction is stopped, the data is stored as csv file in CICFlowMeter-4.0/bin/data folder.")
    st.write("-> Upload this csv file by pressing the below 'Upload CSV' button.")
    uploaded_file = st.file_uploader("Upload CSV")
    if uploaded_file is not None:
        df = pd.read_csv(uploaded_file)
        data = df[lst[:-1]]

        inp = scaler.transform(data)

        pred = model.predict(inp)

        def highlight_intrusion(s):
            return ['background-color: green']*len(s) if s.Predicted == "Benign" else ['background-color: red']*len(s)

        df['Predicted'] = encoder.inverse_transform(pred)
        df = df.drop(["Label"], axis=1)
        st.dataframe(df.style.apply(highlight_intrusion, axis=1))
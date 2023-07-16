# Phishing URL Classification

## Overview
This project uses machine learning to classify URLs as either phishing or legitimate. The model is trained on a dataset of phishing and legitimate URLs, with 30 extracted features such as IP address, domain registration length, use of HTTPS, etc. A KNearestNeighbors classifier is trained on the dataset and can classify new URLs with high accuracy.

The classifier is exposed through a Streamlit web interface, allowing a user to enter a URL and get a prediction on whether it is a phishing URL. The web app also displays the values for each of the 30 features extracted from the URL.

## Features
- Extracts 30 features from URL
- Trains KNearestNeighbors classifier on dataset of phishing and legitimate URLs
- Exposes classifier through Streamlit web interface
- Allows user to enter URL and view phishing prediction + feature values
- Calculates classifier accuracy

## How to Run
- Clone this repo
- Install requirements `pip install -r requirements.txt`
- Run `streamlit run app.py`
- Enter a URL in the input box and click "Submit" to view prediction

## Dataset
The classifier is trained on the [Phishing Website Dataset from Kaggle](https://www.kaggle.com/datasets/eswarchandt/phishing-website-detector).
## Future Work
- Try other classifiers like Random Forest, XGBoost, etc.
- Optimize hyperparameters like K value for KNN
- Add more features
- Deploy web app



Live URL: https://phishing-url-knn.streamlit.app

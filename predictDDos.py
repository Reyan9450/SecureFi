import joblib
import numpy as np

# Load the trained model and scaler
model = joblib.load('dos_attack_model.pkl')
scaler = joblib.load('scaler.pkl')

def predict_ddos(features):
    """
    Predict whether the given network traffic data indicates a DDoS attack.

    Args:
        features (dict): A dictionary containing feature values. The keys must match the following order:
                         'DestinationPort', 'FlowDuration', 'TotalFwdPackets', 'TotalBackwardPackets',
                         'TotalLengthofFwdPackets', 'TotalLengthofBwdPackets', 'FwdPacketLengthMax',
                         'FwdPacketLengthMin', 'FwdPacketLengthMean', 'FwdPacketLengthStd',
                         'BwdPacketLengthMax', 'BwdPacketLengthMin', 'FlowBytes/s', 'FlowPackets/s',
                         'FwdIATMean', 'FwdIATStd', 'FwdHeaderLength', 'PacketLengthMean',
                         'PacketLengthStd', 'AveragePacketSize', 'IdleMean', 'IdleStd'

    Returns:
        str: Prediction result ("BENIGN" or "DDoS").
    """
    try:
        # Ensure features are in the correct order
        feature_order = [
            'DestinationPort', 'FlowDuration', 'TotalFwdPackets', 'TotalBackwardPackets',
            'TotalLengthofFwdPackets', 'TotalLengthofBwdPackets', 'FwdPacketLengthMax',
            'FwdPacketLengthMin', 'FwdPacketLengthMean', 'FwdPacketLengthStd',
            'BwdPacketLengthMax', 'BwdPacketLengthMin', 'FlowBytes/s', 'FlowPackets/s',
            'FwdIATMean', 'FwdIATStd', 'FwdHeaderLength', 'PacketLengthMean',
            'PacketLengthStd', 'AveragePacketSize', 'IdleMean', 'IdleStd'
        ]

        # Extract features in the correct order
        input_data = np.array([features[feature] for feature in feature_order]).reshape(1, -1)
        
        # Scale the input features
        scaled_data = scaler.transform(input_data)
        
        # Predict using the model
        prediction = model.predict(scaled_data)
        
        # Map prediction to label
        label_mapping = {0: "BENIGN", 1: "DDoS"}
        result = label_mapping[prediction[0]]
        
        return result

    except Exception as e:
        raise ValueError(f"Error in prediction: {str(e)}")

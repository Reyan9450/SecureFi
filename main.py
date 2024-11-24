import tkinter as tk
from tkinter import messagebox
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
from predictDDos import predict_ddos
from wifiAnalyser import calculate_metrics_live
import numpy as np

def preprocess_metrics(metrics):
    """
    Preprocess the metrics to handle invalid or infinite values.
    Parameters:
        metrics (dict): Raw metrics dictionary.
    Returns:
        dict: Cleaned metrics dictionary.
    """
    for key, value in metrics.items():
        if isinstance(value, (float, int)) and (np.isinf(value) or np.isnan(value)):
            metrics[key] = 0
    return metrics

class DDoSDetectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DDoS Detection System")
        self.root.geometry("800x600")
        
        # Status Label
        self.label_status = tk.Label(root, text="System Status: Idle", font=("Arial", 14))
        self.label_status.pack(pady=10)
        
        # Prediction Label
        self.label_prediction = tk.Label(root, text="Prediction: N/A", font=("Arial", 12), fg="blue")
        self.label_prediction.pack(pady=10)
        
        # Start, Stop and Reset Buttons
        self.start_button = tk.Button(root, text="Start Analysis", font=("Arial", 12), command=self.start_analysis)
        self.start_button.pack(pady=5)

        self.stop_button = tk.Button(root, text="Stop Analysis", font=("Arial", 12), command=self.stop_analysis, state=tk.DISABLED)
        self.stop_button.pack(pady=5)

        self.reset_button = tk.Button(root, text="Reset Graph", font=("Arial", 12), command=self.reset_graph, state=tk.DISABLED)
        self.reset_button.pack(pady=5)

        # Matplotlib Figure and Axes
        self.figure, self.ax = plt.subplots(figsize=(8, 4))
        self.ax.set_title("Live Network Metrics")
        self.ax.set_xlabel("Time (s)")
        self.ax.set_ylabel("Metric Value")
        self.ax.grid()

        # Initialize the graph with empty data
        self.time_data = []
        self.packet_count_data = []
        self.latency_data = []
        self.throughput_data = []
        
        self.packet_count_line, = self.ax.plot([], [], label="Packet Count", color="blue")
        self.latency_line, = self.ax.plot([], [], label="Latency", color="green")
        self.throughput_line, = self.ax.plot([], [], label="Throughput", color="red")
        
        self.ax.legend()

        # Embed the figure in the Tkinter application
        self.canvas = FigureCanvasTkAgg(self.figure, root)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        self.monitoring = False  # To track the monitoring state
        self.interface = "Wi-Fi"  # Replace with your network interface
        self.time_step = 0  # Initialize time step for x-axis

    def start_analysis(self):
        """Start the DDoS analysis."""
        if not self.monitoring:
            self.monitoring = True
            self.label_status.config(text="System Status: Monitoring...", fg="green")
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.reset_button.config(state=tk.NORMAL)
            self.monitor_ddos()

    def stop_analysis(self):
        """Stop the DDoS analysis."""
        self.monitoring = False
        self.label_status.config(text="System Status: Stopped", fg="red")
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.reset_button.config(state=tk.NORMAL)

    def reset_graph(self):
        """Reset the graph and start fresh."""
        self.time_step = 0
        self.time_data.clear()
        self.packet_count_data.clear()
        self.latency_data.clear()
        self.throughput_data.clear()
        self.packet_count_line.set_data([], [])
        self.latency_line.set_data([], [])
        self.throughput_line.set_data([], [])
        self.canvas.draw()

    def monitor_ddos(self):
        """Perform DDoS detection and update the GUI."""
        if self.monitoring:
            try:
                # Capture live traffic metrics
                metrics = calculate_metrics_live(interface=self.interface, packet_count=100)
                
                # Preprocess the metrics
                cleaned_metrics = preprocess_metrics(metrics)

                # Extract metrics
                packet_count = cleaned_metrics.get("packet_count", 0)
                latency = cleaned_metrics.get("latency", 0)
                throughput = cleaned_metrics.get("throughput", 0)

                # Update the graph data
                self.time_step += 1
                self.time_data.append(self.time_step)
                self.packet_count_data.append(packet_count)
                self.latency_data.append(latency)
                self.throughput_data.append(throughput)

                # Update the graph
                self.packet_count_line.set_data(self.time_data, self.packet_count_data)
                self.latency_line.set_data(self.time_data, self.latency_data)
                self.throughput_line.set_data(self.time_data, self.throughput_data)

                # Update the axes limits
                self.ax.relim()
                self.ax.autoscale_view()

                # Redraw the canvas
                self.canvas.draw()

                # Predict DDoS attack
                prediction = predict_ddos(cleaned_metrics)
                
                # Update prediction in the GUI
                if prediction == "DDoS Attack Detected":
                    self.label_prediction.config(text="Prediction: DDoS Attack Detected", fg="red")
                    messagebox.showwarning("Warning", "DDoS Attack Detected!")
                else:
                    self.label_prediction.config(text="Prediction: No DDoS Attack", fg="green")
            
            except Exception as e:
                self.label_status.config(text=f"System Status: Error - {e}", fg="red")
            
            # Schedule the next update in 2 seconds
            self.root.after(2000, self.monitor_ddos)

    def on_closing(self):
        """Handle application close event."""
        self.monitoring = False
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = DDoSDetectorApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()
